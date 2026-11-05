import { GatewaySessionError } from './errors.js';

export const HEARTBEAT_INTERVAL_MS = 60_000;
export const SESSION_IDLE_MS = 180_000;
type Control = 'heartbeat' | 'session_close';

/** In-memory ownership only. Heartbeats never renew account authority or keys. */
export class SessionLifecycle {
  private operations = 0;
  private holds = 0;
  private closing = false;
  private closed = false;
  private failed = false;
  private lastActivity = Date.now();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private completion: Promise<void> | undefined;
  private finish: (() => void) | undefined;
  private reject: ((error: unknown) => void) | undefined;

  constructor(private readonly supported: boolean, private readonly valid: () => boolean,
    private readonly request: (op: Control) => Promise<unknown>) {}

  private idleValid(): boolean { return !this.supported || this.operations > 0 || Date.now() < this.lastActivity + SESSION_IDLE_MS; }
  get available(): boolean { return !this.closing && !this.closed && !this.failed && this.valid() && this.idleValid(); }
  acknowledge(startedAt: number): void { this.lastActivity = Math.max(this.lastActivity, startedAt); }

  start(): void { if (this.supported && this.available && this.timer === undefined) this.schedule(0); }

  private schedule(delay: number): void {
    this.timer = setTimeout(() => { this.timer = undefined; void this.beat(); }, delay);
    (this.timer as unknown as { unref?: () => void }).unref?.();
  }

  private async beat(): Promise<void> {
    if (this.closed || this.failed || !this.valid() || (this.closing && !this.holds)) return;
    if (!this.idleValid()) { this.failed = true; return; }
    let leave: (() => void) | undefined;
    const started = Date.now();
    try {
      leave = this.enter();
      const result = await this.request('heartbeat') as { alive?: boolean };
      if (result?.alive !== true) throw new GatewaySessionError('session_rejected');
      this.acknowledge(started);
    } catch (error) {
      // Transient network failures do not tear down an authenticated reply.
      // An authenticated session rejection makes the next acquisition reconnect.
      if (error instanceof GatewaySessionError) this.failed = true;
    } finally {
      leave?.();
      if (!this.closed && !this.failed && this.valid()) this.schedule(HEARTBEAT_INTERVAL_MS);
    }
  }

  enter(): () => void {
    if (this.closed || this.failed || !this.valid() || !this.idleValid()) throw new GatewaySessionError('session_expired');
    if (this.closing && !this.holds) throw new GatewaySessionError('session_closed');
    this.operations++;
    let released = false;
    return () => { if (!released) { released = true; this.operations--; this.drain(); } };
  }

  /** Hold the original session across uploads, inference and tool rounds. */
  retain(): () => void {
    // A retained reply may start its next upload after replacement was requested.
    // New acquisitions use available; only the existing owner keeps this client.
    const continuation = this.closing && !this.closed && !this.failed && this.valid() && this.idleValid() && this.holds > 0;
    if (!this.available && !continuation) throw new GatewaySessionError('session_closed');
    this.holds++;
    let released = false;
    return () => { if (!released) { released = true; this.holds--; this.drain(); } };
  }

  close(): Promise<void> {
    if (!this.completion) {
      this.completion = new Promise((resolve, reject) => { this.finish = resolve; this.reject = reject; });
      this.closing = true;
      this.drain();
    }
    return this.completion;
  }

  private drain(): void {
    if (!this.closing || this.closed || this.operations || this.holds) return;
    this.closed = true;
    if (this.timer !== undefined) { clearTimeout(this.timer); this.timer = undefined; }
    if (!this.supported || !this.valid() || this.failed) { this.finish?.(); return; }
    void this.request('session_close').then(result => {
      if ((result as { closed?: boolean })?.closed !== true) throw new GatewaySessionError('session_rejected');
      this.finish?.();
    }).catch(error => this.reject?.(error));
  }
}
