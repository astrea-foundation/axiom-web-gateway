let worker: Worker | undefined;
let serial = 0;
const pending = new Map<number, { resolve(value: string): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }>();
/** Verify off the UI thread. Node tests use the identical packaged WASM directly. */
export async function verifyGateway(evidence: unknown, context: unknown, bytes?: BufferSource): Promise<string> {
  const input = JSON.stringify({ evidence, context });
  if (new TextEncoder().encode(input).length > 8 * 1024 * 1024) throw new Error('gateway attestation failed');
  if (typeof Worker === 'undefined') return (await import('./verifier-runtime.js')).verifyLocally(input, bytes);
  if (!worker) {
    worker = new Worker(new URL('./verifier-worker.js', import.meta.url), { type: 'module' });
    worker.onmessage = ({ data }) => {
      const call = pending.get(data.id); if (!call) return;
      pending.delete(data.id); clearTimeout(call.timer);
      if (typeof data.result === 'string' && !data.error) call.resolve(data.result);
      else call.reject(new Error('gateway attestation failed'));
    };
    worker.onerror = () => {
      for (const call of pending.values()) { clearTimeout(call.timer); call.reject(new Error('Gateway verifier unavailable')); }
      pending.clear(); worker?.terminate(); worker = undefined;
    };
  }
  const id = ++serial;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('Gateway verification timed out')); }, 60_000);
    pending.set(id, { resolve, reject, timer });
    worker!.postMessage({ id, input, bytes });
  });
}
