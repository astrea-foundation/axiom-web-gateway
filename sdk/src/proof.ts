import type { VerifiedGateway } from './index.js';
import { GatewayRestartedError } from './errors.js';

/** One locally verified refresh at a time for the connection's accepted keys. */
export class ProofRefresh {
  private pending: Promise<void> | undefined;
  constructor(
    private readonly proof: VerifiedGateway,
    private readonly verify: (minimum: number, signal?: AbortSignal) => Promise<VerifiedGateway>,
  ) {}

  async refresh(signal?: AbortSignal): Promise<void> {
    if (!this.pending) {
      this.pending = this.verify(this.proof.policy_sequence, signal).then(fresh => {
        if (fresh.policy_sequence < this.proof.policy_sequence) throw new Error('Gateway policy rollback rejected');
        if (fresh.encryption_key !== this.proof.encryption_key || fresh.authorization_key !== this.proof.authorization_key) throw new GatewayRestartedError();
        Object.assign(this.proof, fresh);
      });
    }
    const pending = this.pending;
    try { await pending; }
    finally { if (this.pending === pending) this.pending = undefined; }
  }
}
