/** Bound a peer's absolute expiry despite the verifier's allowed clock skew.
 * A slow local clock must never extend the locally enforced lifetime. */
export function delegationDeadline(remote: unknown, current: number, lifetime: number): number {
  if (!Number.isSafeInteger(remote) || (remote as number) <= current || (remote as number) > current + lifetime + 60) throw new Error('Gateway session rejected');
  return Math.min(remote as number, current + lifetime);
}
