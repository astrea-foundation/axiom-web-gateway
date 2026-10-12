import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GatewayClient, type VerifiedGateway } from '../src/index.js';
import { ProofRefresh } from '../src/proof.js';

const fixture = (policy_sequence = 10): VerifiedGateway => ({
  encryption_key: '12'.repeat(32), authorization_key: '34'.repeat(32), origin: 'https://gateway.example',
  image_digest: 'fixture', source_repository: 'fixture', source_revision: 'fixture', generation: 2,
  policy_sequence, policy_expires_at: Math.floor(Date.now() / 1000) + 86400,
  evidence_expires_at: Math.floor(Date.now() / 1000) + 240, config_repository: 'fixture', config_digest: 'fixture',
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

// These fixtures test orchestration of already verified results, not TEE acceptance.
test('concurrent RPC refreshes share one verification and advance the policy floor', async () => {
  const proof = fixture(), waiting = deferred<VerifiedGateway>();
  const floors: number[] = [];
  const refresh = new ProofRefresh(proof, minimum => { floors.push(minimum); return waiting.promise; });
  const first = refresh.refresh(), second = refresh.refresh();
  assert.deepEqual(floors, [10]);
  waiting.resolve(fixture(12)); await Promise.all([first, second]);
  assert.equal(proof.policy_sequence, 12);
  await refresh.refresh();
  assert.deepEqual(floors, [10, 12]);
});
test('a stale or rotated verification result cannot replace the accepted proof', async () => {
  const proof = fixture(12), original = { ...proof };
  for (const candidate of [fixture(11), { ...fixture(13), encryption_key: '56'.repeat(32) }, { ...fixture(13), authorization_key: '56'.repeat(32) }]) {
    const refresh = new ProofRefresh(proof, async () => candidate);
    await assert.rejects(refresh.refresh(), /rollback|reconnect/);
    assert.deepEqual(proof, original);
  }
});
test('a failed refresh is shared and does not prevent a later retry', async () => {
  const proof = fixture(); let attempts = 0;
  const refresh = new ProofRefresh(proof, async () => {
    if (++attempts === 1) throw new Error('Verification unavailable');
    return fixture(11);
  });
  const results = await Promise.allSettled([refresh.refresh(), refresh.refresh()]);
  assert(results.every(result => result.status === 'rejected')); assert.equal(attempts, 1);
  await refresh.refresh(); assert.equal(proof.policy_sequence, 11); assert.equal(attempts, 2);
});
test('a connection waits for the durable checkpoint and fails before granting on rollback', async () => {
  // Fake worker output isolates the async checkpoint boundary. Real WASM rejection
  // is covered separately; no inference endpoint or hardware acceptance is mocked live.
  const originalWorker = globalThis.Worker, originalFetch = globalThis.fetch;
  class WorkerFixture {
    onmessage?: (message: { data: { id: number; result: string } }) => void;
    postMessage({ id }: { id: number }) { queueMicrotask(() => this.onmessage?.({ data: { id, result: JSON.stringify(fixture()) } })); }
  }
  globalThis.Worker = WorkerFixture as unknown as typeof Worker;
  globalThis.fetch = async () => new Response('{}');
  try {
    const entered = deferred<void>(), checkpoint = deferred<void>(); let grants = 0;
    const connection = GatewayClient.connect({
      gatewayOrigin: 'https://gateway.example', backendOrigin: 'https://api.example', publisherKey: 'ab'.repeat(32),
      rememberPolicySequence: async () => { entered.resolve(); await checkpoint.promise; throw new Error('Gateway policy rollback rejected'); },
      grant: async () => { grants++; throw new Error('Grant must not be requested'); },
    });
    const rejected = assert.rejects(connection, /rollback/);
    await entered.promise; assert.equal(grants, 0);
    checkpoint.resolve(); await rejected; assert.equal(grants, 0);
  } finally { globalThis.Worker = originalWorker; globalThis.fetch = originalFetch; }
});
