import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { GatewayClient } from '../src/index.js';
import { verifyLocally } from '../src/verifier-runtime.js';
test('packaged Tinfoil browser verifier rejects malformed evidence without echoing input', async () => {
  const bytes = await readFile(new URL('../wasm/axiom_gateway_verifier.wasm', import.meta.url));
  for (const input of ['{}', '{"PRIVATE_INPUT":true}', 'broken PRIVATE_INPUT']) {
    await assert.rejects(verifyLocally(input, bytes), { message: 'gateway attestation failed' });
  }
});

test('gateway startup loads the verifier while its evidence fetch is pending', async (t) => {
  let releaseEvidence!: (response: Response) => void;
  const evidence = new Promise<Response>(resolve => { releaseEvidence = resolve; });
  const fetched = t.mock.method(globalThis, 'fetch', (url: string) => url.endsWith('/v1/attestation')
    ? evidence : Promise.resolve(Response.json({})));
  const posted: Array<string | undefined> = [];
  const originalWorker = globalThis.Worker;
  class TestWorker {
    onmessage?: (event: { data: { id: number; result?: string; error?: string } }) => void;
    postMessage({ id, input }: { id: number; input?: string }) {
      posted.push(input);
      queueMicrotask(() => this.onmessage?.({ data: input === undefined ? { id, result: '' } : { id, error: 'invalid evidence' } }));
    }
  }
  globalThis.Worker = TestWorker as unknown as typeof Worker;
  try {
    const grant = t.mock.fn();
    const connecting = GatewayClient.connect({ gatewayOrigin: 'https://gateway.example', backendOrigin: 'https://api.example',
      publisherKey: 'ab'.repeat(32), grant });
    const rejected = assert.rejects(connecting, { message: 'gateway attestation failed' });
    assert.equal(fetched.mock.callCount(), 2);
    assert.deepEqual(posted, [undefined]);
    releaseEvidence(Response.json({}));
    await rejected;
    assert.equal(typeof posted[1], 'string');
    assert.equal(grant.mock.callCount(), 0);
  } finally {
    globalThis.Worker = originalWorker;
  }
});
