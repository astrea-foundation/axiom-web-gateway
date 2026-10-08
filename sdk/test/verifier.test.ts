import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { verifyLocally } from '../src/verifier-runtime.js';
test('packaged Tinfoil browser verifier rejects malformed evidence without echoing input', async () => {
  const bytes = await readFile(new URL('../wasm/axiom_gateway_verifier.wasm', import.meta.url));
  for (const input of ['{}', '{"PRIVATE_INPUT":true}', 'broken PRIVATE_INPUT']) {
    await assert.rejects(verifyLocally(input, bytes), { message: 'gateway attestation failed' });
  }
});
