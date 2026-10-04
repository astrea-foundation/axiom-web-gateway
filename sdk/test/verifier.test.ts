import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import init, { verify_gateway } from '../wasm/axiom_gateway_protocol.js';

test('packaged browser verifier rejects missing or malformed evidence without echoing input', async () => {
  await init({ module_or_path: await readFile(new URL('../wasm/axiom_gateway_protocol_bg.wasm', import.meta.url)) });
  for (const input of ['{}', '{"PRIVATE_INPUT":true}', 'broken PRIVATE_INPUT']) {
    try { verify_gateway(input, '{}'); assert.fail('unverified evidence accepted'); }
    catch (error) { assert.equal(String(error), 'gateway attestation failed'); }
  }
});
