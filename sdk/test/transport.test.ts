import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Identity } from 'ehbp';
import { GatewayTransport } from '../src/transport.js';

test('application ciphertext bypasses shim EHBP and never accepts plaintext responses', async () => {
  const identity = await Identity.generate();
  const transport = new GatewayTransport(identity, 'https://gateway.example');
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async input => {
    calls++;
    const request = input as Request;
    assert.equal(request.headers.get('ehbp-encapsulated-key'), null);
    assert.match(request.headers.get('axiom-encapsulated-key')!, /^[0-9a-f]{64}$/);
    assert.equal(request.credentials, 'omit');
    assert.notEqual(new TextDecoder().decode(await request.arrayBuffer()), 'private fixture');
    return new Response('{"success":true}', { status: 200 });
  };
  try {
    await assert.rejects(transport.request('https://gateway.example/v1/rpc', { method: 'POST', body: 'private fixture', credentials: 'omit' }), /Authenticated gateway response required/);
    await assert.rejects(transport.request('https://attacker.example/v1/rpc', { method: 'POST', body: 'private fixture' }), /Encrypted gateway request required/);
    await assert.rejects(transport.request('https://gateway.example/v1/rpc', { method: 'POST' }), /Encrypted gateway request required/);
    assert.equal(calls, 1);
  } finally { globalThis.fetch = original; }
});
