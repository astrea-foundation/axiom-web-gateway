import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GatewayClient } from '../src/index.js';
import { sha256 } from '@noble/hashes/sha2.js';

// Unit tests for chunk construction only. Actual RPCs always verify fresh TEE
// evidence and use EHBP; this port never opens an inference listener.
test('upload chunks preserve original bytes and bind the eventual request', async () => {
  const operations: any[] = [];
  const client = Object.create(GatewayClient.prototype) as GatewayClient;
  client.rpc = async operation => { operations.push(operation); return operation.op === 'upload_begin' ? { upload_id: 'ab'.repeat(16) } : {}; };
  const bytes = crypto.getRandomValues(new Uint8Array(64000));
  const original = new Uint8Array(1048577); for (let i = 0; i < original.length; i++) original[i] = bytes[i % bytes.length]!;
  const result = await client.upload({ bytes: original, targetRequestId: 'cd'.repeat(16), model: 'tinfoil-model', kind: 'file', name: 'original.pdf', mimeType: 'application/pdf' });
  assert.equal(result, 'ab'.repeat(16));
  assert.equal(operations[0].upload.target_request_id, 'cd'.repeat(16));
  assert.equal(operations[0].upload.model, 'tinfoil-model');
  assert.equal(operations[0].upload.sha256, Buffer.from(sha256(original)).toString('hex'));
  const chunks = operations.slice(1); let offset = 0;
  for (const chunk of chunks) {
    assert.equal(chunk.offset, offset);
    const decoded = Buffer.from(chunk.data, 'base64');
    assert(decoded.length <= 256 * 1024);
    assert.deepEqual(decoded, Buffer.from(original.subarray(offset, offset + decoded.length)));
    offset += decoded.length; assert.equal(chunk.final_chunk, offset === original.length);
  }
  assert.equal(offset, original.length);
});
test('failed chunks discard session-owned handles and oversized files never dispatch', async () => {
  const operations: any[] = [], client = Object.create(GatewayClient.prototype) as GatewayClient;
  client.rpc = async operation => { operations.push(operation); if (operation.op === 'upload_chunk') throw new Error('Interrupted'); return { upload_id: 'ab'.repeat(16) }; };
  const input = { bytes: new Uint8Array([1]), targetRequestId: 'cd'.repeat(16), model: 'model', kind: 'file' as const, name: 'file.txt', mimeType: 'text/plain' };
  await assert.rejects(client.upload(input), /Interrupted/);
  assert.deepEqual(operations.at(-1), { op: 'upload_abort', target_request_id: input.targetRequestId });
  const before = operations.length;
  await assert.rejects(client.upload({ ...input, bytes: new Uint8Array(10 * 1024 * 1024 + 1) }), /exceeds limit/);
  assert.equal(operations.length, before);
});
