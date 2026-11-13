import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { decryptResponseWithToken } from 'ehbp';
import { sha256 } from '@noble/hashes/sha2.js';
import { CipherCommitments, OUTER, POOL, encoder, hash, hex, ndjson, outerFrames, requestDigest, signed, strictJson, unbase64, unhex } from '../src/pool-wire.js';

const vector = JSON.parse(await readFile(new URL('./pool-vectors.json', import.meta.url), 'utf8'));
const frames: Uint8Array[] = vector.response_frames.map((v: string) => unbase64(v, 100_000));
const token = () => ({ exportedSecret: unhex(vector.exported_secret, 32), requestEnc: unhex(vector.request_enc, 32) });
function stream(parts: Uint8Array[], fragment = 17) {
  return new ReadableStream<Uint8Array>({ start(controller) {
    for (const part of parts) for (let i = 0; i < part.length; i += fragment) controller.enqueue(part.slice(i, i + fragment));
    controller.close();
  } });
}
test('Rust worker ciphertext, exporter, ordered transcript, receipt and prefix interoperate with the browser', async () => {
  assert.equal(requestDigest(vector.request.encapsulated_key, unbase64(vector.request.body, 100_000)), vector.request_digest);
  const commitments = new CipherCommitments(vector.request_digest, vector.response_nonce);
  for (const frame of frames) for (const byte of frame) commitments.push(Uint8Array.of(byte));
  const opened = await decryptResponseWithToken(new Response(stream(frames), { headers: { 'ehbp-response-nonce': vector.response_nonce } }), token());
  const transcript = sha256.create(); let sequence = 0; let complete = false;
  for await (const frame of ndjson(opened.body!, 100_000)) {
    assert.equal(frame.value.protocol, POOL);
    assert.equal(frame.value.sequence, sequence);
    assert.equal(frame.value.binding_sha256, hash(vector.binding));
    assert.equal(frame.value.request_wire_sha256, vector.request_digest);
    const prefix = commitments.take(sequence);
    if (frame.value.kind === 'terminal') {
      const end = frame.value.data;
      assert.equal(end.frame_count, sequence);
      assert.equal(end.transcript_sha256, hex(transcript.digest()));
      const receipt = await signed(end.receipt, vector.worker_public_key, 'axiom-pool-receipt-v1');
      assert.equal(receipt.response_prefix_sha256, prefix);
      assert.equal(receipt.binding_sha256, hash(vector.binding));
      assert.deepEqual(receipt.binding, strictJson(vector.binding));
      assert.equal(receipt.request_wire_sha256, vector.request_digest);
      assert.deepEqual(receipt.usage, end.usage);
      await assert.rejects(signed(end.receipt, vector.worker_public_key, 'axiom-pool-ticket-v1'));
      const corrupt = { ...end.receipt, signature: '00'.repeat(64) };
      await assert.rejects(signed(corrupt, vector.worker_public_key, 'axiom-pool-receipt-v1'));
      complete = true;
    } else { transcript.update(frame.raw); }
    sequence++;
  }
  assert.equal(complete, true); commitments.finish();
});
test('wrong context, nonce, reordered, replayed, corrupted and truncated encrypted frames fail closed', async () => {
  const corrupt = frames.map(f => f.slice()); corrupt[0]![15] ^= 1;
  const variants = [ [frames[1]!, frames[0]!, frames[2]!], [frames[0]!, ...frames], corrupt, [frames[0]!.slice(0, -1)] ];
  for (const parts of variants) {
    const opened = await decryptResponseWithToken(new Response(stream(parts), { headers: { 'ehbp-response-nonce': vector.response_nonce } }), token());
    await assert.rejects(opened.arrayBuffer());
  }
  for (const change of ['secret', 'nonce']) {
    const context = token(); if (change === 'secret') context.exportedSecret[0] ^= 1;
    const opened = await decryptResponseWithToken(new Response(stream(frames), { headers: { 'ehbp-response-nonce': change === 'nonce' ? '00'.repeat(32) : vector.response_nonce } }), context);
    await assert.rejects(opened.arrayBuffer());
  }
});
test('strict JSON rejects recursive duplicate identity fields, invalid unicode, excessive depth and infinities', () => {
  for (const raw of ['{"worker":{"key":1,"key":2}}', '{"a":1,"\\u0061":2}', '"\\ud800"', '"\\udc00"', '1e9999', '['.repeat(65) + '0' + ']'.repeat(65)]) assert.throws(() => strictJson(raw));
  assert.deepEqual(strictJson('{"a":["\\ud83d\\ude00",null,true,-2.3e2]}'), { a: ['😀', null, true, -230] });
});
test('outer relay requires the originating request, transcript, exactly one terminal and EOF', async () => {
  const id = 'a'.repeat(32); const data = encoder.encode(JSON.stringify({ protocol: OUTER, request_id: id, sequence: 0, kind: 'worker_bytes', data: { bytes_base64: 'AA==' } }) + '\n');
  const terminal = encoder.encode(JSON.stringify({ protocol: OUTER, request_id: id, sequence: 1, kind: 'terminal', data: { success: true, transcript_sha256: hash(data) } }) + '\n');
  async function consume(parts: Uint8Array[], request = id) { const result = []; for await (const frame of outerFrames(new Response(stream(parts)), request)) result.push(frame); return result; }
  assert.equal((await consume([data, terminal])).length, 1);
  for (const parts of [[data], [terminal, data], [data, terminal, terminal], [data, terminal.slice(0, -1)]]) await assert.rejects(consume(parts));
  await assert.rejects(consume([data, terminal], 'b'.repeat(32)));
});
