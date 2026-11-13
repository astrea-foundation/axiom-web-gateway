import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { PROTOCOL, readFrames } from '../src/frames.js';
const id = 'a'.repeat(32);
const line = (sequence: number, kind: string, data: unknown, request_id = id) => JSON.stringify({ protocol: PROTOCOL, request_id, sequence, kind, data }) + '\n';
const first = line(0, 'text_delta', { text: 'secret', provisional: true });
const digest = createHash('sha256').update(first).digest('hex');
const terminal = line(1, 'terminal', { success: true, transcript_sha256: digest, result: { upstream_response_verified: true } });
const stream = (...chunks: string[]) => new ReadableStream<Uint8Array>({ start(controller) { for (const chunk of chunks) controller.enqueue(new TextEncoder().encode(chunk)); controller.close(); } });
test('only authenticated terminal and EOF complete a split stream', async () => {
  const seen: unknown[] = [];
  const result = await readFrames(stream(first.slice(0, 7), first.slice(7) + terminal.slice(0, 19), terminal.slice(19)), id, f => seen.push(f));
  assert.equal(seen.length, 1); assert.equal(result.success, true);
});
test('missing completion cannot promote provisional deltas', async () => {
  let deltas = 0;
  await assert.rejects(readFrames(stream(first), id, () => deltas++), /interrupted/);
  assert.equal(deltas, 1);
});
test('digest substitution, wrong request, reordering, suffix and partial EOF fail', async () => {
  for (const text of [first + terminal.replace(digest, '0'.repeat(64)), first.replace(id, 'b'.repeat(32)) + terminal, terminal + first, first + terminal + first, first + terminal.slice(0, -1), first + terminal.replace('"success":true', '"success":false')]) {
    await assert.rejects(readFrames(stream(text), id, () => {}));
  }
});
test('oversized frame fails before a listener receives it', async () => {
  let received = false;
  await assert.rejects(readFrames(stream('x'.repeat(1024 * 1024 + 1)), id, () => { received = true; }), /exceeds/);
  assert.equal(received, false);
});
test('an AEAD reader error after terminal still fails completion', async () => {
  const faulty = new ReadableStream<Uint8Array>({ start(c) { c.enqueue(new TextEncoder().encode(first + terminal)); }, pull(c) { c.error(new Error('authentication failed')); } });
  await assert.rejects(readFrames(faulty, id, () => {}), /authentication failed/);
});
