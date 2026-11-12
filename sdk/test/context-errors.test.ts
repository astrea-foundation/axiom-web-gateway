import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { GatewayRequestError, requestFailure } from '../src/errors.js';
import { PROTOCOL, readFrames } from '../src/frames.js';

const id = 'b'.repeat(32);
const line = (sequence: number, kind: string, data: unknown) => JSON.stringify({ protocol: PROTOCOL, request_id: id, sequence, kind, data }) + '\n';
const rejection = { code: 'CONTEXT_LENGTH_EXCEEDED', stage: 'upstream_exchange', pre_generation: true };
const failure = (prefix = '', value: unknown = rejection) => prefix + line(prefix ? 1 : 0, 'terminal', {
  success: false, transcript_sha256: createHash('sha256').update(prefix).digest('hex'), result: value,
});
const stream = (text: string) => new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new TextEncoder().encode(text)); controller.close(); } });

test('only exact bounded context rejection metadata grants pre-generation recovery', () => {
  assert.equal(requestFailure(rejection).preGeneration, true);
  assert.equal(requestFailure({ ...rejection, stage: 'request_validation' }).preGeneration, true);
  for (const value of [
    { ...rejection, pre_generation: false }, { ...rejection, pre_generation: 'true' },
    { ...rejection, stage: 'upstream_attestation' }, { ...rejection, stage: 'private prompt' },
    { ...rejection, code: 'INVALID_REQUEST' }, { ...rejection, code: 'TRANSIENT_FAILURE' },
    { ...rejection, code: 'private provider diagnostic' }, { code: rejection.code, stage: rejection.stage },
  ]) {
    const error = requestFailure(value);
    assert.equal(error.preGeneration, false);
    assert.equal(error.message.includes('private'), false);
  }
});

test('context rejection reaches the caller only after terminal transcript binding and EOF', async () => {
  const prefix = line(0, 'accepted', { request_id: id });
  await assert.rejects(readFrames(stream(failure(prefix)), id, () => {}), error =>
    error instanceof GatewayRequestError && error.code === rejection.code && error.preGeneration);
  const text = failure(prefix);
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const pending = new ReadableStream<Uint8Array>({ start(value) { controller = value; value.enqueue(new TextEncoder().encode(text)); } });
  let settled = false;
  const reading = readFrames(pending, id, () => {}).finally(() => { settled = true; });
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(settled, false);
  controller.close();
  await assert.rejects(reading, error => error instanceof GatewayRequestError && error.preGeneration);
  const damaged = text.replace(createHash('sha256').update(prefix).digest('hex'), '0'.repeat(64));
  await assert.rejects(readFrames(stream(damaged), id, () => {}), error => !(error instanceof GatewayRequestError));
  const unauthenticatedEOF = new ReadableStream<Uint8Array>({
    start(value) { value.enqueue(new TextEncoder().encode(text)); },
    pull(value) { value.error(new Error('authentication failed at EOF')); },
  });
  await assert.rejects(readFrames(unauthenticatedEOF, id, () => {}), /authentication failed/);
});

test('generation or unknown frames withhold replay permission even if terminal claims pre-generation', async () => {
  for (const kind of ['text_delta', 'reasoning_delta', 'refusal_delta', 'tool_call_delta', 'image_progress', 'future_frame']) {
    const prefix = line(0, kind, { text: 'provisional', arguments: '{}' });
    await assert.rejects(readFrames(stream(failure(prefix)), id, () => {}), error =>
      error instanceof GatewayRequestError && error.code === rejection.code && !error.preGeneration);
  }
});
