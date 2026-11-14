import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { GatewayClient } from '../src/index.js';
import { PROTOCOL } from '../src/frames.js';

const id = 'c'.repeat(32);
const line = (sequence: number, kind: string, data: unknown) => JSON.stringify({ protocol: PROTOCOL, request_id: id, sequence, kind, data }) + '\n';
const prefix = line(0, 'text_delta', { text: 'original ' });
const complete = (start = prefix) => start + line(1, 'text_delta', { text: 'answer' }) + line(2, 'terminal', {
  success: true, transcript_sha256: createHash('sha256').update(start + line(1, 'text_delta', { text: 'answer' })).digest('hex'), result: { verified: true },
});
const response = (body: string) => new Response(body, { headers: { 'ehbp-response-nonce': 'a'.repeat(64) } });

async function fixture(transport: (operation: Record<string, unknown>) => Promise<Response>) {
  const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const publicKey = await crypto.subtle.exportKey('jwk', key.publicKey);
  return Object.assign(Object.create(GatewayClient.prototype), {
    options: { gatewayOrigin: 'https://gateway.invalid' },
    proof: { policy_expires_at: Date.now() / 1000 + 600, evidence_expires_at: Date.now() / 1000 + 600, encryption_key: 'a'.repeat(64) },
    expires: Date.now() / 1000 + 600, session: 'fixture', key: key.privateKey, publicKey, resumable: true,
    lifecycle: { enter: () => () => {}, acknowledge: () => {} },
    transport: { request: async (_url: string, init: RequestInit) => transport(JSON.parse(JSON.parse(init.body as string).payload)) },
  }) as GatewayClient;
}

test('a cut stream resumes the same request and never redispatches inference or duplicate deltas', async () => {
  const operations: Record<string, unknown>[] = [], text: string[] = [];
  const client = await fixture(async operation => { operations.push(operation); return response(operations.length === 1 ? prefix : complete()); });
  assert.deepEqual(await client.rpc({ op: 'infer', request: {} }, frame => text.push((frame.data as { text: string }).text), { requestId: id }), { verified: true });
  assert.deepEqual(text, ['original ', 'answer']);
  assert.deepEqual(operations.map(op => op.op), ['infer', 'resume']);
  assert.equal(operations[1]!.target_request_id, id);
  assert.notEqual(operations[1]!.request_id, id);
});

test('changed replay prefixes fail closed even if their new transcript digest is valid', async () => {
  let calls = 0;
  const client = await fixture(async () => response(++calls === 1 ? prefix : complete(line(0, 'text_delta', { text: 'substitution' }))));
  await assert.rejects(client.rpc({ op: 'infer', request: {} }, () => {}, { requestId: id }), /changed an accepted frame/);
  assert.equal(calls, 2);
});

test('stop in recovery cancels the delay without issuing a resume or another generation', async () => {
  let calls = 0; const controller = new AbortController();
  const client = await fixture(async () => { calls++; return response(prefix); });
  await assert.rejects(client.rpc({ op: 'infer', request: {} }, () => {}, { requestId: id, signal: controller.signal,
    onRecovery: () => controller.abort(new Error('Stopped')) }), /Stopped/);
  assert.equal(calls, 1);
});

test('authentication errors never reconnect', async () => {
  let calls = 0;
  const client = await fixture(async () => { calls++; return new Response(new ReadableStream({ start(c) { c.error(new Error('AEAD authentication failed')); } }), { headers: { 'ehbp-response-nonce': 'a'.repeat(64) } }); });
  await assert.rejects(client.rpc({ op: 'infer', request: {} }, () => {}, { requestId: id }), /AEAD authentication failed/);
  assert.equal(calls, 1);
});
