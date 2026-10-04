import assert from 'node:assert/strict';
import { test } from 'node:test';
import { browserGrant } from '../src/index.js';

test('existing API session supplies CSRF across approved first-party origins', async () => {
  const original = globalThis.fetch;
  const requests: [string, RequestInit | undefined][] = [];
  globalThis.fetch = async (url, options) => {
    requests.push([String(url), options]);
    return Response.json(requests.length === 1 ? { authenticated: true, csrf_token: 'test-csrf', account: { email: 'private@example.test' } } : { grant: 'axw_' + 'a'.repeat(43) });
  };
  try {
    const publicKey = { kty: 'EC', crv: 'P-256', x: 'fixture', y: 'fixture' };
    assert.equal(await browserGrant('https://api.example.com')(publicKey), 'axw_' + 'a'.repeat(43));
    assert.equal(requests[0]![0], 'https://api.example.com/api/v1/auth/session');
    assert.equal(requests[1]![1]!.credentials, 'include');
    assert.deepEqual(JSON.parse(requests[1]![1]!.body as string), { browser_key: publicKey });
    assert.equal(new Headers(requests[1]![1]!.headers).get('x-csrf-token'), 'test-csrf');
    assert.equal(new Headers(requests[1]![1]!.headers).has('authorization'), false);
  } finally { globalThis.fetch = original; }
});

test('signed-out session creates no grant', async () => {
  const original = globalThis.fetch; let calls = 0;
  globalThis.fetch = async () => { calls++; return Response.json({ authenticated: false }); };
  try {
    await assert.rejects(browserGrant('https://api.example.com')({}), /authenticated account/);
    assert.equal(calls, 1);
  } finally { globalThis.fetch = original; }
});
