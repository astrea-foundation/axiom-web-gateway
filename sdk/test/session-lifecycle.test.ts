import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GatewaySessionError } from '../src/errors.js';
import { HEARTBEAT_INTERVAL_MS, SESSION_IDLE_MS, SessionLifecycle } from '../src/session-lifecycle.js';

const settle = () => new Promise<void>(resolve => setImmediate(resolve));

test('heartbeats stop at the original delegation expiry and older gateways receive no new operations', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let valid = true;
  const operations: string[] = [];
  const session = new SessionLifecycle(true, () => valid, async op => { operations.push(op); return { alive: true, closed: true }; });
  session.start();
  t.mock.timers.tick(0); await settle();
  assert.deepEqual(operations, ['heartbeat']);
  t.mock.timers.tick(HEARTBEAT_INTERVAL_MS); await settle();
  assert.deepEqual(operations, ['heartbeat', 'heartbeat']);
  valid = false;
  t.mock.timers.tick(HEARTBEAT_INTERVAL_MS); await settle();
  assert.equal(session.available, false);
  await session.close();
  assert.equal(operations.length, 2);
  const older = new SessionLifecycle(false, () => true, async () => { throw new Error('Unsupported control dispatched'); });
  older.start(); await older.close();
});

test('idempotent close waits for a retained reply and its uploads before releasing the original session', async () => {
  const operations: string[] = [];
  const session = new SessionLifecycle(true, () => true, async op => { operations.push(op); return { closed: true }; });
  const releaseReply = session.retain();
  const upload = session.enter();
  const closing = session.close();
  assert.equal(session.close(), closing);
  assert.equal(session.available, false);
  upload(); upload();
  const nextUpload = session.retain();
  // The retained owner can still send its normal inference after upload finishes.
  const inference = session.enter();
  releaseReply(); releaseReply();
  assert.deepEqual(operations, []);
  inference();
  assert.deepEqual(operations, []);
  nextUpload();
  await closing;
  assert.deepEqual(operations, ['session_close']);
  assert.throws(() => session.enter(), GatewaySessionError);
});

test('a transient heartbeat failure preserves the connection but authenticated rejection requires reconnect', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let attempts = 0;
  const session = new SessionLifecycle(true, () => true, async () => {
    if (++attempts === 1) throw new TypeError('Network unavailable');
    throw new GatewaySessionError('session_expired');
  });
  session.start(); t.mock.timers.tick(0); await settle();
  assert.equal(session.available, true);
  t.mock.timers.tick(HEARTBEAT_INTERVAL_MS); await settle();
  assert.equal(session.available, false);
  await session.close();
});

test('closing during an in-flight catalog does not race its heartbeat or dispatch another operation', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const operations: string[] = [];
  const session = new SessionLifecycle(true, () => true, async op => { operations.push(op); return { closed: true }; });
  const leave = session.enter();
  session.start();
  const closing = session.close();
  t.mock.timers.tick(0); await settle();
  assert.deepEqual(operations, []);
  leave(); await closing;
  assert.deepEqual(operations, ['session_close']);
});

test('a sleeping tab detects idle expiry before dispatching new work or a resumed heartbeat', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const operations: string[] = [];
  const session = new SessionLifecycle(true, () => true, async op => { operations.push(op); return { alive: true, closed: true }; });
  session.start(); t.mock.timers.tick(0); await settle();
  assert.equal(session.available, true);
  t.mock.timers.tick(SESSION_IDLE_MS); await settle();
  assert.equal(session.available, false);
  assert.throws(() => session.enter(), GatewaySessionError);
  assert.deepEqual(operations, ['heartbeat']);
  await session.close();
});

test('an active response remains protected across idle expiry without extending the next idle lease', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: 0 });
  const session = new SessionLifecycle(true, () => true, async () => ({ closed: true }));
  const leave = session.enter();
  t.mock.timers.setTime(SESSION_IDLE_MS + 1);
  assert.equal(session.available, true);
  session.acknowledge(0); leave();
  assert.equal(session.available, false);
  await session.close();
});

test('expiry between heartbeat scheduling and acquisition fails closed without an unhandled rejection', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let checks = 0;
  const operations: string[] = [];
  const session = new SessionLifecycle(true, () => ++checks < 3, async op => { operations.push(op); return { alive: true }; });
  session.start(); t.mock.timers.tick(0); await settle();
  assert.equal(session.available, false);
  assert.deepEqual(operations, []);
  await session.close();
});
