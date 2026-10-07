import assert from 'node:assert/strict';
import { test } from 'node:test';
import { delegationDeadline } from '../src/expiry.js';

test('cross-clock delegation stays within its local lifetime and rejects expired or excessive leases', () => {
  assert.equal(delegationDeadline(1902, 1000, 900), 1900);
  assert.equal(delegationDeadline(1898, 1000, 900), 1898);
  for (const expiry of [1000, 999, 1961, 1900.5, '1900', NaN, Infinity]) assert.throws(() => delegationDeadline(expiry, 1000, 900));
});
