import assert from 'node:assert/strict';
import test from 'node:test';
import { response, requests, threadId } from '../observe-native.mjs';
test('responses need exactly one outcome and the expected ID', () => {
  assert.deepEqual(response({ id: 1, result: {} }, 1), {});
  for (const record of [null, [], { id: 1 }, { id: 1, result: {}, error: {} }, { id: 2, result: {} }, { id: 1, error: {} }]) {
    assert.throws(() => response(record, 1));
  }
});
test('thread identity must be a UUID, never a path', () => {
  assert.equal(threadId({ thread: { id: '11111111-2222-4333-8444-555555555555' } }), '11111111-2222-4333-8444-555555555555');
  for (const id of ['', '../other', '123', null]) assert.throws(() => threadId({ thread: { id } }));
});
test('fixed protocol cannot start a model turn or authentication', () => {
  const protocol = requests('C:\\private\\home');
  assert.deepEqual(protocol.map((item) => item.method), ['initialize', 'initialized', 'thread/start']);
  assert.equal(protocol[2].params.approvalPolicy, 'never');
  assert.equal(protocol[2].params.sandbox, 'read-only');
  assert.equal(protocol[2].params.ephemeral, false);
  assert.equal(JSON.stringify(protocol).includes('turn/start'), false);
});
