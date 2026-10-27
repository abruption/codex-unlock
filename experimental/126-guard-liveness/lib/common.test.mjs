import assert from 'node:assert/strict'
import { test } from 'node:test'
import process from 'node:process'
import { startChild, stopAll } from './common.mjs'

test('cleanup retains a child that exited after readiness with nonzero status', async () => {
  const children = new Set()
  const child = startChild(process.execPath, ['-e', 'process.stdout.write("ready\\n"); process.exitCode=3'], {}, children)
  assert.equal(await child.ready, 'ready')
  assert.equal((await child.exited).exitCode, 3)
  const outcomes = await stopAll(children, 1000)
  assert.equal(outcomes.length, 1)
  assert.equal(outcomes[0].exitCode, 3)
})

test('spawn failure remains available to cleanup', async () => {
  const children = new Set()
  const child = startChild('/nonexistent-codex-research-fixture', [], {}, children)
  await assert.rejects(child.ready, /exited before ready/)
  const outcomes = await stopAll(children, 1000)
  assert.equal(outcomes.length, 1)
  assert.match(outcomes[0].error, /ENOENT/)
})
