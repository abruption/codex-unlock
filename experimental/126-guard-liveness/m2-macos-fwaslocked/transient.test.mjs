import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import net from 'node:net'
import path from 'node:path'
import process from 'node:process'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { assertSocketPath, freshPrivateDir, startChild, stopChild, writeNew } from '../lib/common.mjs'

const DIR = path.dirname(fileURLToPath(import.meta.url))
const requireFrom = path.resolve(DIR, '../../../node_modules/fs-ext-extra-prebuilt/package.json')
const { flockSync } = createRequire(requireFrom)('fs-ext-extra-prebuilt')

function request(socketPath, command) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath, () => socket.write(command + '\n'))
    let text = ''
    socket.setTimeout(1000, () => socket.destroy(new Error('request timeout')))
    socket.on('error', reject)
    socket.on('data', (chunk) => {
      text += chunk
      if (text.includes('\n')) { socket.destroy(); resolve(text.split('\n')[0]) }
    })
  })
}

test('reentrant attempt preserves the original descriptors until finish', async () => {
  const dir = freshPrivateDir('127-reentrant')
  const guardPath = path.join(dir, '.coordination.lock')
  const lockPath = path.join(dir, 'thread.lock')
  const socket = path.join(dir, 's.sock')
  assertSocketPath(socket)
  writeNew(guardPath, ''); writeNew(lockPath, '')
  const owner = fs.openSync(lockPath, 'r+')
  const guard = fs.openSync(guardPath, 'r')
  flockSync(owner, 'exnb')
  const handle = startChild(path.join(DIR, 'transient/codex'), [], {
    env: { PATH: process.env.PATH, FIXTURE_REQUIRE_FROM: requireFrom, FIXTURE_LOCK_PATH: lockPath,
      FIXTURE_SOCKET: socket, FIXTURE_LOG: path.join(dir, 'events.jsonl'), FIXTURE_LIFETIME_MS: '5000' },
  }, new Set())
  try {
    assert.equal(await handle.ready, 'ready')
    assert.equal(await request(socket, 'attempt'), 'inside')
    assert.equal(await request(socket, 'attempt'), 'busy')
    assert.throws(() => flockSync(guard, 'exnb'), (error) => ['EAGAIN', 'EWOULDBLOCK'].includes(error.code))
    assert.equal(await request(socket, 'finish'), 'done')
    flockSync(guard, 'exnb'); flockSync(guard, 'un')
  } finally {
    const result = await stopChild(handle)
    fs.closeSync(owner); fs.closeSync(guard)
    if (!result.incomplete) fs.rmSync(dir, { recursive: true })
    assert.equal(result.exitCode, 0, JSON.stringify(result))
  }
})
