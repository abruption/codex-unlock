import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { test } from 'node:test'
import { freshPrivateDir } from '../lib/common.mjs'
import { options, shellQuote, wrapperText } from './options.mjs'

test('repeat and part bounds reject empty, fractional, unbounded and duplicate selections', () => {
  for (const value of ['', '0', '-1', '1.5', 'Infinity', 'NaN', '11', '1e1']) assert.throws(() => options({ M2_REPEATS: value }))
  for (const value of ['', '3', '1,', '1,1', '1,2,1', ' 1']) assert.throws(() => options({ M2_PARTS: value }))
  assert.deepEqual(options({ M2_REPEATS: '10', M2_PARTS: '2,1' }), { repeats: 10, parts: ['2', '1'] })
})

test('wrapper quotes shell substitutions, backticks, apostrophes and spaces literally', () => {
  const dir = freshPrivateDir('127-quote-test')
  try {
    // Only a marker inside this fresh private scratch could be affected by
    // accidental shell execution. No user paths or credentials are involved.
    const marker = path.join(dir, 'executed')
    const payload = ` spaces ' $(touch ${shellQuote(marker)}) \`touch ${shellQuote(marker)}\``
    const probe = path.join(dir, "probe ' spaced $(touch executed) `touch executed`.mjs")
    fs.writeFileSync(probe, 'process.stdout.write(JSON.stringify({config:process.env.FIXTURE_CONFIG,args:process.argv.slice(2)}))\n', { flag: 'wx', mode: 0o600 })
    const wrapper = path.join(dir, 'wrapper.sh')
    fs.writeFileSync(wrapper, wrapperText(payload, process.execPath, probe), { flag: 'wx', mode: 0o700 })
    const result = spawnSync('/bin/sh', [wrapper, payload], { cwd: dir, encoding: 'utf8', timeout: 3000 })
    assert.equal(result.status, 0, result.stderr)
    assert.deepEqual(JSON.parse(result.stdout), { config: payload, args: [payload] })
    assert.equal(fs.existsSync(marker), false)
  } finally {
    fs.rmSync(dir, { recursive: true })
  }
})
