import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import process from 'node:process'
import { test } from 'node:test'
import { fileURLToPath, URL } from 'node:url'

const cli = fileURLToPath(new URL('../evaluate.mjs', import.meta.url))
const secret = 'PRIVATE_INPUT_SENTINEL_NOT_FOR_OUTPUT'
const root = process.env.RESEARCH_TMP_ROOT ?? (process.platform === 'darwin' ? null : tmpdir())
if (!root) throw new Error('RESEARCH_TMP_ROOT is required on macOS')

function invoke(args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 10000 })
}

test('unreadable and invalid configuration inputs are structured unknown without data excerpts', () => {
  const dir = mkdtempSync(join(root, 'codex-observer-cli-'))
  try {
    const preflight = join(dir, 'preflight.jsonl')
    const observe = join(dir, 'observe.jsonl')
    const baseline = join(dir, 'baseline.json')
    writeFileSync(preflight, '{}\n', { mode: 0o600 })
    writeFileSync(observe, '{}\n', { mode: 0o600 })
    const common = ['run', '--label', 'medium', '--preflight', preflight, '--observe', observe]
    const cases = [
      { args: ['run', '--label', 'medium', '--preflight', join(dir, secret), '--observe', observe], reason: 'input_unreadable' },
      { baseline: `{"${secret}":`, reason: 'baseline_invalid_json' },
      { baseline: '[]', reason: 'baseline_not_object' },
    ]
    for (const entry of cases) {
      if (entry.baseline !== undefined) writeFileSync(baseline, entry.baseline, { mode: 0o600 })
      const result = invoke(entry.args ?? [...common, '--baseline', baseline])
      assert.equal(result.status, 2, result.stderr)
      assert.equal(result.stderr, '')
      assert.deepEqual(JSON.parse(result.stdout), { status: 'unknown', problems: [entry.reason], safeToUnlock: false })
      assert.ok(!result.stdout.includes(secret))
      assert.ok(!result.stdout.includes(dir))
    }
    assert.equal(readFileSync(preflight, 'utf8'), '{}\n')
    assert.equal(readFileSync(observe, 'utf8'), '{}\n')
  } finally { rmSync(dir, { recursive: true }) }
})

test('usage and table retain their documented exit codes', () => {
  assert.equal(invoke([]).status, 64)
  assert.equal(invoke(['table']).status, 0)
})
