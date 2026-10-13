import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { socketFor, startChild, stopChild } from '../scripts/fixtures/attribution-interleaving/orchestrator.mjs'
import { removePidSets } from '../scripts/fixtures/attribution-interleaving/lsof-barrier.mjs'

test('research socket paths cannot collide with scenario home directories', () => {
  const scratch = path.join(tmpdir(), 'cu-research')
  assert.notEqual(socketFor(scratch, 's2'), path.join(scratch, 's2'))
  assert.ok(socketFor(scratch, 's2').endsWith('.sock'))
  assert.throws(() => socketFor('/' + 'x'.repeat(110), 's2'))
})

test('research PID filtering removes only the requested complete process set', () => {
  const input = 'p12\0cnode\0\nf3\0nfixture\0\np123\0cnode\0\nf4\0nfixture\0\n'
  const output = removePidSets(input, 12)
  assert.ok(!output.includes('p12\0'))
  assert.ok(output.includes('p123\0'))
  assert.ok(output.includes('f4\0'))
  assert.ok(!output.includes('f3\0'))
})

test('research child readiness buffers split records and EOF closes normally', async () => {
  const scratch = await mkdtemp(path.join(tmpdir(), 'codex-attribution-test-'))
  const registry = []
  try {
    const script = path.join(scratch, 'ready.mjs')
    await writeFile(script, "process.stdout.write('rea');setTimeout(()=>process.stdout.write('dy\\n'),20);process.stdin.resume();process.stdin.on('end',()=>process.exit(0));\n")
    const { child } = await startChild(script, {}, { registry, budgetMs: 2000 })
    assert.equal(registry.length, 1)
    const result = await stopChild(child, 2000)
    assert.equal(result.exitCode, 0)
    assert.ok(!result.incomplete)
  } finally {
    for (const child of registry) await stopChild(child, 2000)
    await rm(scratch, { recursive: true })
  }
})

test('research readiness timeout still registers child for cooperative cleanup', async () => {
  const scratch = await mkdtemp(path.join(tmpdir(), 'codex-attribution-test-'))
  const registry = []
  try {
    const script = path.join(scratch, 'silent.mjs')
    await writeFile(script, "process.stdin.resume();process.stdin.on('end',()=>process.exit(0));\n")
    await assert.rejects(startChild(script, {}, { registry, budgetMs: 50 }))
    assert.equal(registry.length, 1)
    const result = await stopChild(registry[0], 2000)
    assert.equal(result.exitCode, 0)
    assert.ok(!result.incomplete)
  } finally {
    for (const child of registry) await stopChild(child, 2000)
    await rm(scratch, { recursive: true })
  }
})

test('research startup failure remains nonzero and keeps the registered child', async () => {
  const scratch = await mkdtemp(path.join(tmpdir(), 'codex-attribution-test-'))
  const registry = []
  try {
    const script = path.join(scratch, 'failed.mjs')
    await writeFile(script, 'process.exit(7);\n')
    await assert.rejects(startChild(script, {}, { registry, budgetMs: 2000 }))
    assert.equal(registry.length, 1)
    const result = await stopChild(registry[0], 2000)
    assert.equal(result.exitCode, 7)
  } finally {
    for (const child of registry) await stopChild(child, 2000)
    await rm(scratch, { recursive: true })
  }
})
