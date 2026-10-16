#!/usr/bin/env node
// Cross-platform plumbing check for the F2 inspector (#126 research).
//
//   F2_BUILD=<build.mjs output> RESEARCH_TMP_ROOT=<root> node plumbing-smoke.mjs
//
// Not an F2 result. It checks only that inspect-child.mjs, the generic
// observer and the F2 protocol work together against a real build:
// 1. nominal: every F2 stage is reported once, in order, the build verifies
//    and unlock.js is unreachable. Product outcomes (on macOS `prepare` fails
//    because there is no /proc) are recorded, not judged.
// 2. F2_CHILD_FAULT=stall:prepare: the stage bound returns `incomplete` with
//    open stage `prepare`, and the child's late exit is looked for with a bound.
// The target is a same-user Python flock holder started here. It ends on stdin
// EOF or after 60 s. No process is signalled.
import { log } from 'node:console'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { freshPrivateDir, startChild, stopAll, writeNew } from '../lib/common.mjs'
import { lateExitStatus, runIsolated } from '../lib/isolated-observer.mjs'
import { F2_STAGES, validateF2 } from './protocol.mjs'

const DIR = path.dirname(fileURLToPath(import.meta.url))
const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
if (!process.env.F2_BUILD) throw new Error('F2_BUILD is required')
const BUILD = fs.realpathSync(process.env.F2_BUILD)
const HOLDER = `
import fcntl, json, os, select, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print(json.dumps({"ready": True, "pid": os.getpid(), "fd": fd}), flush=True)
deadline = time.monotonic() + 60
while time.monotonic() < deadline:
    r, _, _ = select.select([0], [], [], max(0, deadline - time.monotonic()))
    if r and not os.read(0, 4096):
        break
os.close(fd)
`

const out = freshPrivateDir('126-f2-plumbing')
const home = path.join(out, 'home')
fs.mkdirSync(path.join(home, 'thread-writer-locks'), { recursive: true, mode: 0o700 })
fs.mkdirSync(path.join(home, 'sessions', '2026', '10', '16'), { recursive: true, mode: 0o700 })
writeNew(path.join(home, 'thread-writer-locks', '.coordination.lock'), '')
const lockPath = path.join(home, 'thread-writer-locks', `${THREAD_ID}.lock`)
writeNew(lockPath, '')
writeNew(path.join(home, 'sessions', '2026', '10', '16', `rollout-2026-10-16T00-00-00-${THREAD_ID}.jsonl`),
  JSON.stringify({ timestamp: '2026-10-16T00:00:00.000Z', type: 'event_msg', payload: { type: 'task_complete' } }) + '\n')
const live = new Set()
const failures = []
const report = { build: BUILD, cases: [] }
try {
  const holder = startChild('python3', ['-I', '-c', HOLDER, lockPath], { env: { PATH: '/usr/bin:/bin' } }, live)
  const ready = JSON.parse(await holder.ready)
  const args = [path.join(DIR, 'inspect-child.mjs'), BUILD, String(ready.pid), String(ready.fd), lockPath, home, THREAD_ID]
  const env = { PATH: '/usr/sbin:/usr/bin:/bin' }
  const nominal = await runIsolated(process.execPath, args, { startupBudgetMs: 10000, budgetMs: 15000, env })
  const protocol = validateF2(nominal)
  report.cases.push({ case: 'nominal', faults: nominal.faults, protocolFaults: protocol.faults, begun: nominal.begun,
    outcomes: nominal.stages.map((s) => [s.stage, s.error ? `error:${s.error.code ?? s.error.name}:${s.error.message}` : 'result']) })
  if (JSON.stringify(nominal.begun) !== JSON.stringify(F2_STAGES)) failures.push(`nominal stage order ${nominal.begun}`)
  if (protocol.faults.some((f) => /^stage_(order|duplicate|unknown|result_malformed:(dist_identity|module_load))/.test(f) || f.startsWith('stages_missing'))) {
    failures.push(`nominal protocol ${protocol.faults}`)
  }
  if (nominal.incomplete || nominal.faults.length) failures.push(`nominal observer ${nominal.faults}`)
  const stalled = await runIsolated(process.execPath, args, { startupBudgetMs: 10000, budgetMs: 2000, env: { ...env, F2_CHILD_FAULT: 'stall:prepare' } })
  const [late] = stalled.lateExit ? await lateExitStatus([{ label: { case: 'stall:prepare' }, instance: stalled.instance, lateExit: stalled.lateExit }], 20000) : [null]
  report.cases.push({ case: 'stall:prepare', incomplete: stalled.incomplete, phase: stalled.incompletePhase, openStage: stalled.openStage,
    begun: stalled.begun, late })
  if (!stalled.incomplete || stalled.incompletePhase !== 'stages' || stalled.openStage !== 'prepare') failures.push('stall case not bounded at prepare')
  if (late?.status !== 'exited' || late.exit.code !== 4) failures.push(`stall case late exit ${JSON.stringify(late)}`)
} catch (error) {
  failures.push(String(error?.stack ?? error))
} finally {
  for (const r of await stopAll(live, 5000)) if (r.incomplete || r.exitCode !== 0) failures.push(`holder ${JSON.stringify(r)}`)
}
Object.assign(report, { ok: failures.length === 0, failures })
writeNew(path.join(out, 'plumbing-results.json'), JSON.stringify(report, null, 2) + '\n')
log(JSON.stringify({ out, ...report }, null, 2))
process.exitCode = report.ok ? 0 : 1
