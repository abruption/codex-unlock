// Linux-only real-kernel checks for the G2 models (#126 research). On other
// platforms every test is skipped and proves nothing.
//
// Same-user synthetic Python holders in a fresh private scratch directory
// (RESEARCH_TMP_ROOT, or /tmp on Linux). No holder is signalled: holders end
// on stdin EOF, a runner-owned release file, or their own lifetime, and every
// wait is bounded. A bound that expires fails the test as incomplete; it is
// never escalated. The `spawnSync` lock prober has a 5 s timeout, after which
// Node would send SIGTERM to that prober only. These tests measure
// /proc/locks and fdinfo semantics only; they do not run the product or any
// Codex process.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { setTimeout as delay } from 'node:timers/promises'
import { test } from 'node:test'
import { freshPrivateDir, startChild, stopAll } from '../../126-guard-liveness/lib/common.mjs'
import { decideG4, parseProcLocks } from './designs.mjs'

const linux = process.platform === 'linux'
const skip = linux ? false : 'Linux-only real /proc test; skipped on this platform'
const HOLD = `
import fcntl, json, os, select, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print(json.dumps({"pid": os.getpid(), "fd": fd}), flush=True)
deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    r, _, _ = select.select([0], [], [], max(0, deadline - time.monotonic()))
    if r and not os.read(0, 4096):
        break
`
// Grandchild: holds the inherited description FD. Its control channel is the
// runner-owned directory CTL, independent of any pipe: it writes ready.json
// (exclusive), holds until CTL/release exists or its own 20 s lifetime ends,
// closes the FD, writes exit.json and exits (0 on release, 3 on lifetime).
const GRANDCHILD = `
import json, os, sys, time
fd = int(sys.argv[1]); ctl = sys.argv[2]
deadline = time.monotonic() + 20
def ticks():
    try:
        text = open("/proc/self/stat").read()
        return text[text.rindex(") ") + 2:].split()[19]
    except OSError:
        return None
def record(name, value):
    out = os.open(os.path.join(ctl, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(out, json.dumps(value).encode()); os.close(out)
record("ready.json", {"pid": os.getpid(), "ticks": ticks(), "fd": fd})
released = False
while time.monotonic() < deadline:
    if os.path.exists(os.path.join(ctl, "release")):
        released = True
        break
    time.sleep(0.02)
os.close(fd)
record("exit.json", {"pid": os.getpid(), "ticks": ticks(), "released": released})
sys.exit(0 if released else 3)
`
// Parent: takes the flock, starts the grandchild with the description and
// no inherited stdio, prints both PIDs and exits without closing the lock
// (the grandchild's copy keeps the description).
const PARENT = `
import fcntl, json, os, subprocess, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_NOFOLLOW)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
child = subprocess.Popen([sys.executable, "-I", "-c", ${JSON.stringify(GRANDCHILD)}, str(fd), sys.argv[2]], pass_fds=(fd,),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(json.dumps({"parent": os.getpid(), "child": child.pid, "fd": fd}), flush=True)
os._exit(0)
`
const PROBE = 'import fcntl, os, sys\nfd = os.open(sys.argv[1], os.O_RDONLY)\ntry:\n    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n    print("free")\nexcept BlockingIOError:\n    print("held")\n'

const devParts = (dev) => ({ major: ((dev >> 8n) & 0xfffn) | ((dev >> 32n) & 0xfffff000n), minor: (dev & 0xffn) | ((dev >> 12n) & 0xffffff00n) })
const targetOf = (file) => { const s = fs.statSync(file, { bigint: true }); return { ...devParts(s.dev), inode: s.ino } }
const fdinfoRows = (pid, fd) => fs.readFileSync(`/proc/${pid}/fdinfo/${fd}`, 'utf8').split('\n')
  .map((l) => /^lock:\s+\d+:\s+FLOCK\s+ADVISORY\s+WRITE\s+-?\d+\s+([0-9a-f]+):([0-9a-f]+):(\d+)\s+0\s+EOF$/i.exec(l))
  .filter(Boolean).map((m) => ({ major: BigInt(`0x${m[1]}`), minor: BigInt(`0x${m[2]}`), inode: BigInt(m[3]) }))
const probe = (file) => {
  const r = spawnSync('python3', ['-I', '-c', PROBE, file], { encoding: 'utf8', timeout: 5000 })
  return r.status === 0 && !r.signal ? r.stdout.trim() : `probe_failed:${r.status}:${r.signal}`
}
// Start ticks of a live, non-zombie instance, or null.
const liveTicks = (pid) => {
  try {
    const text = fs.readFileSync(`/proc/${pid}/stat`, 'utf8')
    const fields = text.slice(text.lastIndexOf(') ') + 2).trim().split(/\s+/)
    return fields[0] === 'Z' || fields[0] === 'X' ? null : fields[19]
  } catch { return null }
}
const within = (promise, ms) => Promise.race([promise, delay(ms).then(() => 'incomplete')])
async function waitFor(check, ms) {
  const until = Date.now() + ms
  while (Date.now() < until) { const v = check(); if (v) return v; await delay(20) }
  return null
}
const readJson = (file) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')) } catch { return null } }
function scratch() {
  const dir = freshPrivateDir('126-g2-locks')
  const file = path.join(dir, 'thread.lock')
  fs.writeFileSync(file, '', { flag: 'wx', mode: 0o600 })
  const ctl = path.join(dir, 'ctl')
  fs.mkdirSync(ctl, { mode: 0o700 })
  return { file, ctl }
}

test('direct holder: the granted /proc/locks row carries the holder PID and the target dev:ino', { skip }, async () => {
  const { file } = scratch()
  const live = new Set()
  try {
    const holder = startChild('python3', ['-I', '-c', HOLD, file], { env: { PATH: '/usr/bin:/bin' } }, live)
    const ready = JSON.parse(await holder.ready)
    const rows = parseProcLocks(fs.readFileSync('/proc/locks', 'utf8'), targetOf(file))
    assert.deepEqual(rows.filter((r) => !r.blocked), [{ blocked: false, access: 'WRITE', pid: ready.pid }])
    assert.equal(fdinfoRows(ready.pid, ready.fd).length, 1)
  } finally {
    for (const r of await stopAll(live, 5000)) {
      assert.equal(r.incomplete, undefined, 'holder exit incomplete (not signalled)')
      assert.deepEqual([r.exitCode, r.signal, r.stdinErrors.length], [0, null, 0])
    }
  }
})

test('inherited description: the grandchild keeps the lock, /proc/locks keeps the acquirer, G4 refuses the grandchild', { skip }, async () => {
  const { file, ctl } = scratch()
  const live = new Set()
  let grand = null
  try {
    const parent = startChild('python3', ['-I', '-c', PARENT, file, ctl], { env: { PATH: '/usr/bin:/bin' } }, live)
    const ids = JSON.parse(await parent.ready)
    const parentExit = await within(parent.exited, 5000)
    assert.notEqual(parentExit, 'incomplete', 'parent exit unconfirmed within 5 s')
    assert.deepEqual(parentExit, { exitCode: 0, signal: null })
    grand = await waitFor(() => readJson(path.join(ctl, 'ready.json')), 5000)
    assert.ok(grand, 'grandchild ready record missing within 5 s')
    assert.equal(grand.pid, ids.child)
    assert.match(String(grand.ticks), /^\d+$/)
    // Instance binding before and after every measurement.
    assert.equal(liveTicks(grand.pid), grand.ticks, 'grandchild instance not live at measurement start')
    assert.equal(probe(file), 'held')
    const target = targetOf(file)
    const procLocks = fs.readFileSync('/proc/locks', 'utf8')
    const granted = parseProcLocks(procLocks, target).filter((r) => !r.blocked)
    // Init PID namespace: the exited acquirer's PID. Child namespace: omitted.
    assert.ok(granted.length === 0 || (granted.length === 1 && granted[0].pid === ids.parent), JSON.stringify(granted))
    const rows = fdinfoRows(grand.pid, grand.fd)
    assert.equal(rows.length, 1)
    const link = fs.readlinkSync(`/proc/${grand.pid}/fd/${grand.fd}`)
    const descriptors = fs.readdirSync(`/proc/${grand.pid}/fd`).sort((a, b) => Number(a) - Number(b))
    const s = { descriptors, readlink: link, startTicks: grand.ticks }
    const decision = decideG4({ candidatePid: grand.pid, candidateFd: String(grand.fd), candidates: [String(grand.fd)], target,
      pre: { ...s, fdinfoRows: rows }, guard: { ...s, probe: 'held', pidNamespaceSame: true, mountNamespaceSame: true, procLocks },
      post: { ...s, fdinfoRows: rows, commandUnchanged: true } })
    assert.equal(decision.decision, 'refuse')
    assert.ok(['acquirer_pid_mismatch', 'proc_locks_no_granted_row'].includes(decision.reason), decision.reason)
    assert.equal(liveTicks(grand.pid), grand.ticks, 'grandchild instance changed during measurement')
  } finally {
    // Runner-owned release; never a signal.
    fs.writeFileSync(path.join(ctl, 'release'), '', { flag: 'wx', mode: 0o600 })
    for (const r of await stopAll(live, 5000)) assert.equal(r.incomplete, undefined, 'parent exit incomplete')
    if (grand) {
      const exit = await waitFor(() => readJson(path.join(ctl, 'exit.json')), 5000)
      assert.ok(exit, 'grandchild exit record missing within 5 s (incomplete, not signalled)')
      assert.deepEqual([exit.pid, exit.ticks, exit.released], [grand.pid, grand.ticks, true])
      const ended = await waitFor(() => liveTicks(grand.pid) !== grand.ticks, 5000)
      assert.ok(ended, 'grandchild instance still live 5 s after its exit record (incomplete)')
      assert.equal(probe(file), 'free')
    }
  }
})

test('epoll fdinfo reaches the file type show_fdinfo callback (tfd lines)', { skip }, (t) => {
  const epoll = fs.readdirSync('/proc/self/fd').find((n) => { try { return fs.readlinkSync(`/proc/self/fd/${n}`) === 'anon_inode:[eventpoll]' } catch { return false } })
  if (!epoll) { t.skip('no epoll descriptor in this process'); return }
  const text = fs.readFileSync(`/proc/self/fdinfo/${epoll}`, 'utf8')
  // ep_show_fdinfo prints one tfd line per watched descriptor while holding ep->mtx.
  assert.match(text, /^tfd:\s+\d+/m)
})
