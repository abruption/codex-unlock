#!/usr/bin/env node
// Descriptor-lifetime actor for the M2 flag matrix (#127 research). Roles:
//   holder        open + flock(LOCK_EX|LOCK_NB) must succeed, hold
//   holder_multi  as holder, plus a second plain descriptor on the same file
//   opener        open only, never calls flock
//   failed        open + flock(LOCK_EX|LOCK_NB) must fail with EWOULDBLOCK, keep FD
//   former        open + flock(LOCK_EX|LOCK_NB) must succeed, then LOCK_UN, keep FD
// Fault roles (runner fault checks only):
//   early_exit    exits 1 before reporting ready
//   ignore_eof    reports ready but ignores stdin EOF; ends at its lifetime
// Prints `ready` once its state is established. stdin EOF closes the FDs and
// exits 0; FIXTURE_LIFETIME_MS ends the process with code 3.
import fs from 'node:fs'
import { createRequire } from 'node:module'
import process from 'node:process'
import { setTimeout } from 'node:timers'

const require = createRequire(process.env.FIXTURE_REQUIRE_FROM)
const { flockSync } = require('fs-ext-extra-prebuilt')
const role = process.env.FIXTURE_ROLE
if (role === 'early_exit') process.exit(1)
const lockPath = process.env.FIXTURE_LOCK_PATH
const fds = [fs.openSync(lockPath, 'r+')]

function tryLock(fd) {
  try {
    flockSync(fd, 'exnb')
    return true
  } catch (error) {
    if (error.code !== 'EAGAIN' && error.code !== 'EWOULDBLOCK') throw error
    return false
  }
}

if (role === 'holder' || role === 'holder_multi' || role === 'former') {
  if (!tryLock(fds[0])) throw new Error(`${role}: expected to acquire`)
  if (role === 'former') flockSync(fds[0], 'un')
  if (role === 'holder_multi') fds.push(fs.openSync(lockPath, 'r'))
} else if (role === 'failed') {
  if (tryLock(fds[0])) throw new Error('failed: unexpectedly acquired')
} else if (role !== 'opener' && role !== 'ignore_eof') {
  throw new Error(`unknown role ${role}`)
}
const close = () => { for (const fd of fds) fs.closeSync(fd) }
process.stdout.write('ready\n')
const lifetime = setTimeout(() => { close(); process.exit(3) }, Number(process.env.FIXTURE_LIFETIME_MS ?? 60000))
// An ignore_eof actor must stay alive after EOF until its lifetime.
if (role !== 'ignore_eof') lifetime.unref()
process.stdin.resume()
process.stdin.on('end', () => {
  if (role === 'ignore_eof') return
  close()
  process.exit(0)
})
