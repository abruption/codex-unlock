#!/usr/bin/env node
// Descriptor-lifetime actor for the M2 flag matrix (#127 research). Roles:
//   holder  open + flock(LOCK_EX|LOCK_NB) must succeed, hold until EOF
//   opener  open only, never calls flock
//   failed  open + flock(LOCK_EX|LOCK_NB) must fail with EWOULDBLOCK, keep FD
//   former  open + flock(LOCK_EX|LOCK_NB) must succeed, then LOCK_UN, keep FD
// Prints `ready` once its state is established; stdin EOF closes the FD and
// exits normally.
import fs from 'node:fs'
import { createRequire } from 'node:module'
import process from 'node:process'

const require = createRequire(process.env.FIXTURE_REQUIRE_FROM)
const { flockSync } = require('fs-ext-extra-prebuilt')
const role = process.env.FIXTURE_ROLE
const fd = fs.openSync(process.env.FIXTURE_LOCK_PATH, 'r+')

function tryLock() {
  try {
    flockSync(fd, 'exnb')
    return true
  } catch (error) {
    if (error.code !== 'EAGAIN' && error.code !== 'EWOULDBLOCK') throw error
    return false
  }
}

if (role === 'holder' || role === 'former') {
  if (!tryLock()) throw new Error(`${role}: expected to acquire`)
  if (role === 'former') flockSync(fd, 'un')
} else if (role === 'failed') {
  if (tryLock()) throw new Error('failed: unexpectedly acquired')
} else if (role !== 'opener') {
  throw new Error(`unknown role ${role}`)
}
process.stdout.write('ready\n')
process.stdin.resume()
process.stdin.on('end', () => {
  fs.closeSync(fd)
  process.exit(0)
})
