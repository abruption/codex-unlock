// `lsof +fg` file-flag scan shared by the M2 matrix and the barrier wrapper.
// Only FWASLOCKED (0x4000) in the first G value is interpreted, and only as
// refusal-side evidence: an absent bit can exclude a candidate, a present bit
// never proves a holder. Missing fields or unparseable values are `unknown`.
import { spawnSync } from 'node:child_process'

export const FWASLOCKED = 0x4000

export function fgScan(lockPath, lsof = '/usr/sbin/lsof') {
  const result = spawnSync(lsof, ['-nP', '+fg', '-F0pfG', '--', lockPath], {
    env: { LC_ALL: 'C', LANG: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
    timeout: 5000, maxBuffer: 1024 * 1024,
  })
  return {
    status: result.status, signal: result.signal,
    stderr: result.stderr?.toString() ?? '',
    raw: result.stdout?.toString() ?? '',
    entries: parseFg(result.stdout?.toString() ?? ''),
  }
}

export function parseFg(stdout) {
  const entries = []
  let pid = null
  for (const field of stdout.split(/[\0\n]/)) {
    if (!field) continue
    const tag = field[0]
    const value = field.slice(1)
    if (tag === 'p') pid = /^\d+$/.test(value) ? Number(value) : null
    else if (tag === 'f') entries.push({ pid, fd: value, flags: null, wasLocked: 'unknown' })
    else if (tag === 'G' && entries.length) {
      const entry = entries.at(-1)
      const match = /^0x([0-9a-f]+)(;|$)/i.exec(value)
      entry.flags = value
      if (match && entry.pid !== null) entry.wasLocked = (parseInt(match[1], 16) & FWASLOCKED) !== 0
    }
  }
  return entries
}

// Refusal-side filter: `reject` when the bit is absent, `unknown` when it
// cannot be read, `not_excluded` when it is present. There is no `holder`.
export function filterDecision(entry) {
  if (!entry || entry.wasLocked === 'unknown') return 'unknown'
  return entry.wasLocked ? 'not_excluded' : 'reject'
}
