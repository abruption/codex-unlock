// `lsof +fg` file-flag scan for the M2 refusal-side filter (#127 research).
//
// Only FWASLOCKED (0x4000) in the first G value is interpreted, and only as
// refusal-side evidence. Per PID, every descriptor on the scanned path is
// aggregated:
//   - scan failed, signalled, wrote stderr, or its output is malformed
//     (a field outside a process/file set, a file set without G, an
//     unparseable G)                                      -> unknown
//   - PID absent from the scan                            -> unknown
//   - every descriptor of the PID lacks the bit           -> reject
//   - at least one descriptor has the bit                 -> not_excluded
// A present bit never proves a holder: it is sticky after LOCK_UN.
// Detectable truncation is invalid. A clean omission of whole process/file
// records cannot be detected from this output and is not ruled out here.
import { spawnSync } from 'node:child_process'

export const FWASLOCKED = 0x4000

// spawnSync's timeout makes Node send SIGTERM to lsof. The scan records
// `signal` and `error` so such a run is visible and counted as unknown.
export function fgScan(lockPath, lsof = '/usr/sbin/lsof') {
  const result = spawnSync(lsof, ['-nP', '+fg', '-F0pfG', '--', lockPath], {
    env: { LC_ALL: 'C', LANG: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
    timeout: 5000, maxBuffer: 1024 * 1024,
  })
  return interpretScan({
    status: result.status, signal: result.signal, error: result.error?.message ?? null,
    stderr: result.stderr?.toString() ?? '', stdout: result.stdout?.toString() ?? '',
  })
}

// Pure, so it can be checked against fixed outputs.
export function interpretScan({ status, signal = null, error = null, stderr = '', stdout = '' }) {
  const scan = { status, signal, error, stderr, raw: stdout, valid: true, problems: [], files: [] }
  if (error) scan.problems.push(`error:${error}`)
  if (signal) scan.problems.push(`signal:${signal}`)
  if (status !== 0) scan.problems.push(`status:${status}`)
  if (stderr) scan.problems.push('stderr')
  if (stdout && !stdout.endsWith('\0\n')) scan.problems.push('unterminated_record')
  let pid = null
  let file = null
  for (const record of stdout.split('\n')) {
    if (!record) continue
    if (!record.endsWith('\0')) scan.problems.push('unterminated_field')
    for (const field of record.split('\0')) {
      if (!field) continue
      const tag = field[0]
      const value = field.slice(1)
      if (tag === 'p') {
        if (file && file.flags === null) scan.problems.push(`no_flags:${file.pid}:${file.fd}`)
        file = null
        pid = /^[1-9]\d*$/.test(value) && Number.isSafeInteger(Number(value)) ? Number(value) : null
        if (pid === null) scan.problems.push(`bad_pid:${value}`)
      } else if (tag === 'f') {
        if (file && file.flags === null) scan.problems.push(`no_flags:${file.pid}:${file.fd}`)
        if (pid === null) scan.problems.push('file_without_process')
        if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) scan.problems.push(`bad_fd:${value}`)
        file = { pid, fd: value, flags: null, wasLocked: null }
        scan.files.push(file)
      } else if (tag === 'G') {
        if (!file) { scan.problems.push('flags_without_file'); continue }
        if (file.flags !== null) scan.problems.push(`duplicate_flags:${file.pid}:${file.fd}`)
        file.flags = value
        const match = /^0x([0-9a-f]+)(;0x[0-9a-f]+)?$/i.exec(value)
        if (match) file.wasLocked = (BigInt(`0x${match[1]}`) & BigInt(FWASLOCKED)) !== 0n
        else scan.problems.push(`bad_flags:${value}`)
      } else {
        scan.problems.push(`unexpected_field:${tag}`)
      }
    }
  }
  if (file && file.flags === null) scan.problems.push(`no_flags:${file.pid}:${file.fd}`)
  scan.valid = scan.problems.length === 0
  return scan
}

export function filterDecision(scan, pid) {
  if (!scan.valid) return { decision: 'unknown', reason: 'scan_invalid', descriptors: [] }
  const descriptors = scan.files.filter((f) => f.pid === pid)
  if (!descriptors.length) return { decision: 'unknown', reason: 'pid_absent', descriptors }
  if (descriptors.some((f) => f.wasLocked === null)) return { decision: 'unknown', reason: 'flags_unreadable', descriptors }
  return descriptors.some((f) => f.wasLocked)
    ? { decision: 'not_excluded', reason: 'bit_present', descriptors }
    : { decision: 'reject', reason: 'bit_absent_on_all', descriptors }
}

// Apply a modelled omission of one PID to a scan, as the product view sees it.
export function withoutPid(scan, pid) {
  return { ...scan, files: scan.files.filter((f) => f.pid !== pid) }
}
