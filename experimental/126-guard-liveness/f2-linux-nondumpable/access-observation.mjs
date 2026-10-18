// Collection contract for observe.py's JSON result. This validates that each
// access attempt was recorded for the requested fixture instance. An errno,
// false identity comparison, or empty lock list is collected evidence, not a
// passing permission/lock hypothesis. No OS or product operations run here.
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
const integer = (value) => Number.isSafeInteger(value) && value >= 0
const text = (value) => typeof value === 'string' && value.length > 0
const decimal = (value) => typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value)
const arrayOf = (test) => (value) => Array.isArray(value) && value.every(test)
const ROWS = Object.freeze({
  proc_dir_uid: integer,
  fd_dir_uid: integer,
  fdinfo_dir_uid: integer,
  self_ns_mnt_readlink: text,
  ns_mnt_readlink: text,
  fd_listdir: (value) => arrayOf(decimal)(value) && new Set(value).size === value.length,
  fd_readlink: text,
  fd_stat_matches_lock: (value) => Array.isArray(value) && value.length === 2 && value.every((v) => typeof v === 'boolean'),
  fdinfo_lock_rows: arrayOf((value) => typeof value === 'string' && value.startsWith('lock:')),
  exe_readlink: text,
  cmdline: (value) => Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === 'string'),
  stat_start_ticks: decimal,
  status_uid_line: (value) => Array.isArray(value) && value.length <= 1 &&
    value.every((v) => typeof v === 'string' && /^Uid:\s+\d+\s+\d+\s+\d+\s+\d+\s*$/.test(v)),
})

export function validateAccessObservation(value, expected) {
  const faults = []
  if (!object(expected) || !integer(expected.pid) || expected.pid === 0 ||
    !integer(expected.fd) || !integer(expected.uid) || !text(expected.kernel) || !decimal(expected.startTicks)) {
    return { collected: false, faults: ['expected_identity_invalid'] }
  }
  if (!object(value)) return { collected: false, faults: ['observation_not_object'] }
  const keys = ['pid', 'fd', 'observer_uid', 'kernel', ...Object.keys(ROWS)]
  if (Object.keys(value).some((key) => !keys.includes(key))) faults.push('unexpected_field')
  for (const [key, want] of [['pid', expected.pid], ['fd', expected.fd], ['observer_uid', expected.uid], ['kernel', expected.kernel]]) {
    if (!Object.hasOwn(value, key) || value[key] !== want) faults.push(`${key}_unbound`)
  }
  for (const [name, valid] of Object.entries(ROWS)) {
    if (!Object.hasOwn(value, name)) { faults.push(`${name}:missing`); continue }
    const row = value[name]
    if (!object(row)) { faults.push(`${name}:not_object`); continue }
    const fields = Object.keys(row)
    if (fields.length !== 1 || (fields[0] !== 'ok' && fields[0] !== 'errno')) {
      faults.push(`${name}:outcome_invalid`)
      continue
    }
    if (fields[0] === 'errno') {
      // Python errno.errorcode emits a symbolic name, falling back to the
      // decimal errno string for an unmapped native error.
      if (typeof row.errno !== 'string' || !/^(E[A-Z0-9_]+|[1-9]\d*)$/.test(row.errno)) faults.push(`${name}:errno_invalid`)
    } else if (!valid(row.ok)) faults.push(`${name}:value_invalid`)
  }
  if (decimal(value.stat_start_ticks?.ok) && value.stat_start_ticks.ok !== expected.startTicks) faults.push('stat_start_ticks:instance_changed')
  return { collected: faults.length === 0, faults }
}
