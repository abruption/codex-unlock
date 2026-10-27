// Fixed Part 1 expectations from the recorded descriptor-lifetime matrix.
// Descriptor numbers/counts vary; the probe and every expected role's filter
// decision must still agree. not_excluded is never positive holder evidence.
const EXPECTED = Object.freeze({
  holder: { probe: 'held', roles: { holder: 'not_excluded' } },
  holder_multi_opener: { probe: 'held', roles: { holder: 'not_excluded', opener: 'reject' } },
  holder_opener: { probe: 'held', roles: { holder: 'not_excluded', opener: 'reject' } },
  holder_failed: { probe: 'held', roles: { holder: 'not_excluded', failed: 'reject' } },
  former_holder: { probe: 'held', roles: { former: 'not_excluded', holder: 'not_excluded' } },
  former_only: { probe: 'free', roles: { former: 'not_excluded' } },
  failed_after_holder_exit: { probe: 'free', roles: { failed: 'reject' } },
})

export function evaluatePart1Scenario(name, probe, scan, roles) {
  const expected = Object.hasOwn(EXPECTED, name) ? EXPECTED[name] : null
  if (!expected) return ['unknown_scenario']
  const failures = []
  if (scan?.valid !== true) failures.push('invalid_scan')
  if (probe !== expected.probe) failures.push('probe')
  if (roles === null || typeof roles !== 'object' || Array.isArray(roles)) return [...failures, 'roles_missing']
  const expectedRoles = Object.keys(expected.roles)
  if (Object.keys(roles).length !== expectedRoles.length || expectedRoles.some((role) => !Object.hasOwn(roles, role))) failures.push('role_set')
  for (const [role, decision] of Object.entries(expected.roles)) {
    const observed = roles[role]
    if (observed?.decision !== decision) failures.push(`decision:${role}`)
    if (!Number.isSafeInteger(observed?.pid) || observed.pid <= 0 ||
      !Array.isArray(observed.flags) || observed.flags.length === 0) failures.push(`evidence:${role}`)
  }
  return failures
}
