// Fixed expectations from the recorded M2 Part 2 table, not inferred from the
// current outcome. A mismatch invalidates this reproduction; it does not prove
// that a product refusal is unsafe or that the filter establishes ownership.
const EXPECTED = Object.freeze({
  B_failed: { safe: false, sameOwner: false, filter: 'reject', blockers: ['owner_holds_other_thread_locks'] },
  B_failed_all_scans: { safe: true, sameOwner: false, filter: 'reject', blockers: [] },
  B_former: { safe: true, sameOwner: false, filter: 'not_excluded', blockers: [] },
  control_visible_holder: { safe: true, sameOwner: true, filter: 'not_excluded', blockers: [] },
})

export function diagnosticEvidence(result) {
  return {
    exitCode: result.status ?? null, signal: result.signal ?? null,
    error: result.error?.message ?? null, stderr: result.stderr?.toString() ?? '',
  }
}

export function barrierEventFailed(event) {
  if (['barrier_failed', 'barrier_release_failed', 'fatal'].includes(event.event)) return true
  if (event.event === 'barrier_entered') return event.reply !== 'inside'
  if (event.event === 'done') return event.exitCode !== 0 || Boolean(event.signal || event.error) || event.stderr !== ''
  return false
}

export function evaluatePart2Scenario(scenario, inspection, holderPid, visiblePid, measurement) {
  const expected = EXPECTED[scenario]
  if (!expected) return ['unknown_scenario']
  const failures = []
  const pidValid = (pid) => Number.isSafeInteger(pid) && pid > 0
  if (!pidValid(holderPid) || !pidValid(visiblePid) || (holderPid === visiblePid) !== expected.sameOwner) failures.push('fixture_pid_relation')
  if (inspection?.classification !== 'live_owner') failures.push('classification')
  if (inspection?.safeToUnlock !== expected.safe) failures.push('eligibility')
  const ownerPid = inspection?.owner?.pid
  if (!pidValid(ownerPid) || ownerPid !== visiblePid || (ownerPid === holderPid) !== expected.sameOwner) failures.push('owner_relation')
  if (!Array.isArray(inspection?.openers) || inspection.openers.length !== 1 || inspection.openers[0]?.pid !== visiblePid) failures.push('visible_opener')
  if (!Array.isArray(inspection?.blockers) || inspection.blockers.length !== expected.blockers.length ||
    !expected.blockers.every((blocker) => inspection.blockers.includes(blocker))) failures.push('blockers')
  if (measurement?.filterMeasurementValid !== true || measurement.failure !== null ||
    !Array.isArray(measurement.ownerDecisions) || measurement.ownerDecisions.length === 0 ||
    !measurement.ownerDecisions.every((decision) => decision === expected.filter) ||
    measurement.filterWouldRefuse !== (expected.filter === 'reject')) failures.push('filter_result')
  return failures
}
