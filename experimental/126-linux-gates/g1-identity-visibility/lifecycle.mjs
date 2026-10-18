// Holder supervision for the G1 runner (#126 research).
//
// Wraps ../../126-guard-liveness/lib/common.mjs (read-only) so that every
// started child is stopped exactly once and every stop outcome is turned into
// faults. Stopping only closes stdin and waits with a bound. Nothing here
// sends a signal; an exceeded bound is `incomplete` and the child is left to
// its own lifetime.
import { startChild, stopChild } from '../../126-guard-liveness/lib/common.mjs'

// Faults for one stop outcome. A holder is expected to exit 0 on stdin EOF.
export function stopFaults(role, outcome, expectedExit = 0) {
  if (!outcome || typeof outcome !== 'object') return [`${role}:stop_outcome_missing`]
  const faults = []
  if (outcome.incomplete) faults.push(`${role}:incomplete`)
  if (outcome.error) faults.push(`${role}:error:${outcome.error}`)
  if (Array.isArray(outcome.stdinErrors) && outcome.stdinErrors.length) faults.push(`${role}:stdin_errors:${outcome.stdinErrors.length}`)
  if (!outcome.incomplete) {
    if (outcome.signal) faults.push(`${role}:signal:${outcome.signal}`)
    if (outcome.exitCode !== expectedExit) faults.push(`${role}:exit:${outcome.exitCode}`)
  }
  return faults
}

// Tracks every child it starts. `stop` is memoized per handle, so a child's
// outcome is recorded once even if both the per-run cleanup and the final
// sweep reach it.
export function createSupervisor() {
  const live = new Set()
  const outcomes = new Map()
  return {
    start(command, args, options, readyMs) { return startChild(command, args, options, live, readyMs) },
    stop(handle, budgetMs) {
      if (!outcomes.has(handle)) outcomes.set(handle, stopChild(handle, budgetMs))
      return outcomes.get(handle)
    },
    async sweep(budgetMs) {
      const swept = []
      for (const handle of live) if (!outcomes.has(handle)) swept.push({ pid: handle.pid, outcome: await this.stop(handle, budgetMs) })
      return swept
    },
    started: () => live.size,
    stopped: () => outcomes.size,
  }
}

const readyFailure = (error) => {
  const message = String(error?.message ?? error)
  if (message.startsWith('ready timeout')) return 'timeout'
  if (message.startsWith('exited before ready')) return 'exited'
  if (message.startsWith('stdout ended before ready')) return 'stdout_ended'
  return 'other'
}

// One holder lifetime: start, parse readiness, run `during(ready)`, stop.
// Returns every observation; `faults` covers readiness, `during` errors and
// the stop outcome. A failure in any phase never skips the stop.
export async function superviseOnce(supervisor, { role = 'holder', command, args, options, readyMs = 5000, stopMs = 5000,
  validateReady = () => null, during = async () => null }) {
  const faults = []
  const result = { role, ready: null, duringResult: null, error: null, outcome: null, faults }
  let handle
  try {
    handle = supervisor.start(command, args, options, readyMs)
    result.pid = handle.pid
    let line
    try { line = await handle.ready } catch (error) { faults.push(`${role}:ready_failed:${readyFailure(error)}`); throw error }
    try { result.ready = JSON.parse(line) } catch (error) { faults.push(`${role}:ready_unparseable`); throw error }
    const invalid = validateReady(result.ready, handle)
    if (invalid) { faults.push(`${role}:ready_invalid:${invalid}`); throw new Error(invalid) }
    result.duringResult = await during(result.ready, handle)
  } catch (error) {
    result.error = String(error?.message ?? error)
    if (!faults.length) faults.push(`${role}:during_failed`)
  } finally {
    if (handle) {
      result.outcome = await supervisor.stop(handle, stopMs)
      result.stderr = handle.stderr
      faults.push(...stopFaults(role, result.outcome))
    }
  }
  return result
}
