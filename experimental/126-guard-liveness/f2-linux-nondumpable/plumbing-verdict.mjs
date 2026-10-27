// Pure nominal plumbing verdict. validateF2 already distinguishes an allowed
// prepare error (for example macOS has no /proc) from a collection failure.
// No stage-level fault may be filtered out by the smoke runner.
import { F2_STAGES, validateF2 } from './protocol.mjs'

export function evaluateNominalPlumbing(observation) {
  const protocol = validateF2(observation)
  const failures = []
  if (JSON.stringify(observation.begun) !== JSON.stringify(F2_STAGES)) failures.push(`nominal stage order ${observation.begun}`)
  if (protocol.faults.length > 0) failures.push(`nominal protocol ${protocol.faults}`)
  if (observation.incomplete || !Array.isArray(observation.faults) || observation.faults.length > 0) {
    failures.push(`nominal observer ${observation.faults}`)
  }
  return { ok: failures.length === 0, failures, protocol }
}
