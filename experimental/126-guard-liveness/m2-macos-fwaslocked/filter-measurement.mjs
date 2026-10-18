// A valid scan with no selected owner (or unknown owner evidence) is not a
// completed filter measurement. This is separate from proving lock ownership.
export function evaluateFilterMeasurement(scans) {
  const records = Array.isArray(scans) ? scans : []
  const ownerDecisions = records.map((scan) => scan?.owner?.decision ?? 'no_owner')
  const filterMeasurementValid = records.length > 0 && records.every((scan) => scan?.valid === true &&
    (scan.owner?.decision === 'reject' || scan.owner?.decision === 'not_excluded'))
  return {
    ownerDecisions,
    filterMeasurementValid,
    filterWouldRefuse: filterMeasurementValid ? ownerDecisions.includes('reject') : null,
    failure: filterMeasurementValid ? null : 'filter_measurement_unavailable',
  }
}
