// A misspelled fault must not silently run a successful nominal measurement.
export function parseF1Fault(value) {
  if (value === undefined || value === '') return null
  if (value === 'skip_round' || value === 'waiter_lifetime') return value
  throw new Error('F1_FAULT must be empty, skip_round or waiter_lifetime')
}
