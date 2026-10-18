// Offline evaluator for W6/W7 observer evidence (#151, #152). Reads only the
// JSONL files named on the command line. It never runs Codex, opens a Codex
// home, takes locks, or signals processes. Not part of npm test or npm files.
//
//   node evaluate.mjs table
//   node evaluate.mjs run --label medium|high --preflight P --observe O --baseline B.json
//   node evaluate.mjs pair --medium-preflight P --medium-observe O --high-preflight P --high-observe O --baseline B.json [--explanations E.json]
//   node evaluate.mjs pair-fixture --medium-lab L --medium-meta M --high-lab L --high-meta M [--explanations E.json]
//
// --baseline is the operator-asserted, independently established evidence:
// {"sourceCommit":"<40 hex>","binarySha256":"<64 hex>","version":"<line>","harness":{"<name>":"<64 hex>",...}},
// where the harness map holds exactly the harness file names (expectations.mjs,
// HARNESS_FILES) and their exact checkout bytes, line endings included. The
// formats and that name set are validated here; where the operator obtained
// the baseline cannot be shown by this tool. Without a format-valid baseline,
// provenance rows stay `unknown` and the run can never pass.
//
// `pair` additionally requires a validated provenance state on both sides.
// `pair-fixture` is always `unknown`: the existing fixture producer is not
// bound to its own bytes, run or source, so that comparison is deferred until
// a separately reviewed producer proposal binds it.
//
// Exit codes: 0 = W7 pass / W6 compared; 1 = at least one mismatch / W6 fail;
// 2 = unknown (missing, partial, denied, or inconsistent evidence); 64 = usage.
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import console from 'node:console'
import process from 'node:process'
import { parseArgs } from 'node:util'
import { evaluateRun, fixtureSummary, pairSummaries, parseJsonl, renderExpectationTable } from './lib.mjs'

class EvidenceInputError extends Error {
  constructor(reason) { super(reason); this.reason = reason }
}

function readInput(path) {
  try { return readFileSync(path) }
  catch { throw new EvidenceInputError('input_unreadable') }
}

function load(path) {
  const bytes = readInput(path)
  const parsed = parseJsonl(bytes.toString('utf8'))
  return { ...parsed, sha256: createHash('sha256').update(bytes).digest('hex') }
}

function jsonObject(path, what) {
  if (!path) return null
  const bytes = readInput(path)
  let value
  try { value = JSON.parse(bytes.toString('utf8')) }
  catch { throw new EvidenceInputError(`${what}_invalid_json`) }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new EvidenceInputError(`${what}_not_object`)
  return value
}

function run(label, preflightPath, observePath, baseline) {
  const preflight = load(preflightPath)
  const observe = load(observePath)
  return evaluateRun({ preflight, observe, preflightSha256: preflight.sha256, expectedLabel: label, baseline })
}

function exitFor(status) {
  if (status === 'pass' || status === 'compared') return 0
  if (status === 'fail') return 1
  return 2
}

function usage(message) {
  console.error(message)
  console.error('usage: evaluate.mjs table | run | pair | pair-fixture (see file header)')
  process.exit(64)
}

function main() {
  const [command, ...rest] = process.argv.slice(2)
  let values
  try {
    ({ values } = parseArgs({
      args: rest,
      options: {
        label: { type: 'string' },
        preflight: { type: 'string' },
        observe: { type: 'string' },
        baseline: { type: 'string' },
        'medium-preflight': { type: 'string' },
        'medium-observe': { type: 'string' },
        'high-preflight': { type: 'string' },
        'high-observe': { type: 'string' },
        'medium-lab': { type: 'string' },
        'medium-meta': { type: 'string' },
        'high-lab': { type: 'string' },
        'high-meta': { type: 'string' },
        explanations: { type: 'string' },
      },
      strict: true,
    }))
  } catch (error) {
    usage(error.message)
  }
  if (command === 'table') {
    process.stdout.write(renderExpectationTable())
    process.exit(0)
  }
  if (command === 'run') {
    if (!['medium', 'high'].includes(values.label) || !values.preflight || !values.observe) usage('run needs --label, --preflight and --observe')
    const summary = run(values.label, values.preflight, values.observe, jsonObject(values.baseline, 'baseline'))
    console.log(JSON.stringify(summary, null, 2))
    process.exit(exitFor(summary.w7))
  }
  if (command === 'pair') {
    const need = ['medium-preflight', 'medium-observe', 'high-preflight', 'high-observe']
    if (need.some((k) => !values[k])) usage('pair needs --' + need.join(', --'))
    const baseline = jsonObject(values.baseline, 'baseline')
    const medium = run('medium', values['medium-preflight'], values['medium-observe'], baseline)
    const high = run('high', values['high-preflight'], values['high-observe'], baseline)
    const paired = pairSummaries(medium, high, jsonObject(values.explanations, 'explanations') ?? {})
    const side = (s) => ({ w7: s.w7, totals: s.totals, problems: s.problems, provenance: s.provenance })
    console.log(JSON.stringify({ medium: side(medium), high: side(high), w6: paired }, null, 2))
    process.exit(exitFor(paired.status))
  }
  if (command === 'pair-fixture') {
    const need = ['medium-lab', 'medium-meta', 'high-lab', 'high-meta']
    if (need.some((k) => !values[k])) usage('pair-fixture needs --' + need.join(', --'))
    const medium = fixtureSummary({ lab: load(values['medium-lab']), meta: load(values['medium-meta']), expectedLabel: 'medium' })
    const high = fixtureSummary({ lab: load(values['high-lab']), meta: load(values['high-meta']), expectedLabel: 'high' })
    const paired = pairSummaries(medium, high, jsonObject(values.explanations, 'explanations') ?? {})
    console.log(JSON.stringify({ medium: { totals: medium.totals, problems: medium.problems }, high: { totals: high.totals, problems: high.problems }, w6: paired }, null, 2))
    process.exit(exitFor(paired.status))
  }
  usage(`unknown command: ${command ?? '(none)'}`)
}

try { main() }
catch (error) {
  if (!(error instanceof EvidenceInputError)) throw error
  // Do not expose paths, parser excerpts or host exception messages in a
  // shareable diagnostic. A failed input is unknown, not a measured mismatch.
  console.log(JSON.stringify({ status: 'unknown', problems: [error.reason], safeToUnlock: false }))
  process.exitCode = 2
}
