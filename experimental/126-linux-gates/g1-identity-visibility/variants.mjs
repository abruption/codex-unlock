// G1 fixture variants and source-derived predictions (#126 research).
//
// Every variant is SYNTHETIC. None is Codex, and no result here says anything
// about a deployed native Codex binary's argv, image or dumpability.
//
// The variants separate the two causes that failed the 2026-10-16 F2
// positive control on the Linux test host:
// (a) the product's executable/argv identity checks, and
// (b) an lsof stderr warning about incomplete visibility.
// Cause (a) is varied by the fixture's kernel argv. Cause (b) is a property
// of the host, measured in every inspection by a control lsof call on an
// unopened file (`lsof_control` stage). Only the narrow mount-visibility
// warning format counts as cause (b) (expectations.mjs `classifyLsofError`);
// a missing tool, a timeout or any other text is infrastructure, not (b).
// Nothing suppresses the warning and nothing changes the product allowlist
// or policy.
//
// Product conditions, read from #137 `b483cd5` (isolated `git archive` copy):
// - process.ts `codexArgumentOffset`: argv[0] basename `codex` or
//   `codex-<name>` (offset 1), or argv[0] basename `node`/`nodejs` with argv[1]
//   basename `codex` (offset 2). Anything else is `unsupported executable argv`.
// - `reconcileArguments`: `ps -o args=` must equal the space-joined kernel argv,
//   then `classifyCodexMode` must accept every token after the offset
//   (interactive mode allows one positional operand; unknown options refuse).
// - `isCodex`: lsof `c`, ps `comm` basename `codex`/`codex-*`, or the verified
//   argument text matching `(^|/)codex(\s|$)`. Arguments are null after an
//   argv error, so the last test cannot rescue a refused argv.
// - `inspectProcess` on Linux: start ticks and the command fingerprint
//   (`/proc/PID/exe` readlink + cmdline) must be read twice and agree, else
//   `linux_process_instance_unverified` (exe readlink needs ptrace access).
// - `findLockOpeners`: ANY lsof stderr becomes `error`, even with exit 0.
// - `inspectThread`: guarded participation is attempted only when the
//   opener lookup has no error and exactly one process; otherwise the probe
//   keeps `held` without participation, and `evaluateSafety` adds
//   `linux_participation_unproven`, `lock_opener_lookup_failed`, and
//   `classification_unknown` (classify requires no opener error).
// - `lockFilesOpenedByProcess`: any lsof stderr is `owner_lock_file_lookup_failed`.

export const PINNED_SOURCE_COMMIT = 'b483cd587c62329243366e64aaaac477edd36adc'

export function assertPinnedBuildSource(source) {
  if (source?.commit !== PINNED_SOURCE_COMMIT) throw new Error(`G1 build source must be ${PINNED_SOURCE_COMMIT}`)
}

// Predictions describe the unpatched pinned source. A matching source commit
// alone does not authorize a build whose manifest records an applied patch.
export function assertPinnedUnpatchedBuild(verified) {
  if (verified?.ok !== true) throw new Error('G1 build must be verified')
  assertPinnedBuildSource(verified.source)
  const patch = verified.patch
  if (patch === null || typeof patch !== 'object' || Array.isArray(patch) ||
    !Object.hasOwn(patch, 'applied') || patch.applied !== false) {
    throw new Error('G1 build must explicitly record an unpatched build (patch.applied === false)')
  }
}

export const VARIANTS = Object.freeze({
  // The 2026-10-16 fixture: `#!/usr/bin/env python3` script named codex.
  // env execs python3 as argv[0], so the kernel argv is [python3, <path>].
  script: { dumpables: [1, 0], argvClean: false, label: 'python script named codex (as measured 2026-10-16)' },
  // Same Python file, started with argv[0] = 'codex' (spawn argv0). Image is
  // python3. Shows that the product's identity check is argv-shaped: it does
  // not verify the executable image.
  argv0: { dumpables: [1, 0], argvClean: true, label: 'python image with argv[0]=codex (argv-only identity)' },
  // Synthetic C program compiled on the run host and named codex. No args.
  native: { dumpables: [1, 0], argvClean: true, label: 'synthetic native C binary named codex' },
  // Node shebang fixture started as <node> <dir>/codex; dumpability inherited.
  node: { dumpables: [1], argvClean: true, label: 'synthetic node fixture named codex (dumpable inferred)' },
})

export const VARIANT_ORDER = ['script', 'argv0', 'native', 'node']

// Kernel argv each variant is expected to have, for a local check against the
// product's pure `reconcileArguments` (argv-check.mjs). Paths are examples.
export function expectedArgv(variant, { scriptPath, nativePath, nodeExec, nodeFixture }) {
  if (variant === 'script') return ['python3', scriptPath]
  if (variant === 'argv0') return ['codex', scriptPath]
  if (variant === 'native') return [nativePath]
  if (variant === 'node') return [nodeExec, nodeFixture]
  throw new Error(`unknown variant ${variant}`)
}

export const PRODUCT_ARGV_ERROR = 'arguments_unverified:unsupported executable argv'

// Strict variant selection: nonempty, known, unique. Order is canonical.
export function parseVariantSelection(text) {
  if (text === undefined) return [...VARIANT_ORDER]
  if (typeof text !== 'string' || text.trim() === '') throw new Error('G1_VARIANTS is empty')
  const names = text.split(',')
  for (const name of names) if (!Object.hasOwn(VARIANTS, name)) throw new Error(`G1_VARIANTS has an unknown variant: ${name || '(empty)'}`)
  if (new Set(names).size !== names.length) throw new Error('G1_VARIANTS has a duplicate variant')
  return VARIANT_ORDER.filter((v) => names.includes(v))
}

export const HOST_CLASSES = ['clean', 'mount_warning']

// SOURCE PREDICTION for one run, never a measurement. `host` is the measured
// host class: 'clean' (the control lsof wrote no stderr) or 'mount_warning'
// (it wrote only the narrow mount-visibility warning). An unclassified host
// has no prediction. Causes are sorted sets. `confidence: 'source_only'`
// marks rows whose source reading was not checked by any execution.
export function predict(variant, dumpable, host) {
  const v = VARIANTS[variant]
  if (!v) throw new Error(`unknown variant ${variant}`)
  if (!HOST_CLASSES.includes(host)) throw new Error(`no prediction for host class ${host}`)
  const lsof = host === 'mount_warning' ? ['lsof_mount_warning'] : []
  const argv = v.argvClean ? [] : ['argv_identity']
  const out = {}
  const set = (id, status, causes = [], extra = {}) => { out[id] = { basis: 'source_prediction', status, causes: [...new Set(causes)].sort(), ...extra } }
  // Independent guarded probe of the held lock, with no attribution.
  set('H0_held_observed', 'pass')
  if (dumpable === 1) {
    set('V1_owner_listed', 'pass')
    set('V2_opener_clean', lsof.length ? 'fail' : 'pass', lsof)
    set('I1_identity_direct', argv.length ? 'fail' : 'pass', argv)
    set('I2_is_codex', v.argvClean ? 'pass' : 'fail', argv)
    set('E2_prepare_candidate', 'pass')
    set('E3_guarded_participation', 'pass')
    // Guarded participation is skipped by inspectThread on any opener error.
    set('E4_inspection_participation', lsof.length ? 'blocked' : 'pass', lsof)
    const eligibilityCauses = [...lsof, ...argv, ...(lsof.length ? ['owner_lockset_unavailable'] : [])]
    set('E5_eligible', eligibilityCauses.length ? 'fail' : 'pass', eligibilityCauses)
  } else {
    // Source-derived, unexecuted: lsof cannot read the fd directory of a
    // non-dumpable process, so a path-filtered lsof omits it.
    set('V1_owner_listed', 'fail', ['owner_hidden'], { confidence: 'source_only' })
    set('V2_opener_clean', lsof.length ? 'fail' : 'pass', lsof)
    set('I1_identity_direct', 'fail', [...argv, 'instance_unverified'])
    set('R1_prepare_permission_denied', 'pass')
    set('R2_refused_with_participation_blocker', 'pass')
    // Refusal is attributed to denial only when the owner was listed without
    // an opener error; otherwise the refusal comes from visibility.
    set('R3_refusal_attributed_to_denial', 'blocked', ['owner_hidden', ...lsof], { confidence: 'source_only' })
  }
  return out
}
