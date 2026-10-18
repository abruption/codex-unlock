// Pure evaluation of W6/W7 observer evidence (#151, #152). No filesystem,
// process, or network access: callers pass record arrays and digests.
// Every missing, partial, denied, inconsistent, out-of-schema, or unproven
// observation is `unknown`; a harness-provided boolean or verdict is never
// trusted. Provenance is reconstructed from the raw preflight observations and
// a validated baseline, and every stage is cross-bound to the next.
// Nothing here authorizes recovery: safeToUnlock stays false and W7 stays
// `unknown` while the coordination-range row is unmeasurable.
import {
  ACL_INHERITANCE, ACL_RIGHTS, ACL_TYPE, DISPOSABLE_DIR, EXPECTATIONS, FORMATS, HARNESS_FILES, INTEGRITY,
  MAX_SAMPLES, ROLES, SCHEMA, STEP_SCHEMAS, knownSteps, normalizeLocalPath, perSampleSteps, sameKeySet,
} from './expectations.mjs'

const ERROR_ACCESS_DENIED = 5

// Rows whose verdicts make up the provenance state. W6 needs all of them to be
// `match`; it does not need W7's unmeasurable coordination range.
export const PROVENANCE_ROWS = Object.freeze([
  'PF-harness', 'PF-token', 'PF-home', 'PF-binary-sha256', 'PF-binary-version', 'PF-manifest',
  'OB-harness', 'OB-token', 'OB-home', 'OB-run',
])

// Complete, contiguous samples: the process re-query precedes all evidence
// collected for that sample. This is an offline contract, not permission to
// run the dormant native producer.
const SAMPLE_STEPS = Object.freeze([
  'process.sample', 'lockdir.identity', 'coordination.identity', 'thread.count',
  'thread.identity', 'openers.rm', 'share.read_rwd', 'share.delete_rwd',
  'range.probe', 'thread.identity_after',
])

// GetFinalPathNameByHandle reports an extended drive path. Only remove that
// exact kernel spelling; UNC/device/relative paths remain unusable.
function identityPath(path) {
  if (typeof path !== 'string') return null
  return normalizeLocalPath(path.startsWith('\\\\?\\') ? path.slice(4) : path)
}

function samplePaths(sample, ctx) {
  if (!ctx.manifest) return null
  const count = ctx.observeByStep.get(`thread.count#${sample}`)?.observed
  if (!Array.isArray(count?.entries) || count.count !== 1) return null
  const dir = `${ctx.manifest.home}\\thread-writer-locks`
  if (count.entries.some((entry) => typeof entry !== 'string' || entry.includes('\\') ||
    normalizeLocalPath(`${dir}\\${entry}`) === null)) return null
  const threads = count.entries.filter((entry) => entry.toLowerCase() !== '.coordination.lock' && entry.toLowerCase().endsWith('.lock'))
  if (threads.length !== 1) return null
  return { dir, guard: `${dir}\\.coordination.lock`, thread: `${dir}\\${threads[0]}` }
}

function sampleIdentityProblem(sample, ctx) {
  const paths = samplePaths(sample, ctx)
  if (!paths) return 'sample_paths_unusable'
  for (const [step, path] of [['lockdir.identity', paths.dir], ['coordination.identity', paths.guard],
    ['thread.identity', paths.thread], ['thread.identity_after', paths.thread]]) {
    const actual = ctx.observeByStep.get(`${step}#${sample}`)?.observed?.finalPath
    if (identityPath(actual) !== normalizeLocalPath(path)) return `${step}_path_differs`
  }
  return null
}

export function parseJsonl(text) {
  const records = []
  const problems = []
  if (typeof text !== 'string' || text.length === 0) return { records, problems: ['empty_file'] }
  if (text.charCodeAt(0) === 0xfeff) problems.push('bom')
  if (!text.endsWith('\n')) problems.push('missing_final_newline')
  const lines = text.split('\n')
  if (lines[lines.length - 1] === '') lines.pop()
  lines.forEach((line, index) => {
    if (line.endsWith('\r')) problems.push(`crlf:${index + 1}`)
    try {
      const value = JSON.parse(line)
      if (value === null || typeof value !== 'object' || Array.isArray(value)) problems.push(`not_object:${index + 1}`)
      else records.push(value)
    } catch {
      problems.push(`invalid_json:${index + 1}`)
    }
  })
  return { records, problems }
}

export function integrityFromSid(sid) {
  if (sid === INTEGRITY.medium) return 'medium'
  if (sid === INTEGRITY.high) return 'high'
  if (typeof sid === 'string' && /^S-1-16-\d+$/.test(sid)) return 'other'
  return null
}

// whoami /groups prints localized names but a constant label SID.
export function sidFromWhoamiLine(line) {
  if (typeof line !== 'string') return null
  const found = line.match(/\bS-1-16-\d+\b/g)
  return found && found.length === 1 ? found[0] : null
}

// Lexical, case-insensitive relation of two absolute local Windows paths:
// 'same', 'inside' (a under b), 'contains' (b under a), 'disjoint', or null
// when either spelling is not accepted (see normalizeLocalPath: UNC, device,
// relative and ambiguous spellings are rejected, never rewritten). Lexical
// only; reparse points are the harness's responsibility and are covered
// separately by the recorded no-follow ancestry.
export function windowsPathRelation(a, b) {
  const x = normalizeLocalPath(a)
  const y = normalizeLocalPath(b)
  if (x === null || y === null) return null
  if (x === y) return 'same'
  const under = (p, d) => p.startsWith(d.endsWith('\\') ? d : d + '\\')
  if (under(x, y)) return 'inside'
  if (under(y, x)) return 'contains'
  return 'disjoint'
}

export function pathComponents(p) {
  const norm = normalizeLocalPath(p)
  if (norm === null) return null
  const parts = norm.split('\\').filter((part) => part.length > 0)
  parts.shift()
  return parts
}

// True when any component of the path is a disposable observer directory.
// Literal component matching, never a wildcard: a bracket or a `*` in a real
// path name must not change the decision.
export function insideDisposableDir(p) {
  const parts = pathComponents(p)
  return parts !== null && parts.some((part) => DISPOSABLE_DIR.test(part))
}

// Verified mirror of observer.ps1's lexical output/input path gate. Every
// relevant input and output path is validated BEFORE it is tested, read,
// hashed or created: it must be an accepted absolute local drive spelling,
// disjoint from the actual/default and environment Codex homes, and (for an
// output) outside any disposable observer directory on any volume, regardless
// of the current %TEMP%. Real homes are compared textually; nothing is opened.
export function pathGateSafe(path, userCodexHome, envCodexHome, { allowDisposable = false } = {}) {
  if (normalizeLocalPath(path) === null) return 'path_spelling'
  if (normalizeLocalPath(userCodexHome) === null) return 'user_home_spelling'
  if (windowsPathRelation(path, userCodexHome) !== 'disjoint') return 'user_home_overlap'
  if (envCodexHome !== null && envCodexHome !== undefined) {
    if (normalizeLocalPath(envCodexHome) === null) return 'env_home_spelling'
    if (windowsPathRelation(path, envCodexHome) !== 'disjoint') return 'env_home_overlap'
  }
  if (!allowDisposable && insideDisposableDir(path)) return 'inside_disposable_dir'
  return null
}

// A disposable temp root is safe to create inside only when it passes the same
// lexical gate (its own components may not already be a disposable directory).
// The PowerShell Test-CandidateTempSafe implements the same rule (unverified on
// this host until the static CI gate runs).
export function tempRootSafeForCreation(tempRoot, userCodexHome, envCodexHome) {
  return pathGateSafe(tempRoot, userCodexHome, envCodexHome) === null
}

// Creation seam: the create callback runs only when the gate returns true, so a
// gate failure provably skips creation. Mirrors Invoke-GuardedCreate.
export function guardedCreate(gate, create) {
  if (gate()) return create()
  return { created: false, reason: 'gate_refused' }
}

// Per-sample seam: the active operations of a sample run only when that
// sample's own gate passes. Mirrors Invoke-GuardedSample; one failing sample
// never carries a previous sample's verdict.
export function guardedSample(gate, operations) {
  const reason = gate()
  if (reason !== null && reason !== undefined) return { ran: false, reason }
  return { ran: true, result: operations() }
}

export function getPath(obj, dotted) {
  let cur = obj
  for (const key of dotted.split('.')) {
    if (cur === null || typeof cur !== 'object' || !Object.hasOwn(cur, key)) return undefined
    cur = cur[key]
  }
  return cur
}

export function hasAccessDenied(value) {
  if (value === null || typeof value !== 'object') return false
  for (const [key, inner] of Object.entries(value)) {
    if ((key === 'win32' || key === 'tokenWin32') && inner === ERROR_ACCESS_DENIED) return true
    if (hasAccessDenied(inner)) return true
  }
  return false
}

function schemaProblem(mode, step, observed) {
  const schema = STEP_SCHEMAS[`${mode}:${step}`]
  if (!schema) return 'no_schema'
  for (const [key, ok] of Object.entries(schema.required ?? {})) {
    if (!Object.hasOwn(observed, key)) return `missing:${key}`
    if (!ok(observed[key])) return `format:${key}`
  }
  for (const [key, ok] of Object.entries(schema.nested ?? {})) {
    const v = getPath(observed, key)
    if (v === undefined) return `missing:${key}`
    if (!ok(v)) return `format:${key}`
  }
  // Internal consistency: a record that contradicts itself is not evidence.
  for (const [name, ok] of Object.entries(schema.invariants ?? {})) {
    let held
    try {
      held = ok(observed) === true
    } catch {
      // A predicate that throws on a malformed record is a failed invariant.
      held = false
    }
    if (!held) return `invariant:${name}`
  }
  return null
}

// Returns null when the record is a usable, in-schema observation; otherwise
// the reason it is not. A record is measured only when ok is true, nothing is
// partial/denied/unknown, and the typed schema and its invariants for the step
// pass. Hypothesis keys are additionally required and format-free beyond the
// schema.
export function unmeasuredReason(record, mode, hypothesis) {
  if (!record) return 'not_collected'
  const o = record.observed
  if (o === null || o === undefined) return 'no_observation'
  if (typeof o !== 'object' || Array.isArray(o)) return 'malformed_observation'
  if (hasAccessDenied(o)) return 'access_denied'
  if (o.ok !== true) return 'native_error'
  if (o.complete === false) return 'partial'
  if (o.state === 'unknown') return 'unknown_state'
  if (Object.hasOwn(o, 'exception')) return 'exception'
  const sp = schemaProblem(mode, record.step, o)
  if (sp) return `schema_${sp}`
  for (const key of Object.keys(hypothesis ?? {})) {
    const value = getPath(o, key)
    if (value === undefined || value === null) return 'field_missing'
  }
  return null
}

export function compareHypothesis(observed, hypothesis) {
  for (const [key, want] of Object.entries(hypothesis)) {
    if (getPath(observed, key) !== want) return 'mismatch'
  }
  return 'match'
}

// Values kept for W6 comparison: the hypothesis paths, plus any `compare`
// paths of the row. 'roles' is the sorted role list of a process array.
function pickValues(observed, hypothesis, compare = []) {
  if (!observed || typeof observed !== 'object') return null
  const keys = [...Object.keys(hypothesis ?? {}), ...compare]
  if (keys.length === 0) return null
  const out = {}
  for (const key of keys) {
    if (key === 'roles') out.roles = Array.isArray(observed.processes) ? observed.processes.map((p) => p?.role ?? 'unlabelled').sort() : null
    else out[key] = getPath(observed, key) ?? null
  }
  return out
}

// The structural, disjointness, ownership and ancestry contract of the
// disposable parent and home, recomputed from raw recorded fields only.
// Returns a list of reasons; an empty list means the contract holds.
export function homeContractProblems(o) {
  const problems = []
  const rel = (a, b) => windowsPathRelation(a, b)
  if (rel(o.home, o.parent) !== 'inside') problems.push('home_not_inside_parent')
  const homeParts = pathComponents(o.home)
  const parentParts = pathComponents(o.parent)
  if (homeParts === null || parentParts === null) problems.push('path_spelling')
  else {
    if (homeParts.length !== parentParts.length + 1 || homeParts[homeParts.length - 1] !== 'home') problems.push('home_not_parent_home_child')
    if (!DISPOSABLE_DIR.test(parentParts[parentParts.length - 1] ?? '')) problems.push('parent_not_disposable_name')
  }
  const user = rel(o.home, o.userCodexHome)
  if (user === null) problems.push('user_home_spelling')
  else if (user !== 'disjoint') problems.push('home_overlaps_user_home')
  if (o.userRelation !== user) problems.push('recorded_user_relation_differs')
  if (o.envCodexHome === null) {
    if (o.envRelation !== null) problems.push('recorded_env_relation_differs')
  } else {
    const env = rel(o.home, o.envCodexHome)
    if (env === null) problems.push('env_home_spelling')
    else if (env !== 'disjoint') problems.push('home_overlaps_env_home')
    if (o.envRelation !== env) problems.push('recorded_env_relation_differs')
  }
  // Ownership and DACL contract of both directories, for the measuring user.
  const sid = o.currentUserSid
  if (o.owner !== sid || o.parentOwner !== sid) problems.push('owner_not_current_user')
  if (o.aceIdentity !== sid || o.parentAceIdentity !== sid) problems.push('ace_not_current_user')
  if (o.daclProtected !== true || o.parentDaclProtected !== true) problems.push('dacl_not_protected')
  if (o.aceCount !== 1 || o.parentAceCount !== 1) problems.push('ace_count_not_one')
  if (o.aceType !== ACL_TYPE || o.parentAceType !== ACL_TYPE) problems.push('ace_not_allow')
  if (o.aceRights !== ACL_RIGHTS || o.parentAceRights !== ACL_RIGHTS) problems.push('ace_rights_differ')
  if (o.aceInheritance !== ACL_INHERITANCE || o.parentAceInheritance !== ACL_INHERITANCE) problems.push('ace_inheritance_differs')
  // No-follow ancestry: every component above the parent must be a plain
  // directory. This does not prove the ancestry could not change afterwards.
  if (!Array.isArray(o.ancestry) || o.ancestry.length === 0) problems.push('ancestry_missing')
  else {
    const parent = normalizeLocalPath(o.parent)
    const components = pathComponents(o.parent)
    const expected = parent === null || components === null ? [] : [parent.slice(0, 3)]
    for (const component of components ?? []) expected.push(`${expected[expected.length - 1].replace(/\\$/, '')}\\${component}`)
    if (o.ancestry.length !== expected.length) problems.push('ancestry_component_count')
    if (o.ancestry.some((entry, index) => normalizeLocalPath(entry?.path) !== expected[index])) problems.push('ancestry_component_order')
    for (const entry of o.ancestry) {
      if (entry === null || typeof entry !== 'object') { problems.push('ancestry_malformed'); break }
      if (!FORMATS.localPath(entry.path) || !FORMATS.fileId(entry.fileId)) { problems.push('ancestry_malformed'); break }
      if (entry.directory !== true || entry.reparse !== false) { problems.push('ancestry_not_plain'); break }
    }
    const last = o.ancestry[o.ancestry.length - 1]
    if (last && windowsPathRelation(last.path, o.parent) !== 'same') problems.push('ancestry_does_not_end_at_parent')
    if (last && last.fileId !== o.parentFileId) problems.push('ancestry_parent_fileid_differs')
  }
  if (!FORMATS.fileId(o.fileId) || !FORMATS.fileId(o.parentFileId)) problems.push('file_ids_unusable')
  return problems
}

// Recomputes PF-home isolation from the recorded fields; it never trusts the
// recorded `isolated` flag. Returns null when a field is missing or malformed
// in a way that makes the recomputation impossible.
export function recomputeIsolation(o) {
  if (!o || typeof o !== 'object') return null
  const required = ['home', 'parent', 'userCodexHome', 'empty', 'entries', 'currentUserSid', 'fileId', 'parentFileId', 'ancestry']
  if (required.some((k) => o[k] === undefined || o[k] === null)) return null
  if (!FORMATS.localPath(o.home) || !FORMATS.localPath(o.parent) || !FORMATS.localPath(o.userCodexHome)) return null
  if (!FORMATS.fileId(o.fileId) || !FORMATS.fileId(o.parentFileId)) return null
  if (o.envCodexHome !== null && o.envCodexHome !== undefined && !FORMATS.localPath(o.envCodexHome)) return null
  const problems = homeContractProblems(o)
  return problems.length === 0 && o.empty === true
}

function sameExpectation(tableHypothesis, recordExpect) {
  if (tableHypothesis === null) return true
  if (!recordExpect || typeof recordExpect !== 'object') return false
  return Object.entries(tableHypothesis).every(([k, v]) => Object.hasOwn(recordExpect, k) && recordExpect[k] === v)
}

export function deepEqualMap(a, b) {
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false
  const ka = Object.keys(a).sort()
  const kb = Object.keys(b).sort()
  return ka.length > 0 && JSON.stringify(ka) === JSON.stringify(kb) && ka.every((k) => a[k] === b[k])
}

// The baseline is the operator-asserted evidence the evaluator compares
// against. Its field formats and its exact harness file-name set are validated
// here; the evaluator cannot prove how the operator established it (see
// README, remaining decision 5), and the harness map is an exact map of the
// checkout's bytes, line endings included.
export function validateBaseline(baseline) {
  if (baseline === null || baseline === undefined) return ['baseline_missing']
  if (typeof baseline !== 'object' || Array.isArray(baseline)) return ['baseline_not_object']
  const problems = []
  if (!FORMATS.commit(baseline.sourceCommit)) problems.push('baseline_source_commit')
  if (!FORMATS.sha256(baseline.binarySha256)) problems.push('baseline_binary_sha256')
  if (!FORMATS.string(baseline.version)) problems.push('baseline_version')
  if (!FORMATS.hashMap(baseline.harness)) problems.push('baseline_harness')
  else if (!sameKeySet(baseline.harness, HARNESS_FILES)) problems.push('baseline_harness_name_set')
  return problems
}

// Derivations recompute a verdict from raw fields, cross-stage bindings and a
// validated baseline. Each returns { verdict, reason, value }. `verdict` is
// 'match', 'mismatch' or 'unknown'. They never read a harness-provided
// boolean. The record has already passed its typed schema when a derivation
// runs.
const DERIVATIONS = {
  harnessBaseline(rec, _s, ctx) {
    const o = rec.observed
    if (o.complete !== true) return unk('incomplete')
    if (!ctx.baseline) return unk('baseline_missing')
    if (ctx.baselineProblems.length > 0) return unk('baseline_invalid')
    if (!deepEqualMap(o.files, ctx.baseline.harness)) return mis('harness_differs_from_baseline')
    return ok(o.files)
  },
  tokenIntegrity(rec, _s, ctx) {
    const o = rec.observed
    if (!ctx.label) return unk('label_unresolved')
    if (o.tokenOpened !== true) return unk('token_not_opened')
    if (o.integritySid !== INTEGRITY[ctx.label]) return mis('integrity_sid_differs_from_label')
    return ok(o.integritySid)
  },
  binarySha256Baseline(rec, _s, ctx) {
    const o = rec.observed
    if (o.sha256 !== o.expected) return mis('binary_hash_differs_from_expected')
    if (!ctx.baseline) return unk('baseline_missing')
    if (ctx.baselineProblems.length > 0) return unk('baseline_invalid')
    if (o.sha256 !== ctx.baseline.binarySha256) return mis('binary_hash_differs_from_baseline')
    return ok(o.sha256)
  },
  homeIsolated(rec, _s, ctx) {
    const token = ctx.preflightByStep.get('token.self')?.observed
    if (!token || !FORMATS.anySid(token.userSid)) return unk('self_token_user_missing')
    if (rec.observed.currentUserSid !== token.userSid) return mis('home_user_differs_from_self_token')
    const again = recomputeIsolation(rec.observed)
    if (again === null) return unk('isolation_fields_unusable')
    if (again !== rec.observed.isolated) return unk('evaluator_disagreement')
    if (!again) return mis(`home_not_isolated:${homeContractProblems(rec.observed).join(',') || 'not_empty'}`)
    return ok(rec.observed.home)
  },
  binaryVersion(rec, _s, ctx) {
    const o = rec.observed
    if (o.exitCode !== 0) return mis('version_exit_nonzero')
    if (o.stdoutFirstLine !== o.expected) return mis('version_differs_from_expected')
    if (!ctx.baseline) return unk('baseline_missing')
    if (ctx.baselineProblems.length > 0) return unk('baseline_invalid')
    if (o.stdoutFirstLine !== ctx.baseline.version) return mis('version_differs_from_baseline')
    return ok(o.stdoutFirstLine)
  },
  // The manifest is not trusted: it is reconstructed field by field from the
  // raw preflight observations, then compared with the validated baseline.
  manifestBaseline(rec, _s, ctx) {
    const o = rec.observed
    if (o.complete !== true) return unk('manifest_incomplete')
    if (ctx.reconstruction.problems.length > 0) return unk(`preflight_unusable:${ctx.reconstruction.problems.join(',')}`)
    const want = ctx.reconstruction.fields
    for (const key of ['home', 'parent', 'binaryPath']) {
      if (windowsPathRelation(o[key], want[key]) !== 'same') return mis(`manifest_${key}_differs_from_preflight`)
    }
    for (const key of ['homeFileId', 'parentFileId', 'binarySha256', 'binarySize', 'version', 'sourceCommit', 'integritySid']) {
      if (o[key] !== want[key]) return mis(`manifest_${key}_differs_from_preflight`)
    }
    if (!deepEqualMap(o.harness, want.harness)) return mis('manifest_harness_differs_from_preflight')
    if (!ctx.label) return unk('label_unresolved')
    if (o.label !== ctx.label || o.integritySid !== INTEGRITY[ctx.label]) return mis('manifest_label_differs_from_measured_integrity')
    if (!ctx.baseline) return unk('baseline_missing')
    if (ctx.baselineProblems.length > 0) return unk('baseline_invalid')
    if (o.sourceCommit !== ctx.baseline.sourceCommit) return mis('manifest_commit_differs_from_baseline')
    if (o.binarySha256 !== ctx.baseline.binarySha256) return mis('manifest_binary_differs_from_baseline')
    if (o.version !== ctx.baseline.version) return mis('manifest_version_differs_from_baseline')
    if (!deepEqualMap(o.harness, ctx.baseline.harness)) return mis('manifest_harness_differs_from_baseline')
    return ok(o.sourceCommit)
  },
  harnessMatchesManifest(rec, _s, ctx) {
    const o = rec.observed
    if (o.complete !== true) return unk('incomplete')
    if (!ctx.manifest) return unk('no_manifest')
    if (o.manifestSha256 !== ctx.preflightSha256) return mis('manifest_reference_differs')
    if (!deepEqualMap(o.files, ctx.manifest.harness)) return mis('observer_harness_differs_from_manifest')
    return ok(o.files)
  },
  tokenMatchesManifest(rec, _s, ctx) {
    const o = rec.observed
    if (!ctx.label) return unk('label_unresolved')
    if (o.tokenOpened !== true) return unk('token_not_opened')
    if (o.integritySid !== INTEGRITY[ctx.label]) return mis('integrity_sid_differs_from_label')
    if (!ctx.manifest) return unk('no_manifest')
    if (o.integritySid !== ctx.manifest.integritySid) return mis('integrity_sid_differs_from_manifest')
    return ok(o.integritySid)
  },
  // Observe binds the home to the manifest by path AND file ID for both the
  // home and its parent, re-checks the structure and disjointness, and
  // re-checks the owner/DACL contract and the no-follow ancestry.
  homeMatchesManifest(rec, _s, ctx) {
    const o = rec.observed
    const token = ctx.observeByStep.get('token.self#')?.observed
    if (!token || !FORMATS.anySid(token.userSid)) return unk('self_token_user_missing')
    if (o.currentUserSid !== token.userSid) return mis('home_user_differs_from_self_token')
    if (!ctx.manifest) return unk('no_manifest')
    for (const [key, manifestKey] of [['home', 'home'], ['parent', 'parent']]) {
      if (windowsPathRelation(o[key], ctx.manifest[manifestKey]) !== 'same') return mis(`${key}_path_differs_from_manifest`)
    }
    if (o.fileId !== ctx.manifest.homeFileId) return mis('home_fileid_differs_from_manifest')
    if (o.parentFileId !== ctx.manifest.parentFileId) return mis('parent_fileid_differs_from_manifest')
    const problems = homeContractProblems(o)
    if (problems.length > 0) return mis(`home_contract:${problems.join(',')}`)
    return ok(o.fileId)
  },
  // The control record is mandatory: it declares the target PID, the observer
  // PID and the sample count, and every process record must bind to it.
  runControl(rec, _s, ctx) {
    const o = rec.observed
    const token = ctx.observeByStep.get('token.self#')?.observed
    if (!token || !FORMATS.posInt(token.pid) || !FORMATS.anySid(token.userSid)) return unk('self_token_identity_missing')
    if (o.observerPid !== token.pid) return mis('observer_pid_differs_from_self_token')
    if (o.observerUserSid !== token.userSid) return mis('observer_user_differs_from_self_token')
    const first = ctx.observeByStep.get('process.identity#')?.observed
    const after = ctx.observeByStep.get('process.identity_after#')?.observed
    for (const [name, p] of [['process.identity', first], ['process.identity_after', after]]) {
      if (!p || typeof p !== 'object') return unk(`${name}_missing`)
      if (!FORMATS.posInt(p.pid)) return unk(`${name}_pid_unusable`)
      if (p.pid !== o.codexPid) return mis(`${name}_pid_differs_from_run`)
      if (p.pid === o.observerPid) return mis(`${name}_is_the_observer`)
    }
    if (!FORMATS.filetime(first.createFiletime) || !FORMATS.filetime(after.createFiletime)) return unk('create_filetime_unusable')
    if (first.createFiletime !== after.createFiletime) return mis('create_filetime_changed')
    if (!ctx.label) return unk('label_unresolved')
    return ok(o.codexPid)
  },
  imageLive(rec, _s, ctx) {
    const o = rec.observed
    if (o.state !== 'live') return mis(`process_state_${o.state}`)
    if (!ctx.run) return unk('no_run_record')
    if (o.pid !== ctx.run.codexPid) return mis('queried_pid_differs_from_run')
    if (o.userSid !== ctx.run.observerUserSid) return mis('target_user_differs_from_observer')
    if (!ctx.manifest) return unk('no_manifest')
    if (windowsPathRelation(o.image, ctx.manifest.binaryPath) !== 'same') return mis('image_differs_from_manifest_binary')
    return ok(o.image)
  },
  // The per-sample re-query: the same live instance, at the same image,
  // integrity and user, immediately before that sample's active operations.
  // A later failure cannot undo operations already performed, so the producer
  // must refuse the sample rather than record and continue.
  sampleProcess(rec, _s, ctx) {
    const o = rec.observed
    if (o.state !== 'live') return mis(`process_state_${o.state}`)
    if (!ctx.run) return unk('no_run_record')
    if (o.pid !== ctx.run.codexPid) return mis('queried_pid_differs_from_run')
    if (o.userSid !== ctx.run.observerUserSid) return mis('target_user_differs_from_observer')
    const first = ctx.observeByStep.get('process.identity#')?.observed
    if (!first || !FORMATS.filetime(first.createFiletime)) return unk('baseline_create_missing')
    if (o.createFiletime !== first.createFiletime) return mis('create_filetime_changed')
    if (o.integritySid !== first.integritySid) return mis('integrity_sid_changed')
    if (!ctx.manifest) return unk('no_manifest')
    if (windowsPathRelation(o.image, ctx.manifest.binaryPath) !== 'same') return mis('image_differs_from_manifest_binary')
    return ok(o.createFiletime)
  },
  codexToken(rec, _s, ctx) {
    const o = rec.observed
    if (!ctx.codexLabel) return unk('codex_label_missing')
    if (o.tokenOpened !== true) return unk('token_not_opened')
    if (o.integritySid !== INTEGRITY[ctx.codexLabel]) return mis('codex_integrity_differs_from_label')
    return ok(o.integritySid)
  },
  processAfterLive(rec, _s, ctx) {
    const o = rec.observed
    if (o.state !== 'live') return mis(`process_state_${o.state}`)
    if (!ctx.run) return unk('no_run_record')
    if (o.pid !== ctx.run.codexPid) return mis('queried_pid_differs_from_run')
    const first = ctx.observeByStep.get('process.identity#')?.observed
    if (!FORMATS.filetime(first?.createFiletime)) return unk('baseline_create_missing')
    if (o.createFiletime !== first.createFiletime) return mis('create_filetime_changed')
    if (o.userSid !== first.userSid) return mis('target_user_changed')
    return ok(o.createFiletime)
  },
  threadStable(rec, sample, ctx) {
    const o = rec.observed
    const before = ctx.observeByStep.get(`thread.identity#${sample}`)?.observed
    if (!before || !FORMATS.fileId(before.fileId)) return unk('baseline_identity_missing')
    if (o.fileId !== before.fileId) return mis('thread_fileid_changed')
    for (const key of ['links', 'deletePending', 'directory', 'reparse']) {
      if (o[key] !== before[key]) return mis(`thread_${key}_changed`)
    }
    return ok(o.fileId)
  },
  // The guarded probe must have run under the expected coordination guard and
  // lock directory, and every identity it verified must match this sample's
  // own identity records, before and after the locks.
  rangeGuardBinding(rec, sample, ctx) {
    const o = rec.observed
    const lockdir = ctx.observeByStep.get(`lockdir.identity#${sample}`)?.observed
    const guard = ctx.observeByStep.get(`coordination.identity#${sample}`)?.observed
    const thread = ctx.observeByStep.get(`thread.identity#${sample}`)?.observed
    for (const [name, r] of [['lockdir', lockdir], ['coordination', guard], ['thread', thread]]) {
      if (!r || !FORMATS.fileId(r.fileId)) return unk(`${name}_identity_missing`)
    }
    const pathProblem = sampleIdentityProblem(sample, ctx)
    if (pathProblem) return unk(pathProblem)
    if (o.dirFileIdBefore !== lockdir.fileId || o.dirFileIdAfter !== lockdir.fileId) return mis('lock_directory_identity_differs')
    if (o.guardFileId !== guard.fileId || o.guardFileIdAfter !== guard.fileId) return mis('guard_identity_differs')
    if (o.threadFileIdBefore !== thread.fileId || o.threadFileIdAfter !== thread.fileId) return mis('thread_identity_differs')
    if (o.guardLinks !== guard.links || o.threadLinks !== thread.links) return mis('link_count_differs')
    if (o.state !== 'probed') return mis(`range_state_${o.state}`)
    return ok(o.guardFileId)
  },
  // Restart Manager roles are recomputed from the control record; a recorded
  // role is never read as fact, and the target PID with a different creation
  // FILETIME is a reused PID, not the launched process.
  openersRm(rec, sample, ctx) {
    const o = rec.observed
    if (o.complete !== true) return unk('rm_incomplete')
    if (!ctx.run) return unk('no_run_record')
    const paths = samplePaths(sample, ctx)
    const pathProblem = sampleIdentityProblem(sample, ctx)
    if (!paths || pathProblem) return unk(pathProblem ?? 'sample_paths_unusable')
    const expected = [paths.thread, paths.guard].map(normalizeLocalPath).sort()
    const actual = o.files.map(normalizeLocalPath).sort()
    if (actual.length !== expected.length || actual.some((path, i) => path !== expected[i])) return unk('rm_target_files_differ')
    const first = ctx.observeByStep.get('process.identity#')?.observed
    if (!FORMATS.filetime(first?.createFiletime)) return unk('baseline_create_missing')
    for (const p of o.processes) {
      if (p.pid === ctx.run.codexPid && p.startFiletime !== first.createFiletime) return mis(`target_pid_reused:${p.pid}`)
      const want = p.pid === ctx.run.codexPid ? 'launched_codex' : p.pid === ctx.run.observerPid ? 'observer' : 'other'
      if (p.role !== want) return mis(`role_recomputed_differs:${p.pid}`)
    }
    return ok(o.count)
  },
}

function ok(value) { return { verdict: 'match', reason: null, value } }
function mis(reason) { return { verdict: 'mismatch', reason, value: null } }
function unk(reason) { return { verdict: 'unknown', reason, value: null } }

function validSampleCount(samples) {
  return Number.isInteger(samples) && samples >= 1 && samples <= MAX_SAMPLES
}

// Validates one observer JSONL file of a single mode. Integrity must be
// identical on every record; a mixed file, an unexpected step, an out-of-range
// or misplaced sample index, or an orchestrator_error record makes the file
// unusable.
export function validateObserverFile(records, mode, problems = [], samples = null) {
  const out = { mode, label: null, sid: null, problems: [...problems] }
  if (records.length === 0) out.problems.push('no_records')
  const allowed = knownSteps(mode)
  const sampled = perSampleSteps(mode)
  const limit = validSampleCount(samples) ? samples : MAX_SAMPLES
  const sids = new Set()
  const labels = new Set()
  const seen = new Set()
  const order = new Map()
  const sampleSeq = new Map()
  records.forEach((r, index) => {
    if (r.schema !== SCHEMA) out.problems.push(`schema:${r.step}`)
    if (r.mode !== mode) out.problems.push(`mode:${r.step}`)
    if (r.safeToUnlock !== false) out.problems.push(`safe_to_unlock:${r.step}`)
    const sample = r.sample ?? null
    if (r.step === 'orchestrator_error') out.problems.push('orchestrator_error')
    else if (!allowed.has(r.step)) out.problems.push(`unexpected_step:${r.step}`)
    else if (sampled.has(r.step)) {
      if (!Number.isInteger(sample) || sample < 1 || sample > limit) out.problems.push(`sample_invalid:${r.step}#${sample}`)
      else {
        const seq = sampleSeq.get(r.step) ?? []
        seq.push(sample)
        sampleSeq.set(r.step, seq)
      }
    } else if (sample !== null) out.problems.push(`sample_unexpected:${r.step}#${sample}`)
    sids.add(r.integrity?.sid ?? null)
    labels.add(r.integrity?.label ?? null)
    const key = `${r.step}#${sample ?? ''}`
    if (seen.has(key)) out.problems.push(`duplicate:${key}`)
    seen.add(key)
    if (!order.has(r.step)) order.set(r.step, index)
    order.set(`last:${r.step}`, index)
  })
  // Per-sample steps must appear once per sample, in increasing sample order.
  if (validSampleCount(samples)) {
    for (const step of sampled) {
      if (!sampleSeq.has(step)) out.problems.push(`missing_sample_step:${step}`)
    }
    for (const [step, seq] of sampleSeq) {
      const wanted = Array.from({ length: samples }, (_, i) => i + 1)
      if (seq.length !== samples || seq.some((v, i) => v !== wanted[i])) out.problems.push(`sample_order:${step}:${seq.join('.')}`)
    }
    const actual = records.filter((r) => sampled.has(r.step)).map((r) => `${r.step}#${r.sample}`)
    const expected = Array.from({ length: samples }, (_, i) => SAMPLE_STEPS.map((step) => `${step}#${i + 1}`)).flat()
    if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) out.problems.push('sample_sequence_invalid')
  }
  // Control and process records bracket the samples.
  if (mode === 'observe' && sampleSeq.size > 0) {
    const firstSampled = Math.min(...[...sampleSeq.keys()].map((step) => order.get(step)))
    const lastSampled = Math.max(...[...sampleSeq.keys()].map((step) => order.get(`last:${step}`)))
    for (const step of ['run', 'process.identity']) {
      const at = order.get(step)
      if (at === undefined) out.problems.push(`missing_step:${step}`)
      else if (at > firstSampled) out.problems.push(`order:${step}_after_samples`)
    }
    const afterAt = order.get('process.identity_after')
    if (afterAt === undefined) out.problems.push('missing_step:process.identity_after')
    else if (afterAt < lastSampled) out.problems.push('order:process.identity_after_before_samples')
  }
  if (sids.size === 1 && labels.size === 1) {
    const [sid] = sids
    const [label] = labels
    if (sid !== null && integrityFromSid(sid) === label && (label === 'medium' || label === 'high')) {
      out.sid = sid
      out.label = label
    } else out.problems.push('integrity_label_sid_mismatch')
  } else if (records.length > 0) out.problems.push('mixed_integrity')
  return out
}

// A preflight file must end in exactly one manifest record, and every other
// required preflight step must be present exactly once as a usable
// observation. A file with both a complete and an incomplete manifest record,
// or with a manifest that is not last, is refused.
export function validateManifestPlacement(records) {
  const problems = []
  const manifests = records.filter((r) => r.step === 'manifest')
  if (manifests.length === 0) problems.push('manifest_absent')
  if (manifests.length > 1) problems.push(`manifest_not_unique:${manifests.length}`)
  if (manifests.length > 0 && records[records.length - 1] !== manifests[manifests.length - 1]) problems.push('manifest_not_last')
  const record = manifests.length === 1 ? manifests[0] : null
  if (record && record.observed?.complete !== true) problems.push('manifest_not_complete')
  for (const exp of EXPECTATIONS) {
    if (exp.mode !== 'preflight' || exp.step === 'manifest' || exp.measurable === false) continue
    const found = records.filter((r) => r.step === exp.step)
    if (found.length !== 1) problems.push(`manifest_requires_one:${exp.step}:${found.length}`)
  }
  return { record, problems }
}

// Rebuilds the manifest's fields from the raw preflight observations. The
// manifest's own values are then compared with this reconstruction, so a
// manifest that disagrees with the run it claims to describe can never pass.
export function reconstructManifest(records, label) {
  const problems = []
  const usable = (step) => {
    const rec = records.find((r) => r.step === step)
    const reason = unmeasuredReason(rec, 'preflight', null)
    if (reason) {
      problems.push(`${step}:${reason}`)
      return null
    }
    return rec.observed
  }
  const harness = usable('harness')
  const token = usable('token.self')
  const binary = usable('binary.sha256')
  const home = usable('home.isolated')
  const version = usable('binary.version')
  if (problems.length > 0) return { fields: null, problems }
  return {
    problems,
    fields: {
      home: home.home, homeFileId: home.fileId, parent: home.parent, parentFileId: home.parentFileId,
      binaryPath: binary.path, binarySha256: binary.sha256, binarySize: binary.size,
      version: version.stdoutFirstLine, sourceCommit: harness.sourceCommit,
      integritySid: token.integritySid, label, harness: harness.files,
    },
  }
}

function rowFor(exp, records, samples, fileUsable, ctx) {
  const row = {
    id: exp.id, mode: exp.mode, step: exp.step, hypothesis: exp.hypothesis ?? null, derive: exp.derive ?? null,
    gates: exp.gates, collected: 'none', measured: 'none', verdict: 'unknown', reasons: [], values: [],
  }
  if (exp.measurable === false) {
    row.reasons.push('not_measurable')
    return row
  }
  if (exp.perSample && !validSampleCount(samples)) {
    row.reasons.push('sample_count_invalid')
    return row
  }
  const indices = exp.perSample ? Array.from({ length: samples }, (_, i) => i + 1) : [null]
  let collected = 0
  let measured = 0
  const verdicts = []
  for (const sample of indices) {
    const tag = sample === null ? '' : `#${sample}`
    const rec = records.find((r) => r.step === exp.step && (r.sample ?? null) === sample)
    if (rec) collected++
    let reason = unmeasuredReason(rec, exp.mode, exp.hypothesis)
    // Drift only applies to raw-comparison rows; derived and recorded rows have
    // no table hypothesis to drift from.
    if (!reason && exp.hypothesis && !sameExpectation(exp.hypothesis, rec.expect)) reason = 'expectation_drift'
    if (reason) {
      row.reasons.push(`${reason}${tag}`)
      verdicts.push('unknown')
      row.values.push(null)
      continue
    }
    measured++
    row.values.push(pickValues(rec.observed, exp.hypothesis, exp.compare))
    if (exp.derive) {
      const d = DERIVATIONS[exp.derive](rec, sample, ctx)
      if (d.verdict !== 'match') row.reasons.push(`${d.reason}${tag}`)
      verdicts.push(d.verdict)
      continue
    }
    if (exp.hypothesis === null) {
      verdicts.push('recorded')
      continue
    }
    verdicts.push(compareHypothesis(rec.observed, exp.hypothesis))
  }
  row.collected = collected === indices.length ? 'all' : collected === 0 ? 'none' : 'partial'
  row.measured = measured === indices.length ? 'all' : measured === 0 ? 'none' : 'partial'
  if (!fileUsable) {
    row.reasons.push('file_unusable')
    row.verdict = 'unknown'
  } else if (verdicts.includes('mismatch')) row.verdict = 'mismatch'
  else if (verdicts.includes('unknown')) row.verdict = 'unknown'
  else row.verdict = exp.hypothesis === null && !exp.derive ? 'recorded' : 'match'
  return row
}

// A file-global problem (structure, labels, provenance inputs) makes the whole
// result `unknown` before any per-row mismatch is reported: the evidence is not
// in a state where a measured contradiction can be attributed. Valid, complete
// evidence with a genuine mismatch still fails.
function gateOf(rows, problems) {
  if (problems.length > 0) return 'unknown'
  if (rows.some((r) => r.verdict === 'mismatch')) return 'fail'
  if (rows.some((r) => r.verdict === 'unknown')) return 'unknown'
  return 'pass'
}

function dependents(w7, label, codexLabel) {
  const state = w7 === 'pass' ? 'evidence_available_decision_pending' : 'blocked_on_W7'
  return {
    W3: { nativeClassification: state, integrity: label, codexIntegrity: codexLabel, note: 'real process classification needs W7 measured evidence at this integrity level' },
    W5: { releaseDecision: state, integrity: label, codexIntegrity: codexLabel, note: 'also requires W4; never authorized by observation' },
  }
}

// The provenance state of one run: every provenance row measured and matching,
// a format-valid baseline, a usable manifest and no file-global problem. W6
// pairing requires it on both sides; it never requires W7's unmeasurable
// coordination range.
function provenanceOf(rows, problems, baselineProblems) {
  const state = { state: 'unvalidated', problems: [], mismatches: [], unknowns: [] }
  for (const p of baselineProblems) state.problems.push(`baseline:${p}`)
  for (const p of problems) state.problems.push(`file:${p}`)
  for (const id of PROVENANCE_ROWS) {
    const row = rows.find((r) => r.id === id)
    if (!row) {
      state.problems.push(`row_absent:${id}`)
      continue
    }
    if (row.verdict === 'mismatch') {
      state.mismatches.push(id)
      state.problems.push(`row_mismatch:${id}`)
    } else if (row.verdict !== 'match') {
      state.unknowns.push(id)
      state.problems.push(`row_${row.verdict}:${id}`)
    }
  }
  if (state.problems.length === 0) state.state = 'validated'
  return state
}

// Evaluates one integrity level: one preflight file plus one observe file.
// preflightSha256 is the digest of the preflight file bytes as read by the
// caller; observe must reference it. `baseline` is the operator-asserted,
// independently established { sourceCommit, binarySha256, version, harness }.
// Without a format-valid baseline, provenance rows stay `unknown` and the gate
// cannot pass.
export function evaluateRun({ preflight, observe, preflightSha256, expectedLabel, baseline = null, expectations = EXPECTATIONS }) {
  const baselineProblems = validateBaseline(baseline)
  const runRec = observe.records.find((r) => r.step === 'run' && (r.sample ?? null) === null)
  const runReason = unmeasuredReason(runRec, 'observe', null)
  const run = runReason ? null : runRec.observed
  const samples = run?.samples
  const pf = validateObserverFile(preflight.records, 'preflight', preflight.problems)
  const ob = validateObserverFile(observe.records, 'observe', observe.problems, samples)
  const problems = [...pf.problems.map((p) => `preflight:${p}`), ...ob.problems.map((p) => `observe:${p}`)]
  if (pf.label !== null && ob.label !== null && (pf.label !== ob.label || pf.sid !== ob.sid)) problems.push('preflight_observe_integrity_differs')
  const label = pf.label !== null && pf.label === ob.label ? pf.label : null
  if (expectedLabel && label !== expectedLabel) problems.push('expected_label_mismatch')
  if (!FORMATS.sha256(preflightSha256)) problems.push('preflight_sha256_invalid')
  for (const p of baselineProblems) problems.push(p)
  if (runReason) problems.push(`run_unusable:${runReason}`)
  if (!validSampleCount(samples)) problems.push('sample_count_invalid')
  const placement = validateManifestPlacement(preflight.records)
  for (const p of placement.problems) problems.push(`preflight:${p}`)
  const reconstruction = reconstructManifest(preflight.records, label)
  const manifestUsable = placement.record !== null && !schemaProblem('preflight', 'manifest', placement.record.observed ?? {})
  const manifest = manifestUsable ? placement.record.observed : null
  if (!manifest) problems.push('manifest_unusable')
  const obHarness = observe.records.find((r) => r.step === 'harness')
  if (!FORMATS.sha256(obHarness?.observed?.manifestSha256) || obHarness?.observed?.manifestSha256 !== preflightSha256) problems.push('manifest_reference_mismatch')
  const codexLabel = ['medium', 'high'].includes(run?.codexLabel) ? run.codexLabel : null
  if (codexLabel === null) problems.push('codex_label_missing')
  const observeByStep = new Map(observe.records.map((r) => [`${r.step}#${r.sample ?? ''}`, r]))
  const preflightByStep = new Map(preflight.records.map((r) => [r.step, r]))
  const ctx = { label, codexLabel, baseline, baselineProblems, manifest, reconstruction, preflightSha256, preflightByStep, observeByStep, run }
  const pfUsable = pf.problems.length === 0
  const obUsable = ob.problems.length === 0 && !problems.includes('preflight_observe_integrity_differs') && !problems.includes('manifest_reference_mismatch')
  const rows = expectations.map((exp) => {
    const recs = exp.mode === 'preflight' ? preflight.records : observe.records
    const row = rowFor(exp, recs, samples, exp.mode === 'preflight' ? pfUsable : obUsable, ctx)
    row.integrity = label
    return row
  })
  const w7 = gateOf(rows, problems)
  return {
    kind: 'observer',
    label,
    sid: label ? pf.sid : null,
    codexLabel,
    variant: label && codexLabel ? (label === codexLabel ? 'same_level' : 'cross_level') : null,
    baselineProvided: Boolean(baseline) && baselineProblems.length === 0,
    harness: manifest?.harness ?? null,
    sourceCommit: manifest?.sourceCommit ?? null,
    binarySha256: manifest?.binarySha256 ?? null,
    version: manifest?.version ?? null,
    homeFileId: manifest?.homeFileId ?? null,
    codexPid: run?.codexPid ?? null,
    problems,
    provenance: provenanceOf(rows, problems, baselineProblems),
    rows,
    totals: tally(rows),
    w7,
    blockers: rows.filter((r) => r.verdict !== 'match' && r.verdict !== 'recorded').map((r) => r.id),
    dependents: dependents(w7, label, codexLabel),
    safeToUnlock: false,
  }
}

function tally(rows) {
  const t = {}
  for (const r of rows) t[r.verdict] = (t[r.verdict] ?? 0) + 1
  return t
}

// The existing experimental/windows-fixture producer records integrity once
// per run and has no terminal manifest binding the fixture-meta record to the
// lab bytes, run, or source. Its logs therefore cannot be promoted to a passing
// W6 gate. This summary recomputes every row from raw fields (never trusting
// lab.verdict) for information, and always carries `fixture_producer_unbound`
// so pairing can never report `compared` from fixture evidence. Changing that
// needs a separately reviewed producer proposal.
const FIXTURE_FIELDS = ['ok', 'state', 'reason', 'win32', 'locked', 'complete', 'count', 'exitCode', 'empty', 'exists', 'bytes']

function fixtureValues(observed) {
  if (!observed || typeof observed !== 'object') return null
  const out = {}
  for (const k of FIXTURE_FIELDS) if (Object.hasOwn(observed, k)) out[k] = observed[k]
  if (Array.isArray(observed.processes)) out.roles = observed.processes.map((p) => p?.role ?? 'unlabelled').sort()
  return out
}

// A fixture row is measured only when its observation is a usable object that
// is not denied/partial/error/unknown. lab.verdict is never trusted.
function fixtureRowReasons(r, ids, usable) {
  const reasons = []
  const o = r.observed
  if (r.safeToUnlock !== false) reasons.push('safe_to_unlock')
  if (ids.get(`${r.scenario}/${r.step}`) > 1) reasons.push('duplicate')
  if (o === null || o === undefined) reasons.push('no_observation')
  else if (typeof o !== 'object' || Array.isArray(o)) reasons.push('malformed_observation')
  else {
    if (hasAccessDenied(o)) reasons.push('access_denied')
    if (o.ok === false) reasons.push('native_error')
    if (o.complete === false) reasons.push('partial')
    if (o.state === 'unknown') reasons.push('unknown_state')
    if (Object.hasOwn(o, 'exception')) reasons.push('exception')
  }
  if (!usable) reasons.push('file_unusable')
  if (!['match', 'mismatch', 'recorded'].includes(r.verdict)) reasons.push(`harness_${r.verdict ?? 'no_verdict'}`)
  return reasons
}

export function fixtureSummary({ lab, meta, expectedLabel }) {
  const problems = [...lab.problems.map((p) => `lab:${p}`), ...meta.problems.map((p) => `meta:${p}`)]
  // The fixture producer is not bound to its own bytes/run/source, so its
  // evidence can never be a successful gate. This is unconditional.
  problems.push('fixture_producer_unbound')
  const mv = validateObserverFile(meta.records, 'fixture-meta', [])
  // fixture-meta uses a mode not covered by knownSteps, so its own step checks
  // are advisory; keep only the integrity and harness facts.
  const host = lab.records.filter((r) => r.scenario === 'environment' && r.step === 'host')
  let labSid = null
  if (host.length !== 1) problems.push('lab:host_record_count')
  else labSid = sidFromWhoamiLine(host[0].observed?.integrity)
  if (labSid === null) problems.push('lab:integrity_unparsed')
  const metaSid = mv.sid ?? (meta.records.find((r) => r.step === 'token.self')?.integrity?.sid ?? null)
  if (labSid !== null && metaSid !== null && labSid !== metaSid) problems.push('lab_meta_integrity_differs')
  const label = labSid !== null && labSid === metaSid ? integrityFromSid(labSid) : null
  if (label !== 'medium' && label !== 'high') problems.push('fixture_integrity_unresolved')
  if (expectedLabel && label !== expectedLabel) problems.push('expected_label_mismatch')
  const metaHarness = meta.records.find((r) => r.step === 'fixture.harness')?.observed
  if (!metaHarness || metaHarness.complete !== true || !FORMATS.hashMap(metaHarness.files)) problems.push('meta:fixture_harness_incomplete')
  // A closed expected set: the fixture must at least carry the host record and
  // its canonical E1/E3/identity anchors. Anything less is out of scope.
  const present = new Set(lab.records.map((r) => `${r.scenario}/${r.step}`))
  const expectedSet = ['environment/host', 'E1/free', 'E3/holder', 'identity/live']
  const missingAnchors = expectedSet.filter((id) => !present.has(id))
  if (missingAnchors.length > 0) problems.push(`lab:missing_anchors:${missingAnchors.join(',')}`)
  const usable = false // never usable as a successful gate
  const ids = new Map()
  for (const r of lab.records) {
    const id = `${r.scenario}/${r.step}`
    ids.set(id, (ids.get(id) ?? 0) + 1)
  }
  const rows = lab.records.map((r) => {
    const reasons = fixtureRowReasons(r, ids, usable)
    return {
      id: `${r.scenario}/${r.step}`, gates: ['W6'], integrity: label,
      integritySource: 'lab_host_record+fixture_meta(unbound)',
      harnessVerdict: r.verdict ?? null, reasons,
      verdict: 'unknown', values: [fixtureValues(r.observed)],
    }
  })
  return {
    kind: 'fixture',
    label,
    sid: label ? metaSid : null,
    bound: false,
    baselineProvided: false,
    harness: metaHarness?.files ?? null,
    sourceCommit: metaHarness?.sourceCommit ?? null,
    binarySha256: null,
    version: null,
    problems,
    // Fixture evidence is never a validated provenance state.
    provenance: { state: 'unvalidated', problems: ['fixture_producer_unbound'], mismatches: [], unknowns: [] },
    rows,
    totals: tally(rows),
    safeToUnlock: false,
  }
}

// W6 pairing. Each level stays a separate result. Comparison completion is kept
// separate from expectation satisfaction and from CLI success: a mismatch at
// either level (in a compared row or in the provenance it rests on) is a failed
// hypothesis that no explanation can erase, and any unknown row or unvalidated
// provenance keeps the pair unresolved. Nothing is carried across levels.
export function pairSummaries(medium, high, explanations = {}) {
  const problems = []
  if (medium.label !== 'medium') problems.push('medium_label')
  if (high.label !== 'high') problems.push('high_label')
  if (medium.kind !== high.kind) problems.push('kind_differs')
  if (medium.problems.length > 0) problems.push('medium_problems')
  if (high.problems.length > 0) problems.push('high_problems')
  if (!deepEqualMap(medium.harness, high.harness)) problems.push('harness_differs')
  if (!sameKeySet(medium.harness, HARNESS_FILES)) problems.push('harness_name_set')
  if (!FORMATS.commit(medium.sourceCommit) || medium.sourceCommit !== high.sourceCommit) problems.push('source_commit_differs')
  if (medium.kind === 'observer') {
    if (!FORMATS.sha256(medium.binarySha256) || medium.binarySha256 !== high.binarySha256) problems.push('binary_differs')
    if (!FORMATS.string(medium.version) || medium.version !== high.version) problems.push('version_differs')
    if (!medium.baselineProvided || !high.baselineProvided) problems.push('baseline_missing')
    // Provenance must be validated on BOTH sides before any comparison is
    // reported; W6 does not require W7's unmeasurable coordination range, but
    // it does require every provenance prerequisite of it.
    if (medium.provenance?.state !== 'validated') problems.push('medium_provenance_unvalidated')
    if (high.provenance?.state !== 'validated') problems.push('high_provenance_unvalidated')
    // A cross-level run (observer and Codex at different levels) is reported on
    // its own and never paired with a same-level run.
    if (medium.variant !== 'same_level' || high.variant !== 'same_level') problems.push('cross_level_run_not_pairable')
  }
  if (medium.kind === 'fixture' || high.kind === 'fixture') problems.push('fixture_evidence_not_pairable')
  const provenanceFailures = [
    ...(medium.provenance?.mismatches ?? []).map((id) => `medium:${id}`),
    ...(high.provenance?.mismatches ?? []).map((id) => `high:${id}`),
  ]
  const w6Rows = (s) => new Map(s.rows.filter((r) => r.gates.includes('W6')).map((r) => [r.id, r]))
  const m = w6Rows(medium)
  const h = w6Rows(high)
  const ids = [...new Set([...m.keys(), ...h.keys()])].sort()
  const rows = []
  const differences = []
  const failedRows = []
  for (const id of ids) {
    const a = m.get(id)
    const b = h.get(id)
    const entry = {
      id,
      medium: a ? { verdict: a.verdict, values: a.values, reasons: a.reasons } : { verdict: 'unknown', reasons: ['not_collected'] },
      high: b ? { verdict: b.verdict, values: b.values, reasons: b.reasons } : { verdict: 'unknown', reasons: ['not_collected'] },
    }
    if (entry.medium.verdict === 'mismatch' || entry.high.verdict === 'mismatch') failedRows.push(id)
    const differs = entry.medium.verdict !== entry.high.verdict || JSON.stringify(entry.medium.values ?? null) !== JSON.stringify(entry.high.values ?? null)
    if (differs) {
      const text = typeof explanations[id] === 'string' && explanations[id].trim().length > 0 ? explanations[id].trim() : null
      entry.explanation = text
      differences.push(id)
    }
    rows.push(entry)
  }
  // Explanations apply only to differences; they never erase a failed
  // hypothesis (a mismatch at either level).
  const unexplained = rows.filter((r) => differences.includes(r.id) && !failedRows.includes(r.id) && r.explanation === null).map((r) => r.id)
  const unknownRows = rows.filter((r) => r.medium.verdict === 'unknown' || r.high.verdict === 'unknown').map((r) => r.id)
  let status = 'compared'
  if (failedRows.length > 0 || provenanceFailures.length > 0) status = 'fail'
  else if (problems.length > 0 || unexplained.length > 0 || unknownRows.length > 0) status = 'unknown'
  return {
    kind: medium.kind === high.kind ? medium.kind : null,
    status,
    problems,
    provenanceFailures,
    differences,
    unexplained,
    unknownRows,
    failedRows,
    rows,
    note: 'comparison completion is separate from expectation satisfaction; a mismatch at either level, in a compared row or in its provenance, fails regardless of explanation, and no result is carried across levels',
    safeToUnlock: false,
  }
}

function cell(v) {
  return String(v).replace(/\|/g, '\\|')
}

export function renderExpectationTable(expectations = EXPECTATIONS) {
  const lines = [
    '| ID | Mode | Step | Per sample | Check | Gates |',
    '| --- | --- | --- | --- | --- | --- |',
  ]
  for (const e of expectations) {
    const check = e.measurable === false ? 'not measurable (always unknown)'
      : e.derive ? `derived: \`${e.derive}\``
        : e.hypothesis === null ? 'recorded only (typed schema)'
          : Object.entries(e.hypothesis).map(([k, v]) => `\`${k}=${JSON.stringify(v)}\``).join(', ')
    lines.push(`| ${cell(e.id)} | ${e.mode} | \`${cell(e.step)}\` | ${e.perSample ? 'yes' : 'no'} | ${cell(check)} | ${e.gates.join(', ')} |`)
  }
  return lines.join('\n') + '\n'
}

export { ROLES }
