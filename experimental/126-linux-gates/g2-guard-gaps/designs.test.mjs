// Deterministic counterexamples for the G2 gap models. Pure functions only;
// these run on every platform. They test the models and model schedules, not
// the kernel and not any Codex runtime behaviour.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  decideB483, decideG4, finalBoundary, guardWaits, hiddenTransferSchedule, inGuardReads, parseProcLocks, participationPlan,
  soleControlB483, soleControlDecision,
} from './designs.mjs'

const target = { major: 0xfdn, minor: 0x1n, inode: 5678n }
const row = { ...target }
const locks = (lines) => lines.join('\n') + '\n'
const holderLine = (pid) => `1: FLOCK  ADVISORY  WRITE ${pid} fd:01:5678 0 EOF`
const sample = (extra = {}) => ({ descriptors: ['0', '1', '2', '7'], readlink: '/h/thread-writer-locks/x.lock', startTicks: '900', ...extra })
const evidence = (over = {}) => ({
  candidatePid: 42, candidateFd: '7', candidates: ['7'], target,
  pre: sample({ fdinfoRows: [row] }),
  guard: sample({ probe: 'held', pidNamespaceSame: true, mountNamespaceSame: true,
    procLocks: locks(['3: POSIX  ADVISORY  WRITE 11 08:02:131 0 EOF', holderLine(42), '4: FLOCK  ADVISORY  WRITE 99 fd:01:9999 0 EOF']) }),
  post: sample({ fdinfoRows: [row], commandUnchanged: true }),
  ...over,
})
const UNPROVEN = { decision: 'consistent_unproven', participationProven: false, soleControl: false,
  gaps: ['sampled_description_not_bound_inside_guard', 'acquirer_pid_has_no_instance_binding'], waiters: 0 }

test('gap 1: an FD reused by epoll makes b483cd5 and F4 wait on show_fdinfo inside the guard; G4 does not read fdinfo there', () => {
  const schedule = { fdReusedBy: 'epoll' }
  for (const design of ['b483cd5', 'f4']) {
    const w = guardWaits(design, schedule)
    assert.ok(w.unboundedTargetWaits.some((x) => x.waitClass === 'target_file_show_fdinfo' && x.on === 'epoll.show_fdinfo'), design)
  }
  assert.ok(guardWaits('b483cd5').unboundedTargetWaits.some((x) => x.waitClass === 'target_task_mm'))
  assert.equal(guardWaits('f4').unboundedTargetWaits.length, 0)
  const g4 = guardWaits('g4', schedule)
  assert.deepEqual(g4.unboundedTargetWaits, [])
  assert.equal(inGuardReads('g4').some((r) => /fdinfo|cmdline|exe|stat fd/.test(r.read)), false)
  assert.equal(g4.lockFsParity, true)
  assert.ok(inGuardReads('g4').some((r) => r.waitClass === 'global_file_rwsem'))
})

test('/proc/locks parser: strict on the target inode, locate-only elsewhere, overflow and unsafe PIDs refused', () => {
  assert.deepEqual(parseProcLocks(locks([holderLine(42), '1: -> FLOCK  ADVISORY  WRITE 43 fd:01:5678 0 EOF']), target),
    [{ blocked: false, access: 'WRITE', pid: 42 }, { blocked: true, access: 'WRITE', pid: 43 }])
  assert.deepEqual(parseProcLocks(locks(['2: LEASE  ACTIVE    READ 5 00:2e:12 0 EOF', '3: OFDLCK ADVISORY  READ -1 fd:01:77 0 EOF']), target), [])
  assert.throws(() => parseProcLocks(locks(['2: POSIX  ADVISORY  WRITE 42 fd:01:5678 0 EOF']), target), /target_row_unsupported/)
  assert.throws(() => parseProcLocks(holderLine(42), target), /truncated/)
  assert.throws(() => parseProcLocks(locks(['garbage']), target), /line_unsupported/)
  assert.throws(() => parseProcLocks(locks(['1: FLOCK  ADVISORY  WRITE 99999999999999999999 fd:01:5678 0 EOF']), target), /pid_unsafe/)
  assert.throws(() => parseProcLocks(locks(['1: FLOCK  ADVISORY  WRITE 42 1000:01:5678 0 EOF']), target), /field_overflow/)
  assert.throws(() => parseProcLocks(locks(['1: FLOCK  ADVISORY  WRITE 42 fd:100000:5678 0 EOF']), target), /field_overflow/)
  assert.throws(() => parseProcLocks(locks(['1: FLOCK  ADVISORY  WRITE 42 fd:01:18446744073709551616 0 EOF']), target), /field_overflow/)
  assert.throws(() => parseProcLocks(locks([`1: FLOCK  ADVISORY  WRITE 42 fd:01:${'9'.repeat(21)} 0 EOF`]), target), /line_unsupported/)
  assert.deepEqual(parseProcLocks('', target), [])
})

test('G4 at best reports consistent_unproven; it never claims participation', () => {
  assert.deepEqual(decideG4(evidence()), UNPROVEN)
})

test('counterexample (model schedule): hidden transfer satisfies every G4 check while the sampled description was unlocked in the guard', () => {
  const schedule = hiddenTransferSchedule({ target })
  assert.equal(schedule.truth.sampledDescriptionParticipatedInGuard, false)
  const decision = decideG4(schedule.evidence)
  // Every check passes, so G4 cannot tell this apart from real participation.
  assert.equal(decision.decision, 'consistent_unproven')
  assert.equal(decision.participationProven, false)
  assert.ok(decision.gaps.includes('sampled_description_not_bound_inside_guard'))
  assert.notEqual(decision.decision, 'participation')
})

test('model schedule: another acquirer during the guard is refused (necessary check only)', () => {
  const e = evidence({ guard: { ...evidence().guard, procLocks: locks([holderLine(77)]) } })
  assert.deepEqual(decideG4(e), { decision: 'refuse', reason: 'acquirer_pid_mismatch' })
})

test('model schedule: inherited description passes the b483cd5 shape, G4 refuses', () => {
  const inherited = evidence({ candidatePid: 50, guard: { ...evidence().guard, fdinfoRows: [row], procLocks: locks([holderLine(42)]) } })
  assert.equal(decideB483(inherited).decision, 'participation')
  assert.deepEqual(decideG4(inherited), { decision: 'refuse', reason: 'acquirer_pid_mismatch' })
  const omitted = evidence({ candidatePid: 50, guard: { ...evidence().guard, procLocks: locks([]) } })
  assert.deepEqual(decideG4(omitted), { decision: 'refuse', reason: 'proc_locks_no_granted_row' })
})

test('pure repro: deleting descriptors, readlink and startTicks from all samples refuses instead of matching undefined', () => {
  const strip = ({ descriptors: _d, readlink: _r, startTicks: _t, ...rest }) => rest
  const e = evidence()
  const stripped = { ...e, pre: strip(e.pre), guard: strip(e.guard), post: strip(e.post) }
  assert.deepEqual(decideG4(stripped), { decision: 'refuse', reason: 'evidence_malformed:pre.descriptors' })
})

test('G4 rejects malformed and missing fields without throwing', () => {
  const g = evidence().guard
  const cases = [
    [null, 'evidence'], [{ ...evidence(), candidatePid: 0 }, 'candidatePid'], [{ ...evidence(), candidatePid: 2 ** 53 }, 'candidatePid'],
    [{ ...evidence(), candidatePid: '42' }, 'candidatePid'], [{ ...evidence(), candidateFd: 7 }, 'candidateFd'],
    [{ ...evidence(), target: { major: 253, minor: 1, inode: 5678 } }, 'target'], [{ ...evidence(), target: { ...target, inode: 0n } }, 'target'],
    [{ ...evidence(), candidates: [7] }, 'candidates'], [{ ...evidence(), guard: undefined }, 'guard'],
    [{ ...evidence(), pre: sample({ descriptors: [], fdinfoRows: [row] }) }, 'pre.descriptors'],
    [{ ...evidence(), pre: sample({ descriptors: ['7', '7'], fdinfoRows: [row] }) }, 'pre.descriptors'],
    [{ ...evidence(), post: { ...evidence().post, descriptors: ['0', '1'] } }, 'post.descriptors_without_candidate'],
    [{ ...evidence(), guard: { ...g, readlink: '' } }, 'guard.readlink'], [{ ...evidence(), guard: { ...g, readlink: '/x (deleted)' } }, 'guard.readlink'],
    [{ ...evidence(), guard: { ...g, startTicks: 900 } }, 'guard.startTicks'],
    [{ ...evidence(), pre: sample({ fdinfoRows: [{ major: 253, minor: 1, inode: 5678 }] }) }, 'pre.fdinfoRows'],
    [{ ...evidence(), guard: { ...g, probe: undefined } }, 'guard.probe'], [{ ...evidence(), guard: { ...g, pidNamespaceSame: 1 } }, 'guard.namespaces'],
    [{ ...evidence(), guard: { ...g, procLocks: 5 } }, 'guard.procLocks'], [{ ...evidence(), post: { ...evidence().post, commandUnchanged: undefined } }, 'post.commandUnchanged'],
  ]
  for (const [input, field] of cases) {
    assert.deepEqual(decideG4(input), { decision: 'refuse', reason: `evidence_malformed:${field}` }, field)
  }
})

test('G4 refusals: identity drift, namespaces, ambiguity, limits, read lock, command change', () => {
  const g = evidence().guard
  assert.equal(decideG4(evidence({ candidates: ['7', '9'] })).reason, 'candidate_descriptor_not_unique')
  assert.equal(decideG4(evidence({ candidates: ['9'] })).reason, 'candidate_descriptor_not_unique')
  assert.equal(decideG4(evidence({ guard: { ...g, pidNamespaceSame: false } })).reason, 'namespace_mismatch')
  assert.equal(decideG4(evidence({ post: { ...evidence().post, startTicks: '901' } })).reason, 'identity_changed:startTicks')
  assert.equal(decideG4(evidence({ guard: { ...g, readlink: '/other' } })).reason, 'identity_changed:readlink')
  assert.equal(decideG4(evidence({ guard: { ...g, probe: 'unknown' } })).reason, 'probe_unknown')
  assert.equal(decideG4(evidence({ guard: { ...g, procLocks: null } })).reason, 'proc_locks_unavailable')
  assert.equal(decideG4(evidence({ guard: { ...g, procLocks: 'x'.repeat(65537) } })).reason, 'proc_locks_over_limit')
  assert.equal(decideG4(evidence({ guard: { ...g, procLocks: locks([holderLine(42), holderLine(42)]) } })).reason, 'proc_locks_rows_ambiguous')
  assert.equal(decideG4(evidence({ guard: { ...g, procLocks: locks(['1: FLOCK  ADVISORY  READ 42 fd:01:5678 0 EOF']) } })).reason, 'proc_locks_rows_ambiguous')
  assert.equal(decideG4(evidence({ guard: { ...g, procLocks: locks([holderLine(0)]) } })).reason, 'acquirer_not_visible')
  assert.equal(decideG4(evidence({ guard: { ...g, procLocks: locks(['1: FLOCK  ADVISORY  WRITE 99999999999999999999 fd:01:5678 0 EOF']) } })).reason, 'proc_locks_pid_unsafe')
  assert.equal(decideG4(evidence({ pre: sample({ fdinfoRows: [] }) })).reason, 'fdinfo_row_absent_pre')
  assert.equal(decideG4(evidence({ post: { ...evidence().post, fdinfoRows: [{ ...row, inode: 1n }] } })).reason, 'fdinfo_row_mismatch_post')
  assert.equal(decideG4(evidence({ post: { ...evidence().post, commandUnchanged: false } })).reason, 'command_changed_after_guard')
})

test('gap 2: fs-gate refuses a non-allowlisted lock file system before the participation guard; main probe is unchanged', () => {
  const nfs = 0x6969n
  const before = participationPlan('b483cd5', nfs)
  assert.equal(before.participationGuardTaken, true)
  assert.equal(before.refusedInGuard, true)
  assert.ok(before.inGuardLockFsOps.includes('statfs'))
  const gated = participationPlan('fs-gate', nfs)
  assert.equal(gated.participationGuardTaken, false)
  assert.equal(gated.refusedBeforeGuard, true)
  assert.deepEqual(gated.mainProbe, { guarded: true, touchesLockFs: true })
  assert.equal(participationPlan('refuse-before-any-guard', nfs).mainProbe.guarded, false)
  assert.deepEqual(participationPlan('fs-gate', 0xef53n).inGuardLockFsOps, ['stat', 'stat'])
})

test('gap 3: a passing soft check never yields a bound; disordered or invalid inputs refuse', () => {
  const t = { guardObservedAt: 0, guardReleasedAt: 1, probeReturnedAt: 1.2, confirmEndedAt: 5, checkAt: 6, killAt: 10000 }
  const r = finalBoundary(t)
  assert.equal(r.allowed, true)
  assert.equal(r.hardBound, false)
  assert.equal(r.evidenceAgeAtSignalMs, 10000)
  // F4's check covers confirm only: a stale observation with a fast confirm passes it.
  const stale = { ...t, guardObservedAt: -500 }
  assert.ok(stale.confirmEndedAt - stale.probeReturnedAt <= 25)
  assert.equal(finalBoundary(stale).reason, 'soft_freshness_exceeded')
  // Pure repro from review: descending times previously produced negative ages and `allowed`.
  const reversed = finalBoundary({ guardObservedAt: 1000, guardReleasedAt: 900, probeReturnedAt: 800, confirmEndedAt: 700, checkAt: 600 })
  assert.deepEqual(reversed, { allowed: false, reason: 'timestamps_not_monotonic:guardReleasedAt', hardBound: false })
  assert.equal(finalBoundary({ ...t, killAt: 5 }).reason, 'kill_timestamp_invalid')
  assert.equal(finalBoundary({ ...t, checkAt: undefined }).reason, 'timestamp_missing:checkAt')
  assert.equal(finalBoundary({ ...t, checkAt: '6' }).reason, 'timestamp_missing:checkAt')
  for (const softLimitMs of [-1, Number.NaN, Infinity, '25']) assert.equal(finalBoundary(t, { softLimitMs }).reason, 'soft_limit_invalid')
  assert.equal(finalBoundary(null).reason, 'timestamps_missing')
  for (const x of [r, finalBoundary(stale), reversed]) assert.equal(x.hardBound, false)
  assert.ok(r.requires.includes('post_signal_lock_release_verification'))
})

const facts = (over = {}) => ({ lsofError: null, openers: [42], candidatePid: 42, acquirerPid: 42, descendants: [], unobservableSameUser: [], ...over })

test('gap 4: fork-without-exec child sharing the description is eligible under b483cd5 policy but refused here', () => {
  const shared = facts({ descendants: [43] })
  assert.equal(soleControlB483(shared).decision, 'eligible')
  assert.deepEqual(soleControlB483(shared).warnings, ['owner_has_descendants:43'])
  assert.equal(soleControlDecision(shared).reason, 'descendants_may_share_description')
  assert.equal(soleControlDecision(facts({ descendants: null })).reason, 'descendants_unavailable')
  assert.equal(soleControlDecision(facts({ acquirerPid: 41 })).reason, 'description_acquired_by_other_process')
  assert.equal(soleControlDecision(facts({ lsofError: 'WARNING: incomplete' })).reason, 'opener_lookup_incomplete')
})

test('gap 4: hidden sharer is a residual in standard mode, a refusal in strict mode; sole control and binding are never proven', () => {
  const hidden = facts({ unobservableSameUser: [77] })
  const standard = soleControlDecision(hidden)
  assert.equal(standard.decision, 'not_refused')
  assert.ok(standard.residuals.includes('hidden_sharer_not_excluded'))
  assert.ok(standard.residuals.includes('description_binding_unproven'))
  assert.equal(soleControlDecision(hidden, 'strict').reason, 'unobservable_same_user_process')
  assert.equal(soleControlDecision(facts({ unobservableSameUser: null }), 'strict').reason, 'unobservable_scan_unavailable')
  const clean = soleControlDecision(facts(), 'strict')
  assert.equal(clean.decision, 'not_refused')
  for (const r of [standard, clean]) assert.equal(r.soleControlProven, false)
})

test('gap 4: unknown modes and malformed arrays refuse instead of defaulting', () => {
  // Pure repro from review: a misspelled mode previously fell through to standard.
  assert.equal(soleControlDecision(facts({ unobservableSameUser: [77] }), 'strcit').reason, 'mode_unknown:strcit')
  assert.equal(soleControlDecision(facts(), undefined).decision, 'not_refused')
  const cases = [
    [facts({ descendants: 'none' }), 'descendants'], [facts({ descendants: [0] }), 'descendants'], [facts({ descendants: [43, 43] }), 'descendants'],
    [facts({ unobservableSameUser: [1.5] }), 'unobservableSameUser'], [facts({ unobservableSameUser: {} }), 'unobservableSameUser'],
    [facts({ openers: '42' }), 'openers'], [facts({ candidatePid: -1 }), 'candidatePid'], [facts({ acquirerPid: undefined }), 'acquirerPid'],
    [facts({ lsofError: undefined }), 'lsofError'],
  ]
  for (const [input, field] of cases) assert.equal(soleControlDecision(input).reason, `evidence_malformed:${field}`, field)
  assert.equal(soleControlDecision(null).reason, 'evidence_malformed')
})
