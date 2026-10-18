<#
Read-only Windows observer for codex-unlock research W6/W7 (#151, #152).

Windows PowerShell 5.1. WinObserver.cs is compiled by Add-Type. Three modes:

  preflight     verify the Codex binary by SHA-256 before any execution, then
                its version; measure token integrity; record host policy and
                Defender state; create a fresh private disposable CODEX_HOME.
  observe       with the operator-launched Codex holding one thread in that
                home, observe lock file identity, share modes, lock ranges
                (brief probes under the native coordination lock), Restart
                Manager openers, and the process identity of the given PID.
  fixture-meta  record token integrity and fixture file digests next to an
                experimental/windows-fixture lab.ps1 run for W6 pairing.

  powershell -NoProfile -NonInteractive -File observer.ps1 -Mode preflight -IntegrityLabel <medium|high> -SourceCommit <40 hex> -CodexBinary <codex.exe> -ExpectedSha256 <64 hex> -ExpectedVersion <text> -OutFile <new file>
  powershell -NoProfile -NonInteractive -File observer.ps1 -Mode observe -IntegrityLabel <medium|high> -CodexIntegrityLabel <medium|high> -Manifest <preflight jsonl> -CodexPid <pid> -OutFile <new file>
  powershell -NoProfile -NonInteractive -File observer.ps1 -Mode fixture-meta -IntegrityLabel <medium|high> -SourceCommit <40 hex> -OutFile <new file>

HARD REFUSAL (incomplete prototype gate): -Mode preflight and -Mode observe
refuse to run. The ancestor/junction and creation boundary is NOT closed: the
no-follow ancestry check, the identity comparisons and the creation gate all
compare identities at separate points in time instead of pinning a path, so a
same-user actor could still swap an ancestor between the check and the use. No
flag, parameter or environment variable turns this off; closing it, or
accepting the residual, is a separate review decision (README, remaining
decision 10). The code below stays in the tree to be reviewed and statically
gated, not to be run.

It never reads the user's Codex home or a pre-set CODEX_HOME, never changes
an ACL, privilege, execution policy, or Defender setting, never deletes a
file, and never terminates or signals a process. The host's existing
execution policy applies. Every record carries the measured token integrity
and safeToUnlock=false.

It is not purely passive, though: the range probe takes a brief EXCLUSIVE
byte-range lock on the live .coordination.lock and on a thread lock that is
currently free. Codex acquires with a fail-immediately try_lock, so a Codex
acquisition inside one of those windows fails. That is an effect on the
observed process, and it is one more reason the native modes are refused.

Add-Type compiles WinObserver.cs with the .NET compiler, which starts csc.exe
as a child process and writes its own temporary files into %TEMP%. That is a
compiler side effect, not an observation: no observer method is called before
the path and TEMP gate below has passed, and the gate runs BEFORE Add-Type so
the compiler never writes into a directory that resolves inside a real Codex
home.

Exit codes: 0 = every hypothesis matched; 1 = at least one mismatch;
2 = incomplete, error, unknown, or an orchestrator/setup failure;
3 = refused before anything was created or observed.
#>
param(
    [ValidateSet('preflight', 'observe', 'fixture-meta')][string]$Mode,
    [string]$OutFile,
    [ValidateSet('medium', 'high')][string]$IntegrityLabel,
    [ValidateSet('medium', 'high')][string]$CodexIntegrityLabel,
    [string]$SourceCommit,
    [string]$CodexBinary,
    [string]$ExpectedSha256,
    [string]$ExpectedVersion,
    [string]$Manifest,
    [ValidateRange(0, 2147483647)][int]$CodexPid = 0,
    [ValidateRange(1, 10)][int]$Samples = 3,
    [ValidateRange(0, 600000)][int]$WaitBudgetMs = 15000,
    [string]$FixtureDir
)
$ErrorActionPreference = 'Stop'
$Schema = 'codex-unlock-win-observer/1'
$IntegritySids = @{ medium = 'S-1-16-8192'; high = 'S-1-16-12288' }
# Exactly the file-name set expectations.mjs (HARNESS_FILES) requires. A unit
# test compares the two lists.
$HarnessNames = @('observer.ps1', 'WinObserver.cs', 'check.ps1', 'expectations.mjs', 'lib.mjs', 'evaluate.mjs')
$FixtureNames = @('lab.ps1', 'WinLockLab.cs', 'check.ps1')
# The DACL contract of the disposable parent and home, recorded as raw fields
# and recomputed by the evaluator.
$AclRights = 'FullControl'
$AclInheritance = 'ContainerInherit, ObjectInherit'
$AclType = 'Allow'
# Narrow environment allowlist for the one child process this harness starts
# (`codex --version`). The child's environment is cleared first, so no
# inherited authentication variable (CODEX_*, OPENAI_*, *TOKEN*, *KEY*, proxy
# or credential variables) and no USERPROFILE reaches it. The .NET compiler
# Add-Type starts is NOT covered by this allowlist: it inherits this process's
# environment, which is why no credential may be exported into this shell.
$ChildEnvAllowlist = @('SystemRoot', 'SystemDrive', 'windir', 'COMSPEC', 'PATHEXT', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE')
# The native modes stay refused while the ancestry/creation boundary is open.
$NATIVE_MODES_REFUSED = $true
$NativeRefusalReason = 'native preflight and observe are refused in this prototype: the ancestor/junction and creation boundary is not closed (identities are compared at separate points in time, not pinned), so no native observation is approved. There is no bypass flag; see README remaining decision 10.'

# Union of the expectations.mjs hypotheses per step. evaluate.mjs re-checks
# every record against its own table and reports drift as unknown.
$Expect = @{
    # `complete = $false` is already classified as an error by Test-Expect
    # before any hypothesis is compared, so `harness` and `manifest` carry no
    # hypothesis: declaring `complete = $true` here would advertise a
    # comparison that can never produce `mismatch`.
    'preflight'    = @{
        'harness'         = $null
        'token.self'      = @{ integrityMatchesLabel = $true }
        'binary.sha256'   = @{ matches = $true }
        'home.isolated'   = @{ isolated = $true }
        'binary.version'  = @{ matches = $true; exitCode = 0 }
        'host.defender'   = @{ amServiceEnabled = $true; realTimeProtectionEnabled = $true }
        'manifest'        = $null
    }
    'observe'      = @{
        'harness'                = @{ matchesManifest = $true }
        'token.self'             = @{ integrityMatchesLabel = $true; matchesManifest = $true }
        'home.identity'          = @{ matchesManifest = $true }
        'process.identity'       = @{ state = 'live'; imageMatchesBinary = $true; tokenOpened = $true; codexIntegrityMatchesLabel = $true }
        'process.sample'         = @{ state = 'live' }
        'lockdir.identity'       = @{ directory = $true; reparse = $false }
        'coordination.identity'  = @{ directory = $false; reparse = $false; links = 1; deletePending = $false }
        'thread.count'           = @{ count = 1 }
        'thread.identity'        = @{ directory = $false; reparse = $false; links = 1; deletePending = $false }
        'share.read_rwd'         = @{ opened = $true }
        'share.delete_rwd'       = @{ opened = $true }
        'range.probe'            = @{ state = 'probed'; 'ranges.rust.win32' = 33; 'ranges.fsext.win32' = 33; 'ranges.beyond_fsext.win32' = 33 }
        'thread.identity_after'  = @{ sameFileId = $true }
        'process.identity_after' = @{ state = 'live'; sameCreate = $true }
    }
    'fixture-meta' = @{
        'token.self'      = @{ integrityMatchesLabel = $true }
        'fixture.harness' = $null
    }
}

# Refused before anything was created or observed. `exit` raises a PowerShell
# flow-control exception that a `catch` block does not intercept, so the catch
# around setup is not expected to see a refusal; $script:SetupExit is recorded
# anyway so that a later refactor which does intercept it cannot silently turn
# a deliberate refusal into a different exit code.
$script:SetupExit = $null
function Refuse([string]$why) { Write-Output "refused: $why"; $script:SetupExit = 3; exit 3 }
# Setup could not be established either way: documented unknown, never the
# mismatch code 1 and never an accidental uncaught exit.
function Stop-Unknown([string]$why) { Write-Output "unknown: $why"; $script:SetupExit = 2; exit 2 }

# ---- Pure helpers (check.ps1 extracts and exercises these) ---------------

# Lexical, case-insensitive relation of a to b: same, inside, contains,
# disjoint. A drive root is reported as `contains` of everything on its volume,
# which is correct but is why a path's PARENT is never gated on this relation.
function Get-PathRelation([string]$a, [string]$b) {
    $x = $a.TrimEnd('\')
    $y = $b.TrimEnd('\')
    if ([string]::Equals($x, $y, [StringComparison]::OrdinalIgnoreCase)) { return 'same' }
    if ($x.StartsWith($y + '\', [StringComparison]::OrdinalIgnoreCase)) { return 'inside' }
    if ($y.StartsWith($x + '\', [StringComparison]::OrdinalIgnoreCase)) { return 'contains' }
    'disjoint'
}

# Strict spelling rules for every path this harness compares, reads, hashes or
# creates. Only absolute local DRIVE paths are accepted. UNC (\\server\share),
# device (\\?\, \\.\), rooted-without-drive (\x), drive-relative (C:x) and
# relative spellings are REFUSED rather than normalized, as are `.`/`..`
# components, empty components, components ending in a space or a dot, and
# characters Windows does not allow in a name. Tilde components are also
# refused conservatively: GetFullPath does not expand 8.3 aliases, so textual
# disjointness cannot safely compare a short spelling with a long one. This
# rejects literal tilde names too; it is not physical-path canonicalization.
# This mirrors
# normalizeLocalPath in expectations.mjs. An ambiguous spelling is refused; it
# is never rewritten into something that looks safe.
function Test-LocalPathSpelling([string]$p) {
    if ([string]::IsNullOrEmpty($p)) { return $false }
    if ($p.Length -gt 32767) { return $false }
    if ($p -match '[\x00-\x1f\x7f"<>|*?]') { return $false }
    if ($p.Contains('/')) { return $false }
    if ($p -notmatch '^[A-Za-z]:\\') { return $false }
    $parts = $p.Split('\')
    if ($parts[0] -notmatch '^[A-Za-z]:$') { return $false }
    # @() keeps array semantics for a one-element slice: without it a single
    # remaining component would be a bare string and index into characters.
    $rest = @($parts | Select-Object -Skip 1)
    if ($rest.Count -gt 1 -and $rest[$rest.Count - 1] -eq '') { $rest = @($rest[0..($rest.Count - 2)]) }
    if ($rest.Count -eq 1 -and $rest[0] -eq '') { return $true }
    foreach ($part in $rest) {
        if ($part -eq '' -or $part -eq '.' -or $part -eq '..') { return $false }
        if ($part.Contains('~')) { return $false }
        if ($part.Contains(':')) { return $false }
        if ($part.EndsWith(' ') -or $part.EndsWith('.') -or $part.StartsWith(' ')) { return $false }
    }
    $true
}

# True when any COMPONENT of the path is a disposable observer directory. The
# comparison is literal per component, never a wildcard match, so a bracket or
# a `*` in a real directory name cannot change the decision, and the rule holds
# on any volume regardless of the current %TEMP%.
function Test-InsideDisposableDir([string]$p) {
    if (-not (Test-LocalPathSpelling $p)) { return $false }
    foreach ($part in $p.Split('\')) {
        if ($part -imatch '^codex-win-obs-[0-9a-f]{12}$') { return $true }
    }
    $false
}

# The lexical gate every relevant input and output path must pass BEFORE it is
# tested, read, hashed or created: accepted spelling, disjoint from the
# actual/default and environment Codex homes, and outside any disposable
# observer directory unless the caller is the disposable home itself. Real
# homes are compared textually and are never opened, listed or statted.
# Returns $null when the path is acceptable, otherwise the refusal reason.
function Test-PathGateSafe([string]$p, [string]$userCodexHome, [string]$envCodexHome, [bool]$allowDisposable) {
    if (-not (Test-LocalPathSpelling $p)) { return 'path_spelling' }
    if (-not (Test-LocalPathSpelling $userCodexHome)) { return 'user_home_spelling' }
    if ((Get-PathRelation $p $userCodexHome) -ne 'disjoint') { return 'user_home_overlap' }
    if ($envCodexHome) {
        if (-not (Test-LocalPathSpelling $envCodexHome)) { return 'env_home_spelling' }
        if ((Get-PathRelation $p $envCodexHome) -ne 'disjoint') { return 'env_home_overlap' }
    }
    if (-not $allowDisposable -and (Test-InsideDisposableDir $p)) { return 'inside_disposable_dir' }
    $null
}

# True only when the disposable temp ROOT passes the same gate. This refuses to
# create anything when TEMP resolves inside a real Codex home.
function Test-CandidateTempSafe([string]$tempRoot, [string]$userCodexHome, [string]$envCodexHome) {
    $null -eq (Test-PathGateSafe $tempRoot $userCodexHome $envCodexHome $false)
}

# Creation seam: the creation callback runs only when the gate returns true, so
# a gate failure (for example TEMP inside a real home) provably skips creation.
function Invoke-GuardedCreate([scriptblock]$Gate, [scriptblock]$Create) {
    if (& $Gate) { return & $Create }
    [pscustomobject]@{ created = $false; reason = 'gate_refused' }
}

# Per-sample seam: a sample's active operations run only when that sample's own
# gate returns $null. One sample never inherits another sample's verdict, and a
# failed gate provably skips the enumeration, Restart Manager, share and range
# operations instead of recording them and continuing.
function Invoke-GuardedSample([scriptblock]$Gate, [scriptblock]$Operations) {
    $reason = & $Gate
    if ($reason) { return [pscustomobject]@{ ran = $false; reason = $reason } }
    [pscustomobject]@{ ran = $true; result = (& $Operations) }
}

function New-StreamChannel($stream, [int]$maxBytes) {
    @{ stream = $stream; max = $maxBytes; buf = (New-Object byte[] 4096); ms = (New-Object IO.MemoryStream)
        task = $null; complete = $false; truncated = $false; timedOut = $false; error = $null
        bytes = 0; text = $null }
}

# Drains every channel CONCURRENTLY against one monotonic deadline, so a child
# that fills one pipe while the reader waits on the other cannot deadlock the
# observer. Each channel is capped: the loop reads one byte MORE than the cap,
# so a short read exactly at the cap is end-of-stream while a full read is a
# real overflow. The channel hashtables are mutated in place:
#   complete   $true only at end-of-stream, inside the deadline, within the cap
#   truncated  more bytes than the cap were offered
#   timedOut   the deadline passed before end-of-stream
#   error      the read itself failed (the message is kept)
# Only complete=$true is usable evidence; the caller must not treat a valid
# first line beside a failed or truncated read as success. Nothing is ever
# terminated: a producer still holding the pipe is reported and left alone. A
# read still pending at the deadline is abandoned, and its buffer is not
# reused afterwards.
function Read-BothStreams($channels, [Diagnostics.Stopwatch]$clock, [int]$deadlineMs) {
    while ($true) {
        $pending = @()
        foreach ($c in $channels) {
            if ($c.complete -or $c.truncated -or $c.timedOut -or $c.error) { continue }
            if ($null -eq $c.task) {
                $room = ($c.max + 1) - $c.ms.Length
                if ($room -le 0) { $c.truncated = $true; continue }
                $want = [Math]::Min([int]$room, $c.buf.Length)
                try { $c.task = $c.stream.ReadAsync($c.buf, 0, $want) }
                catch { $c.error = $_.Exception.Message; continue }
            }
            $pending += $c
        }
        if ($pending.Count -eq 0) { break }
        $remaining = $deadlineMs - $clock.ElapsedMilliseconds
        if ($remaining -le 0) { foreach ($c in $pending) { $c.timedOut = $true }; break }
        $tasks = [Threading.Tasks.Task[]]@($pending | ForEach-Object { $_.task })
        $index = -1
        try { $index = [Threading.Tasks.Task]::WaitAny($tasks, [int]$remaining) }
        catch { foreach ($c in $pending) { $c.error = $_.Exception.Message }; break }
        if ($index -lt 0) { foreach ($c in $pending) { $c.timedOut = $true }; break }
        $done = $pending[$index]
        $doneTask = $done.task
        $done.task = $null
        # Windows PowerShell 5.1 can turn a throwing Task.Result property
        # getter into $null without a catchable exception. Never interpret
        # that as EOF: inspect task state and use the awaiter's method.
        if ($doneTask.IsCanceled) { $done.error = 'stream_read_canceled'; continue }
        if ($doneTask.IsFaulted) {
            $done.error = 'stream_read_faulted'
            if ($null -ne $doneTask.Exception) { $done.error = $doneTask.Exception.GetBaseException().Message }
            continue
        }
        try {
            $n = $doneTask.GetAwaiter().GetResult()
            if ($null -eq $n) { throw 'stream read returned no byte count' }
            if ($n -le 0) { $done.complete = $true } else { $done.ms.Write($done.buf, 0, $n) }
        } catch {
            $done.error = $_.Exception.Message
        }
    }
    foreach ($c in $channels) {
        if ($c.ms.Length -gt $c.max) { $c.truncated = $true; $c.complete = $false }
        if ($c.error) { $c.complete = $false }
        $c.bytes = [int]$c.ms.Length
        $c.text = [Text.Encoding]::UTF8.GetString($c.ms.ToArray())
    }
    $channels
}

# Single-stream wrapper over the same drain loop, so the bounded-read contract
# that check.ps1 exercises is the one preflight uses.
function Read-BoundedStream($stream, [int]$maxBytes, [Diagnostics.Stopwatch]$clock, [int]$deadlineMs) {
    $c = New-StreamChannel $stream $maxBytes
    Read-BothStreams @($c) $clock $deadlineMs | Out-Null
    $c
}

# Restart Manager opener roles, recomputed from the run's own PIDs and the
# target's creation FILETIME. The target PID with a different creation time is
# a reused PID, not the launched process, so it is not labelled as one.
function Get-OpenerRole([int]$ProcessId, [string]$StartFiletime, [int]$TargetPid, [string]$TargetCreate, [int]$ObserverPid) {
    if ($ProcessId -eq $TargetPid -and $TargetCreate -and $StartFiletime -ceq $TargetCreate) { return 'launched_codex' }
    if ($ProcessId -eq $ObserverPid) { return 'observer' }
    'other'
}

function Get-Dotted($o, [string]$path) {
    $cur = $o
    foreach ($k in $path.Split('.')) {
        if ($null -eq $cur) { return $null }
        $p = $cur.PSObject.Properties[$k]
        if ($null -eq $p) { return $null }
        $cur = $p.Value
    }
    $cur
}

function Test-Denied($o) {
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $o.PSObject.Properties) {
            if (($p.Name -eq 'win32' -or $p.Name -eq 'tokenWin32') -and "$($p.Value)" -eq '5') { return $true }
            if (Test-Denied $p.Value) { return $true }
        }
    } elseif ($o -is [Array]) {
        foreach ($i in $o) { if (Test-Denied $i) { return $true } }
    }
    $false
}

# incomplete (no observation) first; ok=false/complete=false/exception is
# error; an unknown state or access denial is unknown; recorded has no
# hypothesis. Only then is the hypothesis compared.
function Test-Expect($observed, $expect) {
    if ($null -eq $observed) { return 'incomplete' }
    if ($observed.PSObject.Properties['exception'] -or $observed.ok -ne $true -or $observed.complete -eq $false) { return 'error' }
    if ($observed.state -eq 'unknown' -or (Test-Denied $observed)) { return 'unknown' }
    if ($null -eq $expect) { return 'recorded' }
    foreach ($k in $expect.Keys) {
        $v = Get-Dotted $observed $k
        if ($null -eq $v -or "$v" -ne "$($expect[$k])") { return 'mismatch' }
    }
    'match'
}

function Test-SameDigests($a, $b) {
    if ($null -eq $a -or $null -eq $b) { return $false }
    $na = @($a.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    $nb = @($b.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    if (($na -join '|') -ne ($nb -join '|') -or $na.Count -eq 0) { return $false }
    foreach ($n in $na) { if ($null -eq $a.$n -or "$($a.$n)" -cne "$($b.$n)") { return $false } }
    $true
}

# ---- Path gate: runs before Add-Type and before any file is opened --------

function Resolve-Full([string]$p) {
    [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p))
}

# Validates every path this invocation will touch, lexically and in one place,
# before any Test-Path, read, hash, creation or Add-Type. The actual and
# environment Codex homes are derived textually from the environment and are
# never opened. Returns a result object; it refuses (exit 3) on any failure.
function Assert-PathGate {
    $userProfile = $env:USERPROFILE
    if (-not $userProfile) { Refuse 'USERPROFILE is not set, so the real Codex home cannot be excluded' }
    if (-not (Test-LocalPathSpelling $userProfile)) { Refuse 'USERPROFILE is not an accepted absolute local path' }
    $userCodexHome = [IO.Path]::GetFullPath((Join-Path $userProfile '.codex'))
    $envCodexHome = $null
    if ($env:CODEX_HOME) {
        $envCodexHome = [IO.Path]::GetFullPath($env:CODEX_HOME)
        if (-not (Test-LocalPathSpelling $envCodexHome)) { Refuse 'CODEX_HOME is set to a path spelling this harness refuses' }
    }
    $tempRoot = $null
    if ($env:TEMP) { $tempRoot = Resolve-Full $env:TEMP }
    if (-not $tempRoot -or -not (Test-LocalPathSpelling $tempRoot)) { Refuse 'TEMP is unset or not an accepted absolute local path' }
    # The compiler Add-Type starts writes into TEMP, so TEMP must clear the
    # real-home boundary before anything is compiled.
    $tempReason = Test-PathGateSafe $tempRoot $userCodexHome $envCodexHome $false
    if ($tempReason) { Refuse "TEMP is not usable as a disposable root ($tempReason); nothing was created or compiled" }
    $scriptRoot = Resolve-Full $PSScriptRoot
    $scriptReason = Test-PathGateSafe $scriptRoot $userCodexHome $envCodexHome $false
    if ($scriptReason) { Refuse "the harness directory is not usable ($scriptReason)" }
    [pscustomobject]@{
        userProfile = $userProfile; userCodexHome = $userCodexHome; envCodexHome = $envCodexHome
        tempRoot = $tempRoot; scriptRoot = $scriptRoot
    }
}

# ---- Refusals: nothing is created, compiled or observed until these pass --
try {
    if (-not $Mode) { Refuse '-Mode is required (preflight, observe, fixture-meta)' }
    if (-not $IntegrityLabel) { Refuse '-IntegrityLabel is required (medium or high, the level this session is expected to have)' }
    if (-not $OutFile) { Refuse '-OutFile is required (new file)' }

    $PathGate = Assert-PathGate
    $TempRoot = $PathGate.tempRoot
    $UserCodexHome = $PathGate.userCodexHome
    $EnvCodexHome = $PathGate.envCodexHome

    # Every input and output path is normalized and gated before it is tested,
    # read, hashed or created.
    $OutFile = Resolve-Full $OutFile
    $outReason = Test-PathGateSafe $OutFile $UserCodexHome $EnvCodexHome $false
    if ($outReason) { Refuse "-OutFile is not usable ($outReason); it must be an absolute local drive path outside any real Codex home and outside any codex-win-obs-<12 hex> directory" }
    # The parent is checked for spelling and for a disposable component only.
    # Whether the output overlaps a real home is already decided by the output
    # path itself above; a parent that merely CONTAINS a real home (a drive
    # root, or the profile directory next to `.codex`) is not a reason to
    # refuse an output written beside it.
    $outParent = Split-Path $OutFile -Parent
    if (-not (Test-LocalPathSpelling $outParent)) { Refuse '-OutFile parent directory is not an accepted absolute local path' }
    if (Test-InsideDisposableDir $outParent) { Refuse '-OutFile parent directory is inside a codex-win-obs disposable directory' }
    if (Test-Path -LiteralPath $OutFile) { Refuse "$OutFile already exists" }
    if (-not (Test-Path -LiteralPath $outParent -PathType Container)) { Refuse '-OutFile parent directory does not exist' }

    if ($Mode -ne 'observe' -and $SourceCommit -cnotmatch '^[0-9a-f]{40}$') { Refuse '-SourceCommit must be the 40-hex commit of this checkout' }

    if ($Mode -eq 'preflight') {
        if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') { Refuse '-ExpectedSha256 must be 64 lowercase hex characters from the pinned release asset' }
        if (-not $ExpectedVersion) { Refuse '-ExpectedVersion is required' }
        if (-not $CodexBinary) { Refuse '-CodexBinary is required' }
        $CodexBinary = Resolve-Full $CodexBinary
        $binReason = Test-PathGateSafe $CodexBinary $UserCodexHome $EnvCodexHome $false
        if ($binReason) { Refuse "-CodexBinary is not usable ($binReason)" }
    }
    if ($Mode -eq 'observe') {
        if (-not $Manifest) { Refuse '-Manifest must name the preflight JSONL' }
        $Manifest = Resolve-Full $Manifest
        $manifestReason = Test-PathGateSafe $Manifest $UserCodexHome $EnvCodexHome $false
        if ($manifestReason) { Refuse "-Manifest is not usable ($manifestReason)" }
        if ($CodexPid -le 0) { Refuse '-CodexPid is required (the PID of the operator-launched codex.exe)' }
        if ($CodexPid -eq $PID) { Refuse '-CodexPid is this observer process' }
        if (-not $CodexIntegrityLabel) { Refuse '-CodexIntegrityLabel is required (the level of the window that launched Codex)' }
    }
    if ($Mode -eq 'fixture-meta') {
        if (-not $FixtureDir) { $FixtureDir = Join-Path $PSScriptRoot '..\windows-fixture' }
        $FixtureDir = Resolve-Full $FixtureDir
        $fixtureReason = Test-PathGateSafe $FixtureDir $UserCodexHome $EnvCodexHome $false
        if ($fixtureReason) { Refuse "-FixtureDir is not usable ($fixtureReason)" }
    }

    # Host preconditions that must hold before anything is created or executed.
    if ($Mode -eq 'preflight') {
        $volumeCommand = Get-Command Get-Volume -ErrorAction SilentlyContinue
        if ($null -eq $volumeCommand -or -not $volumeCommand.Parameters.ContainsKey('FilePath')) { Refuse 'Storage Get-Volume -FilePath is required' }
        if ($null -eq (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { Refuse 'Get-MpComputerStatus is required to record the existing Defender state; it is never changed' }
    }

    # ---- Hard refusal of the native modes (incomplete prototype gate) ----
    # The ancestor/junction and creation boundary is not closed, so no native
    # preflight or observe run is approved. There is no bypass.
    if ($NATIVE_MODES_REFUSED -and ($Mode -eq 'preflight' -or $Mode -eq 'observe')) { Refuse $NativeRefusalReason }

    # ---- Compilation (after the path and TEMP gate) ----------------------
    # Add-Type starts the .NET compiler as a child process and writes compiler
    # temporaries into the gated TEMP. No observer method is called here.
    Add-Type -Path (Join-Path $PSScriptRoot 'WinObserver.cs')
    $SelfTok = [WinObserver]::SelfToken() | ConvertFrom-Json
    if ($SelfTok.ok -ne $true -or $SelfTok.tokenOpened -ne $true -or -not $SelfTok.integritySid -or -not $SelfTok.userSid) {
        Refuse 'own token integrity could not be measured'
    }
    $UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ("$UserSid" -ne $SelfTok.userSid) { Stop-Unknown 'the measured token user SID differs from the current identity' }
} catch {
    # A deliberate refusal keeps its own code; anything else that escapes
    # setup (a path API, Add-Type, the compiler, a token read) is reported as
    # unknown, never as the mismatch code 1 and never as an uncaught exit.
    if ($null -ne $script:SetupExit) { exit $script:SetupExit }
    Stop-Unknown ('setup failed: ' + $_.Exception.Message)
}

# Every record carries the measured integrity with the declared label; a
# mismatch is recorded and stops the run, it is never relabelled.
$Integrity = [pscustomobject]@{
    label = $IntegrityLabel; sid = $SelfTok.integritySid
    elevationType = $SelfTok.elevationType; sessionId = $SelfTok.sessionId
}

$Results = New-Object System.Collections.Generic.List[object]
$Utf8 = New-Object Text.UTF8Encoding($false)
$Abort = $null
$OrchestratorFailed = $false

function Get-Sha256Hex([string]$path) {
    $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { -join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    } finally { $fs.Dispose() }
}

function Get-FileDigests([string]$dir, [string[]]$names) {
    $files = New-Object psobject
    $complete = $true
    foreach ($n in $names) {
        $p = Join-Path $dir $n
        $v = $null
        if (Test-Path -LiteralPath $p -PathType Leaf) { $v = Get-Sha256Hex $p } else { $complete = $false }
        $files | Add-Member -NotePropertyName $n -NotePropertyValue $v
    }
    [pscustomobject]@{ ok = $true; complete = $complete; files = $files }
}

function Record([string]$step, $observed, $sample = $null) {
    $e = $Expect[$Mode][$step]
    $v = Test-Expect $observed $e
    $Results.Add([pscustomobject]@{
            schema = $Schema; mode = $Mode; step = $step; sample = $sample
            integrity = $Integrity
            expect = $e; observed = $observed; verdict = $v
            safeToUnlock = $false
        })
    $v
}

function Native([scriptblock]$call) {
    try { (& $call) | ConvertFrom-Json } catch {
        [pscustomobject]@{ ok = $false; exception = ($_.Exception.GetType().Name + ': ' + $_.Exception.Message) }
    }
}

# Records the ACL contract of a directory pair as RAW fields. No boolean
# summary is trusted downstream: the evaluator recomputes the contract from the
# owner, the single ACE's identity, rights, inheritance and type.
function Get-AclFields([string]$HomeDir, [string]$ParentDir) {
    $homeAcl = Get-Acl -LiteralPath $HomeDir
    $parentAcl = Get-Acl -LiteralPath $ParentDir
    $homeRules = @($homeAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $parentRules = @($parentAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $homeAce = $(if ($homeRules.Count -eq 1) { $homeRules[0] } else { $null })
    $parentAce = $(if ($parentRules.Count -eq 1) { $parentRules[0] } else { $null })
    [pscustomobject]@{
        currentUserSid = "$UserSid"
        owner = "$($homeAcl.GetOwner([Security.Principal.SecurityIdentifier]))"
        daclProtected = $homeAcl.AreAccessRulesProtected
        aceCount = $homeRules.Count
        aceIdentity = $(if ($homeAce) { "$($homeAce.IdentityReference)" } else { $null })
        aceRights = $(if ($homeAce) { "$($homeAce.FileSystemRights)" } else { $null })
        aceInheritance = $(if ($homeAce) { "$($homeAce.InheritanceFlags)" } else { $null })
        aceType = $(if ($homeAce) { "$($homeAce.AccessControlType)" } else { $null })
        parentOwner = "$($parentAcl.GetOwner([Security.Principal.SecurityIdentifier]))"
        parentDaclProtected = $parentAcl.AreAccessRulesProtected
        parentAceCount = $parentRules.Count
        parentAceIdentity = $(if ($parentAce) { "$($parentAce.IdentityReference)" } else { $null })
        parentAceRights = $(if ($parentAce) { "$($parentAce.FileSystemRights)" } else { $null })
        parentAceInheritance = $(if ($parentAce) { "$($parentAce.InheritanceFlags)" } else { $null })
        parentAceType = $(if ($parentAce) { "$($parentAce.AccessControlType)" } else { $null })
    }
}

# No-follow ancestry of the disposable parent, recorded as raw entries. The
# evaluator refuses the home when any component is not a plain directory. This
# is a check, not a pin: see the header's hard-refusal note.
function Get-AncestryEntries([string]$ParentDir) {
    $a = Native { [WinObserver]::Ancestry($ParentDir) }
    if ($a.ok -ne $true -or $a.state -eq 'unknown') { return @() }
    @($a.entries)
}

# Parameter names are task-specific on purpose: $home would collide with the
# read-only automatic variable $HOME (PowerShell variable names are
# case-insensitive), and check.ps1 refuses such a name in the syntax tree.
function Add-PathFields($o, [string]$HomeDir, [string]$ParentDir) {
    $o | Add-Member -NotePropertyName home -NotePropertyValue $HomeDir
    $o | Add-Member -NotePropertyName parent -NotePropertyValue $ParentDir
    $o | Add-Member -NotePropertyName userCodexHome -NotePropertyValue $UserCodexHome
    $o | Add-Member -NotePropertyName envCodexHome -NotePropertyValue $EnvCodexHome
    $o | Add-Member -NotePropertyName userRelation -NotePropertyValue (Get-PathRelation $HomeDir $UserCodexHome)
    $o | Add-Member -NotePropertyName envRelation -NotePropertyValue $(if ($EnvCodexHome) { Get-PathRelation $HomeDir $EnvCodexHome } else { $null })
    $o | Add-Member -NotePropertyName fileId -NotePropertyValue ([WinObserver]::DirFileId($HomeDir))
    $o | Add-Member -NotePropertyName parentFileId -NotePropertyValue ([WinObserver]::DirFileId($ParentDir))
    # Capture into an array first: a function that emits an empty array emits
    # nothing, which would store $null and make an "@(...).Count -gt 0" guard
    # on the stored value vacuously true.
    $ancestryEntries = @(Get-AncestryEntries $ParentDir)
    $o | Add-Member -NotePropertyName ancestry -NotePropertyValue $ancestryEntries
    foreach ($p in (Get-AclFields $HomeDir $ParentDir).PSObject.Properties) {
        $o | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value
    }
    $o
}

# The per-sample process gate. It re-queries the DECLARED PID and returns $null
# only when that PID is still the same live, same-user instance at the same
# creation FILETIME, image and integrity. The queried record is emitted so the
# evaluator can bind it to the run record. A failure here refuses this sample's
# active operations; it cannot undo a previous sample's operations.
function Get-SampleRefusal([int]$TargetPid, [string]$ExpectCreate, [string]$ExpectImage, [string]$ExpectUserSid,
    [string]$ExpectIntegritySid, $Collected) {
    $p = Native { [WinObserver]::ProcessIdentity($TargetPid) }
    $Collected.record = $p
    if ($p.ok -ne $true -or $p.PSObject.Properties['exception']) { return 'process_query_failed' }
    if ($p.opened -ne $true) { return 'process_not_opened' }
    if ([int]$p.pid -ne $TargetPid) { return 'queried_pid_differs' }
    if ($p.state -ne 'live') { return ('process_state_' + $p.state) }
    if (-not $p.createFiletime -or "$($p.createFiletime)" -cne "$ExpectCreate") { return 'create_filetime_changed' }
    if ($p.tokenOpened -ne $true) { return 'token_unreadable' }
    if ("$($p.userSid)" -cne "$ExpectUserSid") { return 'user_sid_differs' }
    if ("$($p.integritySid)" -cne "$ExpectIntegritySid") { return 'integrity_sid_changed' }
    if (-not $p.image -or -not [string]::Equals($p.image, $ExpectImage, [StringComparison]::OrdinalIgnoreCase)) { return 'image_differs' }
    $null
}

# ---- Manifest validation (observe), before anything is recorded ----------
# Exactly one manifest record in the whole file, and it must be the LAST
# record: zero means an unfinished preflight, more than one (complete or not)
# means an ambiguous or tampered file, and a manifest that is not last means
# the preflight continued after claiming to be done. Every other required
# preflight step must appear exactly once with a usable verdict. Internal
# consistency and digest provenance are checked here, and the values are
# cross-checked against the raw preflight records they claim to describe. A
# file ID alone is never treated as authorization or provenance. This prevents
# stale, partial, contradictory or out-of-scope inputs. It does NOT claim to
# defend against an adversarial same-user forged manifest.
$M = $null
$ManifestSha = $null
$records = @()
# Set before the read so a failure in the hash or the read itself still
# reports a defined position.
$lineNo = 0
if ($Mode -eq 'observe') {
    try {
        $ManifestSha = Get-Sha256Hex $Manifest
        foreach ($line in ([IO.File]::ReadAllText($Manifest) -split "`n")) {
            $lineNo++
            if (-not $line) { continue }
            $records += ($line | ConvertFrom-Json)
        }
    } catch {
        Stop-Unknown ('manifest could not be read or parsed at line ' + $lineNo + ': ' + $_.Exception.Message)
    }
    if ($records.Count -eq 0) { Refuse 'manifest file has no records' }
    foreach ($r in $records) {
        if ($r.schema -ne $Schema) { Refuse 'manifest file holds a record of another schema' }
        if ($r.mode -ne 'preflight') { Refuse 'manifest file holds a record of another mode' }
        if ($r.safeToUnlock -ne $false) { Refuse 'manifest file holds a record without safeToUnlock=false' }
        if ($r.step -eq 'orchestrator_error') { Refuse 'manifest file holds an orchestrator_error record' }
    }
    $manifestRecords = @($records | Where-Object { $_.step -eq 'manifest' })
    if ($manifestRecords.Count -eq 0) { Refuse 'manifest has no manifest record; rerun preflight' }
    if ($manifestRecords.Count -gt 1) { Refuse 'manifest file has more than one manifest record; it is ambiguous' }
    if ($records[$records.Count - 1].step -ne 'manifest') { Refuse 'the manifest record is not the last record of the preflight file' }
    $required = @('harness', 'token.self', 'binary.sha256', 'binary.signature', 'binary.pe_version', 'home.isolated',
        'binary.version', 'home.after_version', 'host.execution_policy', 'host.defender', 'host.volume', 'host.os')
    foreach ($step in $required) {
        $found = @($records | Where-Object { $_.step -eq $step })
        if ($found.Count -ne 1) { Refuse "preflight file must hold exactly one $step record" }
        if ($found[0].verdict -notin @('match', 'recorded')) { Refuse "preflight record $step is not a usable observation" }
    }
    $M = $manifestRecords[0].observed
    if ($M.complete -ne $true) { Refuse 'the manifest record is not complete; rerun preflight' }
    foreach ($field in 'home', 'homeFileId', 'parent', 'parentFileId', 'binaryPath', 'binarySha256', 'binarySize',
        'version', 'sourceCommit', 'integritySid', 'label', 'harness') {
        if (-not $M.PSObject.Properties[$field] -or $null -eq $M.$field) { Refuse "manifest is missing field $field" }
    }
    foreach ($field in 'home', 'parent', 'binaryPath') {
        if (-not (Test-LocalPathSpelling $M.$field)) { Refuse "manifest field $field is not an accepted absolute local path" }
    }
    # The manifest must describe a disposable home outside every real home.
    if ((Get-PathRelation $M.home $M.parent) -ne 'inside' -or (Split-Path $M.home -Leaf) -cne 'home') { Refuse 'manifest home is not the parent''s home child' }
    if ((Split-Path $M.parent -Leaf) -cnotmatch '^codex-win-obs-[0-9a-f]{12}$') { Refuse 'manifest parent is not a codex-win-obs-<12 hex> directory' }
    $homeReason = Test-PathGateSafe $M.home $UserCodexHome $EnvCodexHome $true
    if ($homeReason) { Refuse "manifest home is not usable ($homeReason)" }
    if ($M.integritySid -ne $SelfTok.integritySid) { Refuse 'manifest integrity SID differs from the current token (digest provenance)' }
    if ($M.label -ne $IntegrityLabel) { Refuse 'manifest label differs from -IntegrityLabel' }
    if ($M.sourceCommit -cnotmatch '^[0-9a-f]{40}$' -or $M.binarySha256 -cnotmatch '^[0-9a-f]{64}$') { Refuse 'manifest commit or binary digest is malformed' }
    # Cross-check the manifest against the raw preflight observations it claims
    # to describe; a manifest that disagrees with its own run is refused.
    $pfHome = @($records | Where-Object { $_.step -eq 'home.isolated' })[0].observed
    $pfBinary = @($records | Where-Object { $_.step -eq 'binary.sha256' })[0].observed
    $pfVersion = @($records | Where-Object { $_.step -eq 'binary.version' })[0].observed
    $pfHarness = @($records | Where-Object { $_.step -eq 'harness' })[0].observed
    $pfToken = @($records | Where-Object { $_.step -eq 'token.self' })[0].observed
    if ((Get-PathRelation $M.home $pfHome.home) -ne 'same' -or $M.homeFileId -cne $pfHome.fileId) { Refuse 'manifest home does not match the preflight home observation' }
    if ((Get-PathRelation $M.parent $pfHome.parent) -ne 'same' -or $M.parentFileId -cne $pfHome.parentFileId) { Refuse 'manifest parent does not match the preflight home observation' }
    if ((Get-PathRelation $M.binaryPath $pfBinary.path) -ne 'same' -or $M.binarySha256 -cne $pfBinary.sha256 -or $M.binarySize -ne $pfBinary.size) { Refuse 'manifest binary does not match the hashed binary observation' }
    if ($M.version -cne $pfVersion.stdoutFirstLine) { Refuse 'manifest version does not match the recorded version output' }
    if ($M.sourceCommit -cne $pfHarness.sourceCommit) { Refuse 'manifest commit does not match the preflight harness record' }
    if ($M.integritySid -cne $pfToken.integritySid) { Refuse 'manifest integrity SID does not match the preflight token record' }
    if (-not (Test-SameDigests $M.harness $pfHarness.files)) { Refuse 'manifest harness digests do not match the preflight harness record' }
}

try {
    if ($Mode -eq 'fixture-meta') {
        $tok = $SelfTok | Select-Object *
        $tok | Add-Member -NotePropertyName integrityMatchesLabel -NotePropertyValue ($SelfTok.integritySid -eq $IntegritySids[$IntegrityLabel])
        Record 'token.self' $tok | Out-Null
        $fx = Get-FileDigests $FixtureDir $FixtureNames
        $fx | Add-Member -NotePropertyName sourceCommit -NotePropertyValue $SourceCommit
        $fx | Add-Member -NotePropertyName note -NotePropertyValue 'run lab.ps1 from this same shell session; integrity applies to that run only'
        Record 'fixture.harness' $fx | Out-Null
    }

    if ($Mode -eq 'preflight') {
        $h = Get-FileDigests $PSScriptRoot $HarnessNames
        $h | Add-Member -NotePropertyName sourceCommit -NotePropertyValue $SourceCommit
        $Harness = $h.files
        # The preflight harness record has no hypothesis, so a usable
        # observation verdicts `recorded`; an incomplete one verdicts `error`.
        if ((Record 'harness' $h) -notin @('match', 'recorded')) { $Abort = 'harness digests incomplete' }

        $tok = $SelfTok | Select-Object *
        $tok | Add-Member -NotePropertyName integrityMatchesLabel -NotePropertyValue ($SelfTok.integritySid -eq $IntegritySids[$IntegrityLabel])
        if (-not $Abort -and (Record 'token.self' $tok) -ne 'match') { $Abort = 'measured integrity differs from -IntegrityLabel' }

        # Host state is recorded as found, BEFORE anything is created or
        # executed, and is never changed. A host that does not meet the W7
        # precondition stops the run before the disposable home exists.
        $pol = $null
        try {
            $pol = [pscustomobject]@{ ok = $true; effective = (Get-ExecutionPolicy).ToString()
                scopes = @(Get-ExecutionPolicy -List | ForEach-Object { [pscustomobject]@{ scope = $_.Scope.ToString(); policy = $_.ExecutionPolicy.ToString() } }) }
        } catch { $pol = [pscustomobject]@{ ok = $false; exception = $_.Exception.Message } }
        Record 'host.execution_policy' $pol | Out-Null
        Record 'host.os' ([pscustomobject]@{ ok = $true; os = [Environment]::OSVersion.VersionString; ps = $PSVersionTable.PSVersion.ToString()
                elevated = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole('Administrators')
                sshSession = [bool]$env:SSH_CONNECTION }) | Out-Null
        $def = $null
        try {
            $s = Get-MpComputerStatus
            $def = [pscustomobject]@{ ok = $true; amServiceEnabled = [bool]$s.AMServiceEnabled; realTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled
                antivirusEnabled = [bool]$s.AntivirusEnabled; amProductVersion = $s.AMProductVersion }
        } catch { $def = [pscustomobject]@{ ok = $false; exception = $_.Exception.Message } }
        if ((Record 'host.defender' $def) -ne 'match' -and -not $Abort) { $Abort = 'Defender is not observed enabled; it is not changed here' }

        # Bytes before execution. The binary is never run unless this matches.
        if (-not $Abort) {
            if (-not (Test-Path -LiteralPath $CodexBinary -PathType Leaf)) { $Abort = '-CodexBinary does not name an existing file' }
            elseif ((Get-Item -LiteralPath $CodexBinary -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { $Abort = '-CodexBinary is a reparse point' }
        }
        if (-not $Abort) {
            $sha = Get-Sha256Hex $CodexBinary
            $o = [pscustomobject]@{ ok = $true; path = $CodexBinary; size = (Get-Item -LiteralPath $CodexBinary -Force).Length
                sha256 = $sha; expected = $ExpectedSha256; matches = ($sha -ceq $ExpectedSha256) }
            if ((Record 'binary.sha256' $o) -ne 'match') { $Abort = 'binary SHA-256 differs from -ExpectedSha256' }
        }
        if (-not $Abort) {
            $sig = $null
            try {
                $s = Get-AuthenticodeSignature -LiteralPath $CodexBinary
                $sig = [pscustomobject]@{ ok = $true; status = $s.Status.ToString(); statusMessage = $s.StatusMessage
                    signer = $(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null })
                    thumbprint = $(if ($s.SignerCertificate) { $s.SignerCertificate.Thumbprint } else { $null }) }
            } catch { $sig = [pscustomobject]@{ ok = $false; exception = $_.Exception.Message } }
            Record 'binary.signature' $sig | Out-Null
            # An absent version resource is DECLARED, not implied by empty fields.
            $vi = (Get-Item -LiteralPath $CodexBinary -Force).VersionInfo
            $declared = [bool]$vi.FileVersion
            Record 'binary.pe_version' ([pscustomobject]@{ ok = $true; declared = $declared
                    fileVersion = $(if ($vi.FileVersion) { "$($vi.FileVersion)" } else { $null })
                    productVersion = $(if ($vi.ProductVersion) { "$($vi.ProductVersion)" } else { $null })
                    productName = $(if ($vi.ProductName) { "$($vi.ProductName)" } else { $null }) }) | Out-Null
        }

        # Disposable home: %TEMP%\codex-win-obs-<random>\home. The candidate
        # temp root and the real homes were validated LEXICALLY by the path
        # gate before anything was compiled or created; the creation callback
        # runs only when that gate passes again here, so a TEMP that resolves
        # inside a real Codex home never reaches CreateDirectory. The parent and
        # the home each get a protected DACL with one full-control ACE for the
        # current user SID. Real homes are never opened.
        #
        # The gate itself is LEXICAL: re-evaluating it proves only that the
        # paths still spell something outside every real home. The junction
        # check is the no-follow ancestry walk INSIDE the callback, before and
        # after the parent is created.
        #
        # Not closed: the components are opened separately by path, so this
        # compares identities at two points in time instead of pinning them.
        # That residual window is why the native modes are refused.
        $Parent = $null
        $CodexHomePath = $null
        if (-not $Abort) {
            $created = Invoke-GuardedCreate { Test-CandidateTempSafe $TempRoot $UserCodexHome $EnvCodexHome } {
                $before = Native { [WinObserver]::Ancestry($TempRoot) }
                if ($before.ok -ne $true -or $before.complete -ne $true -or
                    @($before.entries | Where-Object { $_.directory -ne $true -or $_.reparse -ne $false }).Count -gt 0) {
                    return [pscustomobject]@{ created = $false; reason = 'temp_root_ancestry_not_plain' }
                }
                $p = Join-Path $TempRoot ('codex-win-obs-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
                if (-not (Test-LocalPathSpelling $p)) { return [pscustomobject]@{ created = $false; reason = 'parent_path_spelling' } }
                if (Test-Path -LiteralPath $p) { return [pscustomobject]@{ created = $false; reason = 'name_collision' } }
                $acl = New-Object Security.AccessControl.DirectorySecurity
                $acl.SetOwner($UserSid)
                $acl.SetAccessRuleProtection($true, $false)
                $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($UserSid, $AclRights,
                            $AclInheritance, 'None', $AclType)))
                [IO.Directory]::CreateDirectory($p, $acl) | Out-Null
                # Revalidate the ancestry of the new parent before creating the
                # home inside it.
                $after = Native { [WinObserver]::Ancestry($p) }
                if ($after.ok -ne $true -or $after.complete -ne $true -or
                    @($after.entries | Where-Object { $_.directory -ne $true -or $_.reparse -ne $false }).Count -gt 0) {
                    return [pscustomobject]@{ created = $false; reason = 'parent_ancestry_not_plain'; parent = $p }
                }
                # The home gets its OWN protected DACL, not an inherited one:
                # a directory created without a security descriptor inherits
                # its parent's entries and is marked auto-inherited, never
                # protected, so `AreAccessRulesProtected` would be false and
                # the isolation contract below could never hold.
                $homeDir = Join-Path $p 'home'
                [IO.Directory]::CreateDirectory($homeDir, $acl) | Out-Null
                [pscustomobject]@{ created = $true; parent = $p; home = $homeDir }
            }
            if (-not $created.created) {
                $Abort = 'disposable CODEX_HOME refused before creation: ' + $created.reason
                Record 'home.isolated' ([pscustomobject]@{ ok = $true; state = 'unknown'; reason = $created.reason; isolated = $false }) | Out-Null
            } else {
                $Parent = $created.parent
                $CodexHomePath = $created.home
                $entries = @(Get-ChildItem -LiteralPath $CodexHomePath -Force | ForEach-Object { $_.Name })
                $o = [pscustomobject]@{ ok = $true; empty = ($entries.Count -eq 0); entries = $entries }
                $o = Add-PathFields $o $CodexHomePath $Parent
                $ancestryPlain = $null -ne $o.ancestry -and @($o.ancestry).Count -gt 0 -and
                    @($o.ancestry | Where-Object { $_.directory -ne $true -or $_.reparse -ne $false }).Count -eq 0
                $isolated = $o.userRelation -eq 'disjoint' -and ($null -eq $EnvCodexHome -or $o.envRelation -eq 'disjoint') -and
                    $o.empty -and $o.daclProtected -eq $true -and $o.parentDaclProtected -eq $true -and
                    $o.aceCount -eq 1 -and $o.parentAceCount -eq 1 -and
                    "$($o.owner)" -ceq "$UserSid" -and "$($o.parentOwner)" -ceq "$UserSid" -and
                    "$($o.aceIdentity)" -ceq "$UserSid" -and "$($o.parentAceIdentity)" -ceq "$UserSid" -and
                    $o.aceRights -ceq $AclRights -and $o.parentAceRights -ceq $AclRights -and
                    $o.aceInheritance -ceq $AclInheritance -and $o.parentAceInheritance -ceq $AclInheritance -and
                    $o.aceType -ceq $AclType -and $o.parentAceType -ceq $AclType -and
                    $null -ne $o.fileId -and $null -ne $o.parentFileId -and $ancestryPlain
                $o | Add-Member -NotePropertyName isolated -NotePropertyValue $isolated
                if ((Record 'home.isolated' $o) -ne 'match') { $Abort = 'disposable CODEX_HOME could not be verified as isolated' }
            }
        }

        if (-not $Abort) {
            # The volume probe lives in the parent, so the home stays empty.
            $probe = Join-Path $Parent '.volume-probe'
            ([IO.File]::Open($probe, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)).Dispose()
            $vols = @(Get-Volume -FilePath $probe -ErrorAction Stop)
            Record 'host.volume' ([pscustomobject]@{ ok = ($vols.Count -eq 1); probePath = $probe
                    fileSystem = $(if ($vols.Count -eq 1) { "$($vols[0].FileSystemType)" } else { $null }) }) | Out-Null
        }

        # Version: re-hash immediately before the only execution, which runs
        # with CODEX_HOME set to the disposable home and a cleared environment
        # plus a narrow allowlist. A process that does not exit within budget
        # is reported and left alone; it is never killed.
        if (-not $Abort) {
            if ((Get-Sha256Hex $CodexBinary) -cne $ExpectedSha256) {
                Record 'binary.version' ([pscustomobject]@{ ok = $false; reason = 'binary changed after hashing' }) | Out-Null
                $Abort = 'binary changed between hash and execution'
            } else {
                $psi = New-Object Diagnostics.ProcessStartInfo
                $psi.FileName = $CodexBinary
                $psi.Arguments = '--version'
                $psi.UseShellExecute = $false
                $psi.CreateNoWindow = $true
                $psi.RedirectStandardInput = $true
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                $psi.WorkingDirectory = $Parent
                # Clear the inherited environment first: no authentication,
                # proxy or credential variable of this shell reaches the child.
                $psi.EnvironmentVariables.Clear()
                $passed = @()
                foreach ($name in $ChildEnvAllowlist) {
                    $value = [Environment]::GetEnvironmentVariable($name)
                    if ($value) { $psi.EnvironmentVariables[$name] = $value; $passed += $name }
                }
                $psi.EnvironmentVariables['CODEX_HOME'] = $CodexHomePath
                $psi.EnvironmentVariables['TEMP'] = $Parent
                $psi.EnvironmentVariables['TMP'] = $Parent
                $passed += @('CODEX_HOME', 'TEMP', 'TMP')
                $p = [Diagnostics.Process]::Start($psi)
                $p.StandardInput.Close()
                # ONE monotonic deadline bounds both pipe reads and the process
                # exit. Both streams are drained concurrently with a byte cap,
                # so a descendant that inherits the pipes cannot hang this, and
                # a full pipe on one stream cannot deadlock the other. Nothing
                # is killed; an incomplete read is reported with the PID.
                $clock = [Diagnostics.Stopwatch]::StartNew()
                $outC = New-StreamChannel $p.StandardOutput.BaseStream 65536
                $errC = New-StreamChannel $p.StandardError.BaseStream 65536
                Read-BothStreams @($outC, $errC) $clock $WaitBudgetMs | Out-Null
                $exitRemaining = [int][Math]::Max(0, $WaitBudgetMs - $clock.ElapsedMilliseconds)
                $exited = $p.WaitForExit($exitRemaining)
                $streamsOk = $outC.complete -and $errC.complete -and -not $outC.truncated -and -not $errC.truncated -and
                    -not $outC.timedOut -and -not $errC.timedOut -and -not $outC.error -and -not $errC.error
                if (-not $exited -or -not $streamsOk) {
                    Record 'binary.version' ([pscustomobject]@{ ok = $false; complete = $false
                            reason = 'process or pipe did not complete inside the deadline; left running, not killed'
                            pid = $p.Id; exited = $exited
                            stdoutComplete = $outC.complete; stderrComplete = $errC.complete
                            stdoutTruncated = $outC.truncated; stderrTruncated = $errC.truncated
                            timedOut = ($outC.timedOut -or $errC.timedOut)
                            stdoutError = $outC.error; stderrError = $errC.error }) | Out-Null
                    $Abort = 'version command did not complete within budget; process ' + $p.Id + ' left running (never killed)'
                } else {
                    $first = (($outC.text -split "`n") | Select-Object -First 1)
                    if ($null -ne $first) { $first = $first.Trim() }
                    $o = [pscustomobject]@{ ok = $true; exitCode = $p.ExitCode; pid = $p.Id; stdoutFirstLine = $first
                        stdout = $outC.text; stderr = $errC.text
                        stdoutComplete = $outC.complete; stderrComplete = $errC.complete
                        stdoutTruncated = $outC.truncated; stderrTruncated = $errC.truncated
                        stdoutBytes = $outC.bytes; stderrBytes = $errC.bytes
                        timedOut = $false; exited = $true; envAllowlist = $passed
                        expected = $ExpectedVersion; matches = ($first -ceq $ExpectedVersion) }
                    if ((Record 'binary.version' $o) -ne 'match') { $Abort = 'version output differs from -ExpectedVersion' }
                    $created2 = @(Get-ChildItem -LiteralPath $CodexHomePath -Force -Recurse | ForEach-Object { $_.FullName.Substring($CodexHomePath.Length + 1) })
                    Record 'home.after_version' ([pscustomobject]@{ ok = $true; count = $created2.Count; entries = $created2 }) | Out-Null
                }
            }
        }

        $bad = @($Results | Where-Object { $_.verdict -notin @('match', 'recorded') })
        if (-not $Abort -and $bad.Count -eq 0) {
            $binaryRec = @($Results | Where-Object { $_.step -eq 'binary.sha256' })[0].observed
            $versionRec = @($Results | Where-Object { $_.step -eq 'binary.version' })[0].observed
            $homeRec = @($Results | Where-Object { $_.step -eq 'home.isolated' })[0].observed
            Record 'manifest' ([pscustomobject]@{ ok = $true; complete = $true
                    home = $homeRec.home; homeFileId = $homeRec.fileId
                    parent = $homeRec.parent; parentFileId = $homeRec.parentFileId
                    binaryPath = $binaryRec.path; binarySha256 = $binaryRec.sha256; binarySize = $binaryRec.size
                    version = $versionRec.stdoutFirstLine
                    sourceCommit = $SourceCommit; integritySid = $SelfTok.integritySid; label = $IntegrityLabel
                    harness = $Harness; createdUtc = [DateTime]::UtcNow.ToString('o') }) | Out-Null
            Write-Output ('disposable CODEX_HOME: ' + $CodexHomePath)
            Write-Output 'next: launch Codex from a new window at the same integrity level with CODEX_HOME set to that path (README, step 3), then run -Mode observe.'
        } else {
            $why = $Abort
            if (-not $why) { $why = 'non-matching steps: ' + (($bad | ForEach-Object { $_.step }) -join ',') }
            Record 'manifest' ([pscustomobject]@{ ok = $true; complete = $false; reason = $why }) | Out-Null
        }
    }

    if ($Mode -eq 'observe') {
        $h = Get-FileDigests $PSScriptRoot $HarnessNames
        $h | Add-Member -NotePropertyName manifestSha256 -NotePropertyValue $ManifestSha
        $h | Add-Member -NotePropertyName matchesManifest -NotePropertyValue (Test-SameDigests $h.files $M.harness)
        if ((Record 'harness' $h) -ne 'match') { $Abort = 'observer files differ from the preflight run' }

        $tok = $SelfTok | Select-Object *
        $tok | Add-Member -NotePropertyName integrityMatchesLabel -NotePropertyValue ($SelfTok.integritySid -eq $IntegritySids[$IntegrityLabel])
        $tok | Add-Member -NotePropertyName matchesManifest -NotePropertyValue ($SelfTok.integritySid -eq $M.integritySid -and $IntegrityLabel -eq $M.label)
        if (-not $Abort -and (Record 'token.self' $tok) -ne 'match') { $Abort = 'integrity differs from -IntegrityLabel or the preflight run' }

        # Re-validate the disposable home against the manifest before use: same
        # path, unchanged parent and home file IDs, still disjoint from the
        # current real homes, still owned by this user with the protected
        # single-ACE DACL, and a still-plain no-follow ancestry. A matching file
        # ID is necessary but NOT sufficient. Real homes are compared lexically
        # only. The structure and the paths were already validated before any
        # of them was opened.
        if (-not $Abort) {
            $CodexHomePath = $M.home
            $o = Add-PathFields ([pscustomobject]@{ ok = $true }) $CodexHomePath $M.parent
            $ancestryPlain = $null -ne $o.ancestry -and @($o.ancestry).Count -gt 0 -and
                @($o.ancestry | Where-Object { $_.directory -ne $true -or $_.reparse -ne $false }).Count -eq 0
            $homeOk = ($null -ne $o.fileId -and $o.fileId -ceq $M.homeFileId) -and
                ($null -ne $o.parentFileId -and $o.parentFileId -ceq $M.parentFileId) -and
                ($o.userRelation -eq 'disjoint') -and ($null -eq $EnvCodexHome -or $o.envRelation -eq 'disjoint') -and
                $o.daclProtected -eq $true -and $o.parentDaclProtected -eq $true -and
                $o.aceCount -eq 1 -and $o.parentAceCount -eq 1 -and
                "$($o.owner)" -ceq "$UserSid" -and "$($o.parentOwner)" -ceq "$UserSid" -and
                "$($o.aceIdentity)" -ceq "$UserSid" -and "$($o.parentAceIdentity)" -ceq "$UserSid" -and
                $o.aceRights -ceq $AclRights -and $o.parentAceRights -ceq $AclRights -and
                $o.aceInheritance -ceq $AclInheritance -and $o.parentAceInheritance -ceq $AclInheritance -and
                $o.aceType -ceq $AclType -and $o.parentAceType -ceq $AclType -and $ancestryPlain
            $o | Add-Member -NotePropertyName matchesManifest -NotePropertyValue $homeOk
            if ((Record 'home.identity' $o) -ne 'match') { $Abort = 'disposable home failed re-validation against the manifest' }
        }

        # Control record and the first process observation. The per-sample gate
        # below re-queries this PID before every sample; the first observation
        # is the creation-FILETIME witness every later record binds to.
        $create0 = $null
        $codexIntegrity0 = $null
        if (-not $Abort) {
            [WinObserver]::SetRoot($CodexHomePath)
            Record 'run' ([pscustomobject]@{ ok = $true; samples = $Samples; codexPid = $CodexPid
                    codexLabel = $CodexIntegrityLabel; observerPid = $PID; observerUserSid = "$UserSid"
                    startedUtc = [DateTime]::UtcNow.ToString('o') }) | Out-Null
            $proc = Native { [WinObserver]::ProcessIdentity($CodexPid) }
            $create0 = $proc.createFiletime
            $codexIntegrity0 = $proc.integritySid
            # Both booleans are advisory for the operator; they are recorded as
            # $null when the evidence is missing and the evaluator recomputes
            # the verdict from the raw fields either way.
            $imageMatch = $null
            if ($proc.image) { $imageMatch = [string]::Equals($proc.image, $M.binaryPath, [StringComparison]::OrdinalIgnoreCase) }
            $proc | Add-Member -NotePropertyName imageMatchesBinary -NotePropertyValue $imageMatch -Force
            $integrityMatch = $null
            if ($proc.integritySid) { $integrityMatch = ($proc.integritySid -ceq $IntegritySids[$CodexIntegrityLabel]) }
            $proc | Add-Member -NotePropertyName codexIntegrityMatchesLabel -NotePropertyValue $integrityMatch -Force
            Record 'process.identity' $proc | Out-Null
            $firstOk = ($proc.ok -eq $true) -and ([int]$proc.pid -eq $CodexPid) -and ($proc.state -eq 'live') -and
                ($imageMatch -eq $true) -and ($proc.tokenOpened -eq $true) -and ("$($proc.userSid)" -ceq "$UserSid") -and
                ($null -ne $create0) -and ($integrityMatch -eq $true)
            if (-not $firstOk) { $Abort = 'launched process is not a live, same-user match for the manifest binary at the declared integrity; active operations refused' }
        }

        if (-not $Abort) {
            $lockDir = Join-Path $CodexHomePath 'thread-writer-locks'
            $guard = Join-Path $lockDir '.coordination.lock'
            for ($s = 1; $s -le $Samples; $s++) {
                # Per-sample process gate: nothing active runs for this sample
                # unless the DECLARED PID is still the same live, same-user
                # instance. The queried record is emitted either way so the
                # evaluator can bind it; a refusal here cannot undo the
                # operations of an earlier sample.
                $collected = @{ record = $null }
                $sample = Invoke-GuardedSample {
                    Get-SampleRefusal $CodexPid $create0 $M.binaryPath "$UserSid" $codexIntegrity0 $collected
                } {
                    $ld = Native { [WinObserver]::Identity($lockDir) }
                    Record 'lockdir.identity' $ld $s | Out-Null
                    $gd = Native { [WinObserver]::Identity($guard) }
                    Record 'coordination.identity' $gd $s | Out-Null
                    # A lexically scoped path does not exclude a junction
                    # ANCESTOR, so the lock directory must be a plain
                    # non-reparse directory, and the coordination guard a
                    # single-link regular file that is not pending delete,
                    # BEFORE any enumeration or probe. Guard identity failures
                    # are consumed here, ahead of every active operation.
                    $lockDirOk = ($ld.ok -eq $true -and $ld.directory -eq $true -and $ld.reparse -eq $false -and $null -ne $ld.fileId)
                    $guardOk = ($gd.ok -eq $true -and $gd.directory -eq $false -and $gd.reparse -eq $false -and
                        $gd.links -eq 1 -and $gd.deletePending -eq $false -and $null -ne $gd.fileId)
                    if (-not $lockDirOk -or -not $guardOk) {
                        $why = $(if (-not $lockDirOk) { 'lock_directory_not_plain' } else { 'coordination_guard_not_single_regular' })
                        Record 'thread.count' ([pscustomobject]@{ ok = $true; state = 'unknown'; reason = $why }) $s | Out-Null
                        return
                    }
                    $threads = @()
                    try {
                        $names = @([IO.Directory]::GetFileSystemEntries($lockDir) | ForEach-Object { Split-Path $_ -Leaf })
                        $threads = @($names | Where-Object { $_ -ne '.coordination.lock' -and $_ -like '*.lock' })
                        Record 'thread.count' ([pscustomobject]@{ ok = $true; count = $threads.Count; entries = $names }) $s | Out-Null
                    } catch {
                        Record 'thread.count' ([pscustomobject]@{ ok = $false; exception = $_.Exception.Message }) $s | Out-Null
                    }
                    if ($threads.Count -ne 1) { return }
                    $leaf = $threads[0]
                    $thread = Join-Path $lockDir $leaf
                    $before = Native { [WinObserver]::Identity($thread) }
                    Record 'thread.identity' $before $s | Out-Null
                    # Thread identity gate: a reparse point, a directory, a
                    # hardlinked (links != 1) or pending-delete lock file
                    # refuses the RM/share/range operations for this sample.
                    $threadOk = ($before.ok -eq $true -and $before.reparse -eq $false -and $before.directory -eq $false -and
                        $before.links -eq 1 -and $before.deletePending -eq $false -and $null -ne $before.fileId)
                    if (-not $threadOk) { return }
                    $rm = Native { [WinObserver]::RmList([string[]]@($thread, $guard)) }
                    if ($rm.ok -eq $true -and $rm.complete -eq $true) {
                        foreach ($entry in @($rm.processes)) {
                            $entry | Add-Member -NotePropertyName role -NotePropertyValue (
                                Get-OpenerRole ([int]$entry.pid) "$($entry.startFiletime)" $CodexPid "$create0" $PID)
                        }
                    }
                    Record 'openers.rm' $rm $s | Out-Null
                    # Only full-sharing opens; restrictive-sharing probes are a
                    # separately proposed, NOT-executed experiment (see README).
                    Record 'share.read_rwd' (Native { [WinObserver]::ShareProbe($thread, 'read', 'rwd') }) $s | Out-Null
                    Record 'share.delete_rwd' (Native { [WinObserver]::ShareProbe($thread, 'delete', 'rwd') }) $s | Out-Null
                    # Bind the guarded range probe to the validated expected
                    # identities (lock directory, coordination guard and thread
                    # lock) so it refuses a changed target before locking. The
                    # expected link count is fixed at one inside the native
                    # layer and is not passed from here.
                    Record 'range.probe' (Native {
                            [WinObserver]::GuardedRangeProbe($lockDir, $leaf, $ld.fileId, $gd.fileId, $before.fileId)
                        }) $s | Out-Null
                    $after = Native { [WinObserver]::Identity($thread) }
                    if ($after.ok -eq $true -and $before.ok -eq $true) {
                        $after | Add-Member -NotePropertyName sameFileId -NotePropertyValue ($null -ne $after.fileId -and $after.fileId -ceq $before.fileId)
                    }
                    Record 'thread.identity_after' $after $s | Out-Null
                }
                # The re-queried process record is always emitted, with the
                # refusal reason when the gate stopped this sample.
                $gateRecord = $collected.record
                if ($null -eq $gateRecord) { $gateRecord = [pscustomobject]@{ ok = $false; reason = 'process_not_queried' } }
                if (-not $sample.ran) { $gateRecord | Add-Member -NotePropertyName refused -NotePropertyValue $sample.reason -Force }
                Record 'process.sample' $gateRecord $s | Out-Null
                if ($s -lt $Samples) { Start-Sleep -Milliseconds 500 }
            }
            # A fresh handle, not the one used above; identity is sampled, never pinned.
            $proc2 = Native { [WinObserver]::ProcessIdentity($CodexPid) }
            if ($proc2.PSObject.Properties['createFiletime']) {
                $proc2 | Add-Member -NotePropertyName sameCreate -NotePropertyValue ($null -ne $create0 -and "$($proc2.createFiletime)" -ceq "$create0")
            }
            Record 'process.identity_after' $proc2 | Out-Null
        }
    }
}
catch {
    $OrchestratorFailed = $true
    Record 'orchestrator_error' ([pscustomobject]@{ ok = $false; exception = $_.Exception.Message }) | Out-Null
}
finally {
    # New file only; never overwrite. UTF-8 without BOM, one JSON object per line.
    $fs = $null
    $sw = $null
    $written = $false
    try {
        $lines = $Results | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 10 }
        $fs = New-Object IO.FileStream($OutFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $sw = New-Object IO.StreamWriter($fs, $Utf8)
        foreach ($l in $lines) { $sw.Write($l); $sw.Write("`n") }
        $sw.Flush()
        $written = $true
    } catch {
        $OrchestratorFailed = $true
        Write-Output ('results write error: ' + $_.Exception.Message)
    } finally {
        foreach ($resource in @($sw, $fs)) {
            if ($null -ne $resource) { try { $resource.Dispose() } catch { $OrchestratorFailed = $true; $written = $false } }
        }
    }
    if ($written) { Write-Output ('results: ' + $OutFile) }
    if ($Abort) { Write-Output ('aborted: ' + $Abort) }
    $counts = @{}
    foreach ($r in $Results) { $counts[$r.verdict] = 1 + [int]$counts[$r.verdict] }
    Write-Output ('verdicts: ' + (($counts.Keys | Sort-Object | ForEach-Object { "$_=$($counts[$_])" }) -join ' '))
    $code = 0
    if ($counts['mismatch']) { $code = 1 }
    if ($counts['incomplete'] -or $counts['error'] -or $counts['unknown'] -or $OrchestratorFailed -or -not $written -or ($Abort -and $code -eq 0)) { $code = 2 }
    exit $code
}
