<#
Fixture-only Windows lock observation lab for codex-unlock research (#122).

Windows PowerShell 5.1, no compiler install: WinLockLab.cs is compiled by
Add-Type in each process. The orchestrator creates one new private scratch
directory under %TEMP%, starts agent processes it owns, and drives them with a
line protocol. It never touches CODEX_HOME and never terminates or signals a
process. Every result is observation evidence; safeToUnlock is always false.

  powershell -NoProfile -NonInteractive -File lab.ps1 -OutFile <new file outside %TEMP%\codex-unlock-lab-*>

The host's existing execution policy applies. If it blocks the script, the run
stops; changing the policy is a separate decision and is not done here.

Exit codes: 0 = every hypothesis matched and every agent exited;
1 = at least one mismatch; 2 = incomplete, error, or an agent still running;
3 = refused before any fixture was created.
#>
param(
    [ValidateSet('run', 'agent')][string]$Role = 'run',
    [string]$OutFile,
    [string]$Root,
    [ValidateRange(0, 600000)][int]$ReadyBudgetMs = 60000,
    [ValidateRange(0, 600000)][int]$WaitBudgetMs = 15000,
    [ValidateRange(0, 3600)][int]$TotalBudgetSec = 600
)
$ErrorActionPreference = 'Stop'

if ($Role -eq 'agent') {
    Add-Type -Path (Join-Path $PSScriptRoot 'WinLockLab.cs')
    [WinLockLab]::SetRoot($Root)
    # One JSON line per command. "exit" or stdin EOF (parent gone) disposes
    # every fixture handle and ends the process normally.
    [Console]::Out.WriteLine('{"ready":true,"pid":' + $PID + ',"start":' + [WinLockLab]::SelfStartFiletime() + '}')
    [Console]::Out.Flush()
    # The parent writes UTF-8 bytes, independently of the host console code page.
    $inputReader = New-Object IO.StreamReader([Console]::OpenStandardInput(), (New-Object Text.UTF8Encoding($false, $true)))
    try {
        while ($null -ne ($line = $inputReader.ReadLine())) {
            if ($line -eq 'exit') { break }
            [Console]::Out.WriteLine([WinLockLab]::Execute($line))
            [Console]::Out.Flush()
        }
    } finally {
        [WinLockLab]::DisposeAll()
        $inputReader.Dispose()
    }
    exit 0
}

# ---- Preflight: nothing is created until these pass ------------------------
function Resolve-Full([string]$p) {
    [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p))
}

function Test-Inside([string]$path, [string]$dir) {
    $d = $dir.TrimEnd('\')
    [string]::Equals($path, $d, [StringComparison]::OrdinalIgnoreCase) -or
        $path.StartsWith($d + '\', [StringComparison]::OrdinalIgnoreCase)
}

$TempRoot = Resolve-Full $env:TEMP
$volumeCommand = Get-Command Get-Volume -ErrorAction SilentlyContinue
if ($null -eq $volumeCommand -or -not $volumeCommand.Parameters.ContainsKey('FilePath')) {
    Write-Output 'refused: Storage Get-Volume -FilePath is required to identify the scratch volume'; exit 3
}
if (-not $OutFile) { Write-Output 'refused: -OutFile is required (new file outside the scratch directory)'; exit 3 }
$OutFile = Resolve-Full $OutFile
if (Test-Path -LiteralPath $OutFile) { Write-Output "refused: $OutFile already exists"; exit 3 }
if (-not (Test-Path -LiteralPath (Split-Path $OutFile -Parent) -PathType Container)) { Write-Output 'refused: -OutFile parent directory does not exist'; exit 3 }
# Any path under %TEMP%\codex-unlock-lab-* could be a scratch directory that cleanup removes.
if ((Split-Path $OutFile -Parent) -like (Join-Path $TempRoot 'codex-unlock-lab-*') -or
    $OutFile -like (Join-Path $TempRoot 'codex-unlock-lab-*\*')) {
    Write-Output 'refused: -OutFile must not be inside a codex-unlock-lab scratch directory'; exit 3
}

Add-Type -Path (Join-Path $PSScriptRoot 'WinLockLab.cs')

# Monotonic budget. It bounds the waits this script performs (reads, exit
# waits, stderr collection). It does not bound Add-Type, Process.Start,
# synchronous file I/O, or cleanup, so it is not a hard wall-clock cap.
$Clock = [Diagnostics.Stopwatch]::StartNew()
$TotalMs = [int64]$TotalBudgetSec * 1000
function Remaining([int]$cap) {
    $left = $TotalMs - $Clock.ElapsedMilliseconds
    if ($left -lt 0) { $left = 0 }
    [int][Math]::Max(0, [Math]::Min([int64][int]::MaxValue, [Math]::Min([int64]$cap, $left)))
}

# Private scratch: created with a protected DACL granting only the current
# user SID full control, then read back. This narrows access by other
# non-admin principals; it does not claim to exclude administrators or
# SeBackup/SeRestore/SeTakeOwnership privileges.
$UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$Scratch = Join-Path $TempRoot ('codex-unlock-lab-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
# CreateDirectory does not apply the ACL to an existing directory.
if (Test-Path -LiteralPath $Scratch) { Write-Output 'refused: scratch name collision'; exit 3 }
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($UserSid)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($UserSid, 'FullControl',
            'ContainerInherit, ObjectInherit', 'None', 'Allow')))
try {
    [IO.Directory]::CreateDirectory($Scratch, $acl) | Out-Null
    $back = Get-Acl -LiteralPath $Scratch
    $rules = @($back.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $ScratchId = [WinLockLab]::DirFileId($Scratch)
    if (-not $back.AreAccessRulesProtected -or $rules.Count -ne 1 -or $rules[0].IdentityReference -ne $UserSid -or
        $rules[0].AccessControlType -ne 'Allow' -or $null -eq $ScratchId) {
        throw 'scratch DACL or identity verification failed'
    }
} catch {
    Write-Output ('refused: private scratch could not be established: ' + $_.Exception.Message)
    if ((Test-Path -LiteralPath $Scratch) -and $null -ne [WinLockLab]::DirFileId($Scratch) -and
        @(Get-ChildItem -LiteralPath $Scratch -Force).Count -eq 0) {
        [IO.Directory]::Delete($Scratch, $false)
    }
    exit 3
}

$Results = New-Object System.Collections.Generic.List[object]
$Agents = New-Object System.Collections.Generic.List[object]
$Junctions = New-Object System.Collections.Generic.List[string]
$ThreadName = '00000000-0000-4000-8000-000000000001.lock'
$OrchestratorFailed = $false
$Utf8 = New-Object Text.UTF8Encoding($false)

# Each agent keeps at most one outstanding read or write. A timed-out operation
# is kept (StreamReader allows one outstanding read) and the agent is marked
# stalled; nothing more is written to it.
function Read-AgentLine($a, [int]$cap) {
    if ($a.Stalled) { return $null }
    try {
        if ($null -eq $a.Pending) { $a.Pending = $a.Proc.StandardOutput.ReadLineAsync() }
        if (-not $a.Pending.Wait((Remaining $cap))) { $a.Stalled = $true; return $null }
        $line = $a.Pending.Result
    } catch {
        $a.Stalled = $true
        return $null
    }
    $a.Pending = $null
    $line
}

function Send-AgentLine($a, [string]$text) {
    if ($a.Stalled -or $a.Exited) { return $false }
    $bytes = $Utf8.GetBytes($text + "`n")
    try {
        $stream = $a.Proc.StandardInput.BaseStream
        $t = $stream.WriteAsync($bytes, 0, $bytes.Length)
        if (-not $t.Wait((Remaining $WaitBudgetMs))) { $a.Stalled = $true; return $false }
        $f = $stream.FlushAsync()
        if (-not $f.Wait((Remaining $WaitBudgetMs))) { $a.Stalled = $true; return $false }
    } catch {
        # Broken pipe (agent already gone) or faulted task.
        $a.Stalled = $true
        return $false
    }
    $true
}

function Start-Agent([string]$name) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $PSHOME 'powershell.exe'
    $psi.Arguments = '-NoProfile -NonInteractive -File "' + $PSCommandPath + '" -Role agent -Root "' + $Scratch + '"'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $Utf8
    $p = [System.Diagnostics.Process]::Start($psi)
    # Drain stderr for the whole lifetime so a full pipe cannot block the agent.
    $a = [pscustomobject]@{ Name = $name; Proc = $p; Pending = $null; Stalled = $false; Pid = $p.Id; Start = $null
        StdErr = $p.StandardError.ReadToEndAsync(); Exited = $false }
    $Agents.Add($a)
    $ready = Read-AgentLine $a $ReadyBudgetMs
    if ($null -eq $ready) { throw "agent $name did not report ready" }
    $a.Start = [long](($ready | ConvertFrom-Json).start)
    $a
}

function Invoke-Agent($a, [string[]]$argv) {
    if (-not (Send-AgentLine $a ($argv -join "`t"))) { return $null }
    $line = Read-AgentLine $a $WaitBudgetMs
    if ($null -eq $line) { return $null }
    $line | ConvertFrom-Json
}

# Normal shutdown only: "exit", close stdin, bounded wait. A stalled agent gets
# no write; its stdin is closed so EOF ends it. A process that does not exit is
# reported as still running; it is never killed.
function Stop-Agent($a) {
    if ($a.Exited) { return }
    Send-AgentLine $a 'exit' | Out-Null
    try { $a.Proc.StandardInput.BaseStream.Dispose() } catch { }
    if ($a.Proc.WaitForExit((Remaining $WaitBudgetMs))) {
        $a.Exited = $true
        Record 'lifecycle' "stop:$($a.Name)" @{ exitCode = 0 } ([pscustomobject]@{ exitCode = $a.Proc.ExitCode })
    } else {
        Record 'lifecycle' "stop:$($a.Name)" @{ exited = $true } $null
    }
}

# Verdicts: incomplete (no observation) is checked before anything else. An
# observation without a hypothesis is "recorded" only when it reports success;
# ok=false, complete=false, or an exception is "error".
function Test-Expect($observed, $expect) {
    if ($null -eq $observed) { return 'incomplete' }
    if ($null -eq $expect) {
        if ($observed.PSObject.Properties['exception'] -or $observed.ok -eq $false -or $observed.complete -eq $false) { return 'error' }
        return 'recorded'
    }
    foreach ($k in $expect.Keys) {
        if ("$($observed.$k)" -ne "$($expect[$k])") { return 'mismatch' }
    }
    'match'
}

function Record([string]$scenario, [string]$step, $expect, $observed) {
    $Results.Add([pscustomobject]@{
            scenario = $scenario; step = $step
            expect = $expect; observed = $observed
            verdict = Test-Expect $observed $expect
            safeToUnlock = $false
        })
}

# Setup steps are recorded too, so every test condition has evidence that it held.
function Setup([string]$scenario, [string]$step, $a, [string[]]$argv) {
    $o = Invoke-Agent $a $argv
    $expect = @{ ok = $true }
    if ($argv[0] -eq 'lock') { $expect = @{ ok = $true; locked = $true } }
    Record $scenario "setup:$step" $expect $o
}

function New-LockDir([string]$name, [switch]$NoGuard, [switch]$NoThread) {
    $d = Join-Path $Scratch "$name\thread-writer-locks"
    New-Item -ItemType Directory -Path $d | Out-Null
    if (-not $NoGuard) { [IO.File]::WriteAllBytes((Join-Path $d '.coordination.lock'), [byte[]]@()) }
    if (-not $NoThread) { [IO.File]::WriteAllBytes((Join-Path $d $ThreadName), [byte[]]@()) }
    $d
}

function Label-Rm($observed) {
    if ($null -eq $observed -or $observed.ok -ne $true -or $observed.complete -ne $true) { return $observed }
    foreach ($p in @($observed.processes)) {
        $role = 'other'
        if ($p.pid -eq $PID) { $role = 'orchestrator' }
        foreach ($a in $Agents) { if ($p.pid -eq $a.Pid -and $p.startFiletime -eq $a.Start) { $role = $a.Name } }
        $p | Add-Member -NotePropertyName role -NotePropertyValue $role
    }
    # An empty list is a normal observation, distinct from a missing response.
    $observed | Add-Member -NotePropertyName count -NotePropertyValue @($observed.processes).Count
    $observed | Add-Member -NotePropertyName interpretation -NotePropertyValue 'opener_candidates_only'
    $observed
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    # Resolve the volume from this actual path, including volume mount points.
    $volumeProbe = Join-Path $Scratch '.volume-probe'
    $volumeProbeStream = [IO.File]::Open($volumeProbe, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $volumeProbeStream.Dispose()
    $scratchVolumes = @(Get-Volume -FilePath $volumeProbe -ErrorAction Stop)
    if ($scratchVolumes.Count -ne 1 -or -not $scratchVolumes[0].FileSystemType) {
        throw 'scratch volume could not be identified uniquely'
    }
    Record 'environment' 'host' $null ([pscustomobject]@{
            ok = $true
            os = [Environment]::OSVersion.VersionString; ps = $PSVersionTable.PSVersion.ToString()
            integrity = (whoami /groups | Select-String 'S-1-16-' | Select-Object -First 1).ToString().Trim()
            elevated = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole('Administrators')
            executionPolicy = (Get-ExecutionPolicy).ToString()
            fs = $scratchVolumes[0].FileSystemType
            scratchDacl = 'protected, current user SID only'
            note = 'results apply only to this token/integrity; source semantics pinned to Rust std 1.95 (Codex 0.162.1 and 0.155.1 writer_lock.rs identical); installed Codex binaries not exercised'
        })

    $W = Start-Agent 'writer'
    $P = Start-Agent 'prober'
    $O = Start-Agent 'opener'
    $probe = { param($dir, $policy) Invoke-Agent $P @('probe', $dir, $ThreadName, $policy) }

    # ---- E1: guarded probe states -------------------------------------------
    $d = New-LockDir 'e1-free'
    Record 'E1' 'free' @{ state = 'free' } (& $probe $d 'nofollow')

    $d = New-LockDir 'e1-absent' -NoThread
    Record 'E1' 'absent' @{ state = 'absent' } (& $probe $d 'nofollow')

    $d = New-LockDir 'e1-missing-guard' -NoGuard
    Record 'E1' 'missing_guard' @{ state = 'unknown'; reason = 'missing_guard' } (& $probe $d 'nofollow')

    $d = New-LockDir 'e1-busy'
    Setup 'E1' 'busy:open_guard' $W @('open', 'g', (Join-Path $d '.coordination.lock'), 'rwd', 'nofollow')
    Setup 'E1' 'busy:lock_guard' $W @('lock', 'g', 'rust')
    Record 'E1' 'busy_guard' @{ state = 'unknown'; reason = 'busy_guard' } (& $probe $d 'nofollow')
    Setup 'E1' 'busy:close_guard' $W @('close', 'g')

    $d = New-LockDir 'e1-held'
    Setup 'E1' 'held:open_thread' $W @('open', 't', (Join-Path $d $ThreadName), 'rwd', 'nofollow')
    Setup 'E1' 'held:lock_thread' $W @('lock', 't', 'rust')
    Record 'E1' 'held' @{ state = 'held' } (& $probe $d 'nofollow')
    Setup 'E1' 'held:close_thread' $W @('close', 't')
    Record 'E1' 'held:after_writer_close' @{ state = 'free' } (& $probe $d 'nofollow')

    # ---- E1: range compatibility matrix (Rust std vs fs-ext) ------------------
    foreach ($x in 'rust', 'fsext') {
        foreach ($y in 'rust', 'fsext') {
            $d = New-LockDir "e1-range-$x-$y" -NoGuard
            $f = Join-Path $d $ThreadName
            Setup 'E1' "range:${x}-${y}:open_holder" $W @('open', 't', $f, 'rwd', 'nofollow')
            Setup 'E1' "range:${x}-${y}:lock_holder" $W @('lock', 't', $x)
            Setup 'E1' "range:${x}-${y}:open_try" $P @('open', 't', $f, 'rwd', 'nofollow')
            Record 'E1' "range:$x-held/$y-try" @{ ok = $true; locked = $false; win32 = 33 } (Invoke-Agent $P @('lock', 't', $y))
            Setup 'E1' "range:${x}-${y}:close_try" $P @('close', 't')
            Setup 'E1' "range:${x}-${y}:close_holder" $W @('close', 't')
        }
    }

    # ---- E1: SHARE_DELETE, open-handle phase vs after-last-close phase -------
    foreach ($share in 'rwd', 'rw') {
        $d = New-LockDir "e1-share-$share" -NoGuard
        $f = Join-Path $d $ThreadName
        Setup 'E1' "share:${share}:open_writer" $W @('open', 't', $f, 'rwd', 'nofollow')
        Setup 'E1' "share:${share}:lock_writer" $W @('lock', 't', 'rust')
        Setup 'E1' "share:${share}:open_prober" $P @('open', 't', $f, $share, 'nofollow')
        # Writer Drop order: close its own handle, then DeleteFileW, while the prober handle is still open.
        Setup 'E1' "share:${share}:close_writer" $W @('close', 't')
        $expect = $null
        if ($share -eq 'rw') { $expect = @{ ok = $false; win32 = 32 } }
        Record 'E1' "share:${share}:delete_while_prober_open" $expect (Invoke-Agent $W @('delete', $f))
        Setup 'E1' "share:${share}:close_prober" $P @('close', 't')
        $exists = Test-Path -LiteralPath $f
        Record 'E1' "share:${share}:exists_after_last_close" $null ([pscustomobject]@{ ok = $true; exists = $exists })
        if ($exists) {
            # Separate phase: no handle remains, so a failure here is not attributed to share mode.
            Record 'E1' "share:${share}:delete_after_last_close" $null (Invoke-Agent $W @('delete', $f))
        }
    }

    # ---- E1: mandatory byte-range read, data bytes vs empty file -------------
    $d = New-LockDir 'e1-read' -NoGuard -NoThread
    $data = Join-Path $d 'data.bin'
    [IO.File]::WriteAllBytes($data, [byte[]](1..16))
    $empty = Join-Path $d 'empty.bin'
    [IO.File]::WriteAllBytes($empty, [byte[]]@())
    foreach ($case in @(@($data, @{ ok = $false; win32 = 33 }), @($empty, @{ ok = $false; win32 = 33 }))) {
        $leaf = Split-Path $case[0] -Leaf
        Setup 'E1' "read:${leaf}:open_writer" $W @('open', 't', $case[0], 'rwd', 'nofollow')
        Setup 'E1' "read:${leaf}:lock_writer" $W @('lock', 't', 'rust')
        Setup 'E1' "read:${leaf}:open_reader" $P @('open', 'r', $case[0], 'rwd', 'nofollow')
        # The Windows 10 NTFS fixture returned lock violation even for an empty file.
        # Require an actual error 33, never infer a violation from a zero-byte EOF read.
        Record 'E1' "read_locked:$leaf" $case[1] (Invoke-Agent $P @('read', 'r', '16'))
        Setup 'E1' "read:${leaf}:close_reader" $P @('close', 'r')
        Setup 'E1' "read:${leaf}:close_writer" $W @('close', 't')
    }

    # ---- E1: explicit no-follow / identity policy ----------------------------
    $d = New-LockDir 'e1-thread-dir' -NoThread
    New-Item -ItemType Directory -Path (Join-Path $d $ThreadName) | Out-Null
    Record 'E1' 'thread_is_directory' @{ state = 'unknown' } (& $probe $d 'nofollow')

    $real = New-LockDir 'e1-junction-real'
    $j = Join-Path $Scratch 'e1-junction-link'
    New-Item -ItemType Junction -Path $j -Target $real | Out-Null
    $Junctions.Add($j)
    Record 'E1' 'junction:nofollow' @{ state = 'unknown'; reason = 'directory_reparse_or_unreadable' } (& $probe $j 'nofollow')
    # Negative control: without the policy the API follows the junction and reports free.
    Record 'E1' 'junction:follow_control' @{ state = 'free' } (& $probe $j 'follow')

    $d = New-LockDir 'e1-guard-exclusive'
    Setup 'E1' 'guard_exclusive:open' $W @('open', 'g', (Join-Path $d '.coordination.lock'), '-', 'nofollow')
    Record 'E1' 'guard_sharing_violation' @{ state = 'unknown'; reason = 'guard_open'; win32 = 32 } (& $probe $d 'nofollow')
    Setup 'E1' 'guard_exclusive:close' $W @('close', 'g')

    # ---- E3: Restart Manager opener evidence ---------------------------------
    $d = New-LockDir 'e3'
    $f = Join-Path $d $ThreadName
    $rm = { Label-Rm (Invoke-Agent $P @('rm', $f)) }
    Record 'E3' 'none' $null (& $rm)
    Setup 'E3' 'open_holder' $W @('open', 't', $f, 'rwd', 'nofollow')
    Setup 'E3' 'lock_holder' $W @('lock', 't', 'rust')
    Record 'E3' 'holder' $null (& $rm)
    Setup 'E3' 'open_opener' $O @('open', 't', $f, 'rwd', 'nofollow')
    Record 'E3' 'holder+opener' $null (& $rm)
    Setup 'E3' 'open_self' $P @('open', 's', $f, 'rwd', 'nofollow')
    Record 'E3' 'holder+opener+self' $null (& $rm)
    Setup 'E3' 'close_self' $P @('close', 's')
    Setup 'E3' 'close_holder' $W @('close', 't')
    Record 'E3' 'opener_only' $null (& $rm)
    Setup 'E3' 'close_opener' $O @('close', 't')

    $H = Start-Agent 'exiting-holder'
    Setup 'E3' 'open_exiting_holder' $H @('open', 't', $f, 'rwd', 'nofollow')
    Setup 'E3' 'lock_exiting_holder' $H @('lock', 't', 'rust')
    Stop-Agent $H
    for ($i = 0; $i -lt 5; $i++) {
        Record 'E3' "after_holder_exit:$i" $null (& $rm)
        Record 'E3' "after_holder_exit_probe:$i" $null (& $probe $d 'nofollow')
        Start-Sleep -Milliseconds 200
    }

    # ---- Bounded identity-change fixture (no PID-reuse spawning) -------------
    $C = Start-Agent 'identity-target'
    Record 'identity' 'live' @{ state = 'live_same_user' } (Invoke-Agent $P @('procid', "$($C.Pid)", "$($C.Start)"))
    Record 'identity' 'start_mismatch' @{ state = 'identity_changed' } (Invoke-Agent $P @('procid', "$($C.Pid)", "$($C.Start + 1)"))
    Stop-Agent $C
    # The orchestrator still holds a handle to C, so the process object stays
    # openable; liveness must come from waiting on the probe's own handle.
    Record 'identity' 'after_exit' @{ state = 'exited' } (Invoke-Agent $P @('procid', "$($C.Pid)", "$($C.Start)"))
}
catch {
    $OrchestratorFailed = $true
    Record 'lifecycle' 'orchestrator_error' @{ ok = $true } ([pscustomobject]@{ ok = $false; error = $_.Exception.Message })
}
finally {
    $FinalizationFailed = $false
    foreach ($a in $Agents) {
        try { Stop-Agent $a } catch {
            $FinalizationFailed = $true
            Record 'lifecycle' "stop_error:$($a.Name)" $null ([pscustomobject]@{ ok = $false; error = $_.Exception.Message })
        }
    }
    $running = @($Agents | Where-Object { -not $_.Exited })
    foreach ($a in $Agents) {
        try {
            if ($a.Exited) {
                if (-not $a.StdErr.Wait((Remaining 1000))) {
                    Record 'lifecycle' "stderr:$($a.Name)" @{ empty = $true } $null
                } elseif ($a.StdErr.Result) {
                    Record 'lifecycle' "stderr:$($a.Name)" @{ empty = $true } ([pscustomobject]@{ empty = $false; text = $a.StdErr.Result })
                }
            }
        } catch {
            $FinalizationFailed = $true
            Record 'lifecycle' "stderr_error:$($a.Name)" $null ([pscustomobject]@{ ok = $false; error = $_.Exception.Message })
        }
    }

    # New file only; never overwrite. UTF-8 without BOM, one JSON object per line.
    $fs = $null
    $sw = $null
    $ResultsWritten = $false
    try {
        $lines = $Results | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 }
        $fs = New-Object IO.FileStream($OutFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $sw = New-Object IO.StreamWriter($fs, $Utf8)
        foreach ($l in $lines) { $sw.Write($l); $sw.Write("`n") }
        $sw.Flush()
        $ResultsWritten = $true
    } catch {
        $FinalizationFailed = $true
        Write-Output ('results write error: ' + $_.Exception.Message)
        Record 'lifecycle' 'results_write_error' $null ([pscustomobject]@{ ok = $false; error = $_.Exception.Message })
    } finally {
        foreach ($resource in @($sw, $fs)) {
            if ($null -ne $resource) {
                try { $resource.Dispose() } catch {
                    $FinalizationFailed = $true
                    $ResultsWritten = $false
                    Write-Output ('results close error: ' + $_.Exception.Message)
                    Record 'lifecycle' 'results_close_error' $null ([pscustomobject]@{ ok = $false; error = $_.Exception.Message })
                }
            }
        }
    }
    if ($ResultsWritten) { Write-Output ('results: ' + $OutFile) }

    # Cleanup only when every agent exited, junction links were removed as
    # links, and the scratch directory still has the identity it was created with.
    $preserve = $null
    if ($FinalizationFailed -or -not $ResultsWritten) { $preserve = 'finalization failed; results may be absent or incomplete' }
    if ($running.Count -gt 0) { $preserve = 'agents still running: ' + (($running | ForEach-Object { $_.Pid }) -join ',') }
    try {
        if (-not $preserve) {
            foreach ($j in $Junctions) { [IO.Directory]::Delete($j, $false) }
        }
        if (-not $preserve -and [WinLockLab]::DirFileId($Scratch) -ne $ScratchId) { $preserve = 'scratch identity changed or unverifiable' }
        if (-not $preserve -and (Test-Inside $OutFile $Scratch)) { $preserve = 'results file inside scratch' }
        if (-not $preserve) {
            Remove-Item -LiteralPath $Scratch -Recurse -Force
            Write-Output ('scratch removed: ' + $Scratch)
        }
    } catch {
        $FinalizationFailed = $true
        $preserve = 'cleanup failed: ' + $_.Exception.Message
        Record 'lifecycle' 'cleanup_error' $null ([pscustomobject]@{ ok = $false; error = $_.Exception.Message })
    }
    if ($preserve) {
        $FinalizationFailed = $true
        Write-Output ("scratch preserved ($preserve): " + $Scratch)
    }

    $counts = @{}
    foreach ($r in $Results) { $counts[$r.verdict] = 1 + [int]$counts[$r.verdict] }
    Write-Output ('verdicts: ' + (($counts.Keys | Sort-Object | ForEach-Object { "$_=$($counts[$_])" }) -join ' '))
    $code = 0
    if ($counts['mismatch']) { $code = 1 }
    if ($counts['incomplete'] -or $counts['error'] -or $running.Count -gt 0 -or $OrchestratorFailed -or $FinalizationFailed) { $code = 2 }
    exit $code
}
