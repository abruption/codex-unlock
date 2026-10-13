<#
Fixture-only Windows lock observation lab for codex-unlock research (#122).

Windows PowerShell 5.1, no compiler install: WinLockLab.cs is compiled by
Add-Type in each process. The orchestrator creates one new scratch directory
under %TEMP%, starts agent processes it owns, and drives them with a line
protocol. It never touches CODEX_HOME, never terminates or signals a process,
and never deletes anything outside its scratch directory. Every result is
observation evidence; safeToUnlock is always false.

  powershell -NoProfile -ExecutionPolicy Bypass -File lab.ps1 [-OutFile path]

-ExecutionPolicy Bypass applies to that one process only.
#>
param(
    [ValidateSet('run', 'agent')][string]$Role = 'run',
    [string]$OutFile,
    [int]$ReadyBudgetMs = 60000,
    [int]$WaitBudgetMs = 15000,
    [int]$TotalBudgetSec = 600
)
$ErrorActionPreference = 'Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'WinLockLab.cs')

if ($Role -eq 'agent') {
    # One JSON line per command. EOF on stdin or "exit" ends the process normally.
    [Console]::Out.WriteLine('{"ready":true,"pid":' + $PID + ',"start":' + [WinLockLab]::SelfStartFiletime() + '}')
    [Console]::Out.Flush()
    while ($null -ne ($line = [Console]::In.ReadLine())) {
        if ($line -eq 'exit') { break }
        [Console]::Out.WriteLine([WinLockLab]::Execute($line))
        [Console]::Out.Flush()
    }
    exit 0
}

$Deadline = (Get-Date).AddSeconds($TotalBudgetSec)
$Scratch = Join-Path $env:TEMP ('codex-unlock-lab-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
New-Item -ItemType Directory -Path $Scratch | Out-Null
if (-not $OutFile) { $OutFile = Join-Path $Scratch 'results.jsonl' }
$Results = New-Object System.Collections.Generic.List[object]
$Agents = New-Object System.Collections.Generic.List[object]
$Junctions = New-Object System.Collections.Generic.List[string]
$ThreadName = '00000000-0000-4000-8000-000000000001.lock'

function Remaining([int]$cap) {
    $left = [int]($Deadline - (Get-Date)).TotalMilliseconds
    if ($left -lt 0) { $left = 0 }
    [Math]::Min($cap, $left)
}

# Each agent keeps at most one pending ReadLineAsync. A timed-out read is kept
# (StreamReader allows one outstanding read) and the agent is marked stalled;
# no further commands are sent to a stalled agent.
function Read-AgentLine($a, [int]$cap) {
    if ($a.Stalled) { return $null }
    if ($null -eq $a.Pending) { $a.Pending = $a.Proc.StandardOutput.ReadLineAsync() }
    if (-not $a.Pending.Wait((Remaining $cap))) { $a.Stalled = $true; return $null }
    $line = $a.Pending.Result
    $a.Pending = $null
    $line
}

function Start-Agent([string]$name) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Get-Command powershell.exe).Source
    $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Role agent'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
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
    if ($a.Stalled -or $a.Exited) { return $null }
    $a.Proc.StandardInput.WriteLine(($argv -join "`t"))
    $a.Proc.StandardInput.Flush()
    $line = Read-AgentLine $a $WaitBudgetMs
    if ($null -eq $line) { return $null }
    $line | ConvertFrom-Json
}

# Normal shutdown only: "exit", close stdin, bounded wait. A process that does
# not exit is reported as still running; it is never killed.
function Stop-Agent($a) {
    if ($a.Exited) { return }
    try { $a.Proc.StandardInput.WriteLine('exit'); $a.Proc.StandardInput.Close() } catch { }
    if ($a.Proc.WaitForExit((Remaining $WaitBudgetMs))) {
        $a.Exited = $true
        Record 'lifecycle' "stop:$($a.Name)" $null ([pscustomobject]@{ exitCode = $a.Proc.ExitCode })
    } else {
        Record 'lifecycle' "stop:$($a.Name)" $null ([pscustomobject]@{ incomplete = $true; stillRunningPid = $a.Pid })
    }
}

function Test-Expect($observed, $expect) {
    if ($null -eq $expect) { return 'recorded' }
    if ($null -eq $observed) { return 'incomplete' }
    foreach ($k in $expect.Keys) {
        $v = $observed.$k
        if ("$v" -ne "$($expect[$k])") { return 'mismatch' }
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

function New-LockDir([string]$name, [switch]$NoGuard, [switch]$NoThread) {
    $d = Join-Path $Scratch "$name\thread-writer-locks"
    New-Item -ItemType Directory -Path $d | Out-Null
    if (-not $NoGuard) { [IO.File]::WriteAllBytes((Join-Path $d '.coordination.lock'), [byte[]]@()) }
    if (-not $NoThread) { [IO.File]::WriteAllBytes((Join-Path $d $ThreadName), [byte[]]@()) }
    $d
}

function Label-Rm($observed) {
    if ($null -eq $observed -or -not $observed.processes) { return $observed }
    foreach ($p in $observed.processes) {
        $role = 'other'
        if ($p.pid -eq $PID) { $role = 'orchestrator' }
        foreach ($a in $Agents) { if ($p.pid -eq $a.Pid -and $p.startFiletime -eq $a.Start) { $role = $a.Name } }
        $p | Add-Member -NotePropertyName role -NotePropertyValue $role
    }
    $observed | Add-Member -NotePropertyName interpretation -NotePropertyValue 'opener_candidates_only'
    $observed
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$integrity = (whoami /groups | Select-String 'S-1-16-' | Select-Object -First 1).ToString().Trim()
Record 'environment' 'host' $null ([pscustomobject]@{
        os = [Environment]::OSVersion.VersionString; ps = $PSVersionTable.PSVersion.ToString()
        integrity = $integrity; elevated = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole('Administrators')
        fs = (Get-Volume -DriveLetter $Scratch.Substring(0, 1)).FileSystemType
        note = 'results apply only to this token/integrity; source semantics pinned to Rust std 1.95 (Codex 0.162.1 and 0.155.1 writer_lock.rs identical)'
    })

try {
    $W = Start-Agent 'writer'
    $P = Start-Agent 'prober'
    $O = Start-Agent 'opener'

    # ---- E1: guarded probe states -------------------------------------------
    $d = New-LockDir 'e1-free'
    Record 'E1' 'free' @{ state = 'free' } (Invoke-Agent $P @('probe', $d, $ThreadName, 'nofollow'))

    $d = New-LockDir 'e1-absent' -NoThread
    Record 'E1' 'absent' @{ state = 'absent' } (Invoke-Agent $P @('probe', $d, $ThreadName, 'nofollow'))

    $d = New-LockDir 'e1-missing-guard' -NoGuard
    Record 'E1' 'missing_guard' @{ state = 'unknown'; reason = 'missing_guard' } (Invoke-Agent $P @('probe', $d, $ThreadName, 'nofollow'))

    $d = New-LockDir 'e1-busy'
    Invoke-Agent $W @('open', 'g', (Join-Path $d '.coordination.lock'), 'rwd', 'nofollow') | Out-Null
    Record 'E1' 'busy_guard:writer_lock' @{ locked = $true } (Invoke-Agent $W @('lock', 'g', 'rust'))
    Record 'E1' 'busy_guard' @{ state = 'unknown'; reason = 'busy_guard' } (Invoke-Agent $P @('probe', $d, $ThreadName, 'nofollow'))
    Invoke-Agent $W @('close', 'g') | Out-Null

    $d = New-LockDir 'e1-held'
    Invoke-Agent $W @('open', 't', (Join-Path $d $ThreadName), 'rwd', 'nofollow') | Out-Null
    Record 'E1' 'held:writer_lock' @{ locked = $true } (Invoke-Agent $W @('lock', 't', 'rust'))
    Record 'E1' 'held' @{ state = 'held' } (Invoke-Agent $P @('probe', $d, $ThreadName, 'nofollow'))
    Invoke-Agent $W @('close', 't') | Out-Null
    Record 'E1' 'held:after_writer_close' @{ state = 'free' } (Invoke-Agent $P @('probe', $d, $ThreadName, 'nofollow'))

    # ---- E1: range compatibility matrix (Rust std vs fs-ext) ------------------
    foreach ($x in 'rust', 'fsext') {
        foreach ($y in 'rust', 'fsext') {
            $d = New-LockDir "e1-range-$x-$y" -NoGuard
            $f = Join-Path $d $ThreadName
            Invoke-Agent $W @('open', 't', $f, 'rwd', 'nofollow') | Out-Null
            Invoke-Agent $W @('lock', 't', $x) | Out-Null
            Invoke-Agent $P @('open', 't', $f, 'rwd', 'nofollow') | Out-Null
            Record 'E1' "range:$x-held/$y-try" @{ locked = $false; win32 = 33 } (Invoke-Agent $P @('lock', 't', $y))
            Invoke-Agent $P @('close', 't') | Out-Null
            Invoke-Agent $W @('close', 't') | Out-Null
        }
    }

    # ---- E1: SHARE_DELETE, open-handle phase vs after-last-close phase -------
    foreach ($share in 'rwd', 'rw') {
        $d = New-LockDir "e1-share-$share" -NoGuard
        $f = Join-Path $d $ThreadName
        Invoke-Agent $W @('open', 't', $f, 'rwd', 'nofollow') | Out-Null
        Invoke-Agent $W @('lock', 't', 'rust') | Out-Null
        Invoke-Agent $P @('open', 't', $f, $share, 'nofollow') | Out-Null
        # Writer Drop order: close its own handle, then DeleteFileW, while the prober handle is still open.
        Invoke-Agent $W @('close', 't') | Out-Null
        $expect = $null
        if ($share -eq 'rw') { $expect = @{ ok = $false; win32 = 32 } }
        Record 'E1' "share:${share}:delete_while_prober_open" $expect (Invoke-Agent $W @('delete', $f))
        Invoke-Agent $P @('close', 't') | Out-Null
        Record 'E1' "share:${share}:exists_after_last_close" $null ([pscustomobject]@{ exists = (Test-Path -LiteralPath $f) })
        if (Test-Path -LiteralPath $f) {
            # Separate phase: no handle remains, so share mode cannot be the cause of a failure here.
            Record 'E1' "share:${share}:delete_after_last_close" $null (Invoke-Agent $W @('delete', $f))
        }
    }

    # ---- E1: mandatory byte-range read, data bytes vs empty file -------------
    $d = New-LockDir 'e1-read' -NoGuard -NoThread
    $data = Join-Path $d 'data.bin'
    [IO.File]::WriteAllBytes($data, [byte[]](1..16))
    $empty = Join-Path $d 'empty.bin'
    [IO.File]::WriteAllBytes($empty, [byte[]]@())
    foreach ($case in @(@($data, @{ ok = $false; win32 = 33 }), @($empty, $null))) {
        Invoke-Agent $W @('open', 't', $case[0], 'rwd', 'nofollow') | Out-Null
        Invoke-Agent $W @('lock', 't', 'rust') | Out-Null
        Invoke-Agent $P @('open', 'r', $case[0], 'rwd', 'nofollow') | Out-Null
        # Empty-file result is recorded only: zero bytes at EOF must not be read as a lock violation.
        Record 'E1' ("read_locked:" + (Split-Path $case[0] -Leaf)) $case[1] (Invoke-Agent $P @('read', 'r', '16'))
        Invoke-Agent $P @('close', 'r') | Out-Null
        Invoke-Agent $W @('close', 't') | Out-Null
    }

    # ---- E1: explicit no-follow / identity policy ----------------------------
    $d = New-LockDir 'e1-thread-dir' -NoThread
    New-Item -ItemType Directory -Path (Join-Path $d $ThreadName) | Out-Null
    Record 'E1' 'thread_is_directory' @{ state = 'unknown' } (Invoke-Agent $P @('probe', $d, $ThreadName, 'nofollow'))

    $real = New-LockDir 'e1-junction-real'
    $j = Join-Path $Scratch 'e1-junction-link'
    New-Item -ItemType Junction -Path $j -Target $real | Out-Null
    $Junctions.Add($j)
    Record 'E1' 'junction:nofollow' @{ state = 'unknown'; reason = 'directory_reparse_or_unreadable' } (Invoke-Agent $P @('probe', $j, $ThreadName, 'nofollow'))
    # Negative control: without the policy the API follows the junction and reports free.
    Record 'E1' 'junction:follow_control' @{ state = 'free' } (Invoke-Agent $P @('probe', $j, $ThreadName, 'follow'))

    $d = New-LockDir 'e1-guard-exclusive'
    Invoke-Agent $W @('open', 'g', (Join-Path $d '.coordination.lock'), '-', 'nofollow') | Out-Null
    Record 'E1' 'guard_sharing_violation' @{ state = 'unknown'; reason = 'guard_open'; win32 = 32 } (Invoke-Agent $P @('probe', $d, $ThreadName, 'nofollow'))
    Invoke-Agent $W @('close', 'g') | Out-Null

    # ---- E3: Restart Manager opener evidence ---------------------------------
    $d = New-LockDir 'e3'
    $f = Join-Path $d $ThreadName
    Record 'E3' 'none' $null (Label-Rm (Invoke-Agent $P @('rm', $f)))
    Invoke-Agent $W @('open', 't', $f, 'rwd', 'nofollow') | Out-Null
    Invoke-Agent $W @('lock', 't', 'rust') | Out-Null
    Record 'E3' 'holder' $null (Label-Rm (Invoke-Agent $P @('rm', $f)))
    Invoke-Agent $O @('open', 't', $f, 'rwd', 'nofollow') | Out-Null
    Record 'E3' 'holder+opener' $null (Label-Rm (Invoke-Agent $P @('rm', $f)))
    Invoke-Agent $P @('open', 's', $f, 'rwd', 'nofollow') | Out-Null
    Record 'E3' 'holder+opener+self' $null (Label-Rm (Invoke-Agent $P @('rm', $f)))
    Invoke-Agent $P @('close', 's') | Out-Null
    Invoke-Agent $W @('close', 't') | Out-Null
    Record 'E3' 'opener_only' $null (Label-Rm (Invoke-Agent $P @('rm', $f)))
    Invoke-Agent $O @('close', 't') | Out-Null

    $H = Start-Agent 'exiting-holder'
    Invoke-Agent $H @('open', 't', $f, 'rwd', 'nofollow') | Out-Null
    Invoke-Agent $H @('lock', 't', 'rust') | Out-Null
    Stop-Agent $H
    for ($i = 0; $i -lt 5; $i++) {
        Record 'E3' "after_holder_exit:$i" $null (Label-Rm (Invoke-Agent $P @('rm', $f)))
        Record 'E3' "after_holder_exit_probe:$i" $null (Invoke-Agent $P @('probe', $d, $ThreadName, 'follow'))
        Start-Sleep -Milliseconds 200
    }

    # ---- Bounded identity-change fixture (no PID-reuse spawning) -------------
    $C = Start-Agent 'identity-target'
    Record 'identity' 'live' @{ state = 'same_user' } (Invoke-Agent $P @('procid', "$($C.Pid)", "$($C.Start)"))
    Record 'identity' 'start_mismatch' @{ state = 'identity_changed' } (Invoke-Agent $P @('procid', "$($C.Pid)", "$($C.Start + 1)"))
    Stop-Agent $C
    # After exit the PID is either unopenable or reused; both must not read as same_user.
    $after = Invoke-Agent $P @('procid', "$($C.Pid)", "$($C.Start)")
    $verdict = if ($null -eq $after) { 'incomplete' } elseif ($after.state -ne 'same_user') { 'match' } else { 'mismatch' }
    $Results.Add([pscustomobject]@{ scenario = 'identity'; step = 'after_exit'; expect = 'not same_user'; observed = $after; verdict = $verdict; safeToUnlock = $false })
}
catch {
    Record 'lifecycle' 'orchestrator_error' $null ([pscustomobject]@{ error = $_.Exception.Message })
}
finally {
    foreach ($a in $Agents) { Stop-Agent $a }
    $running = @($Agents | Where-Object { -not $_.Exited })
    foreach ($a in $Agents) {
        if ($a.Exited -and $a.StdErr.Wait(1000) -and $a.StdErr.Result) {
            Record 'lifecycle' "stderr:$($a.Name)" $null ([pscustomobject]@{ text = $a.StdErr.Result })
        }
    }
    $Results | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 } | Set-Content -LiteralPath $OutFile -Encoding UTF8
    $summary = $Results | Group-Object verdict | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Output ("results: " + $OutFile)
    Write-Output ("verdicts: " + ($summary -join ' '))
    if ($running.Count -gt 0) {
        # Never kill; leave scratch in place so open handles are not disturbed.
        Write-Output ("incomplete: agents still running, scratch kept: " + (($running | ForEach-Object { $_.Pid }) -join ','))
    } elseif ($OutFile.StartsWith($Scratch)) {
        Write-Output ("scratch kept for results: " + $Scratch)
    } else {
        # Remove junctions as links first so recursive removal never follows them.
        foreach ($j in $Junctions) { [IO.Directory]::Delete($j, $false) }
        Remove-Item -LiteralPath $Scratch -Recurse -Force
        Write-Output ("scratch removed: " + $Scratch)
    }
}
