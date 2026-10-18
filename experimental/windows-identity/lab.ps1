<#
Fixture-only Windows identity lab for codex-unlock research (W1 #146,
W2 #147, W3 #148).

Windows PowerShell 5.1, no compiler install: WinIdentityLab.cs is compiled by
Add-Type. The run reserves the result file first, then creates one new private
scratch directory under %TEMP%, creates synthetic fixtures inside it, records
raw observations as JSONL, and removes only what it created after verifying
each object's identity. It never reads CODEX_HOME or a user Codex home, never
changes an existing object's ACL or owner, never enables a privilege, and
never terminates or signals a process. Classification is done afterwards by
classify.mjs against its own closed case manifest.

  powershell -NoProfile -NonInteractive -File lab.ps1 -OutFile <new file>
  node classify.mjs <that file>

  # Synthetic fault-injection check (expected to fail the suite in a defined way):
  powershell -NoProfile -NonInteractive -File lab.ps1 -OutFile <new file> -FaultInjection after_child_launch
  node classify.mjs --fault after_child_launch <that file>

Exit codes: 0 = suite completed and cleanup succeeded; 2 = suite error,
cleanup failure or preservation, results write failure, or a child still
running; 3 = refused before any fixture was created. Hypothesis verdicts come
only from classify.mjs.
#>
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [ValidateRange(0, 600000)][int]$WaitBudgetMs = 15000,
    [ValidateRange(0, 4096)][int]$ReuseAttempts = 256,
    [ValidateRange(0, 600000)][int]$ReuseBudgetMs = 60000,
    [ValidateSet('none', 'during_file_cases', 'after_child_launch', 'during_child_observation', 'child_abnormal_exit', 'child_ignores_eof')]
    [string]$FaultInjection = 'none'
)
$ErrorActionPreference = 'Stop'

function Test-Inside([string]$path, [string]$dir) {
    $d = $dir.TrimEnd('\')
    [string]::Equals($path, $d, [StringComparison]::OrdinalIgnoreCase) -or
        $path.StartsWith($d + '\', [StringComparison]::OrdinalIgnoreCase)
}

# ---- Reserve the result file before anything else exists -------------------
try {
    $out = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile))
    $parent = [IO.Path]::GetDirectoryName($out)
    if ([string]::IsNullOrEmpty($parent) -or [string]::IsNullOrEmpty([IO.Path]::GetFileName($out))) { throw 'invalid result path' }
    $parentItem = Get-Item -LiteralPath $parent -Force
    if (-not $parentItem.PSIsContainer) { throw 'result parent is not a directory' }
    if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'result parent is a reparse point' }
    if (Test-Path -LiteralPath $out) { throw 'result file already exists' }
    if ($out -match '\\codex-win-identity-[^\\]*\\') { throw 'result file is inside a lab scratch directory' }
    $stream = New-Object IO.FileStream($out, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
} catch {
    Write-Output ('refused: ' + $_.Exception.Message)
    exit 3
}
$writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($false)))

function Write-Records($records) {
    try {
        foreach ($line in $records) { $writer.Write($line + "`n") }
        $writer.Flush()
        return $true
    } catch {
        Write-Output ('results write failed: ' + $_.Exception.Message)
        return $false
    }
}

function Close-Results {
    try { $writer.Dispose(); return $true } catch { Write-Output ('results close failed: ' + $_.Exception.Message); return $false }
}

try {
    Add-Type -Path (Join-Path $PSScriptRoot 'WinIdentityLab.cs')
} catch {
    [void](Write-Records @('{"kind":"refused","case":"refused","track":"setup","reason":"compile_failed","safeToUnlock":false}'))
    [void](Close-Results)
    Write-Output ('refused: compile failed: ' + $_.Exception.Message)
    exit 3
}

$bootstrapReason = $null
try {
    $root = [WinIdentityLab]::CreateScratch()
    if ($null -eq $root -or (Test-Inside $out $root)) { $bootstrapReason = 'scratch_verification_failed' }
} catch {
    $bootstrapReason = 'scratch_bootstrap_exception'
}
if ($null -ne $bootstrapReason) {
    [void](Write-Records @([WinIdentityLab]::Refused($bootstrapReason)))
    [void](Close-Results)
    Write-Output 'refused: scratch directory verification failed'
    exit 3
}

$fault = $null
if ($FaultInjection -ne 'none') { $fault = $FaultInjection }
$exitCode = 0
$lines = New-Object System.Collections.Generic.List[string]
try {
    foreach ($line in [WinIdentityLab]::RunSuite($WaitBudgetMs, $ReuseAttempts, $ReuseBudgetMs, $fault)) { $lines.Add($line) }
    foreach ($line in $lines) { if ($line.StartsWith('{"kind":"suite_error"')) { $exitCode = 2 } }
} catch {
    # Keep whatever evidence was collected before the failure.
    foreach ($line in [WinIdentityLab]::Partial()) { $lines.Add($line) }
    $lines.Add([WinIdentityLab]::SuiteError($_.Exception.Message))
    $exitCode = 2
} finally {
    try { $lines.Add([WinIdentityLab]::Cleanup()) } catch { $lines.Add([WinIdentityLab]::SuiteError('cleanup: ' + $_.Exception.Message)); $exitCode = 2 }
}
if (-not [WinIdentityLab]::CleanupOk) {
    Write-Output "cleanup incomplete; scratch preserved: $root"
    $exitCode = 2
}
if ([WinIdentityLab]::ChildrenStillRunning -gt 0) {
    Write-Output 'a fixture child process is still running; it was not terminated'
    $exitCode = 2
}

$written = Write-Records $lines
$closed = Close-Results
if (-not ($written -and $closed)) { exit 2 }
Write-Output ("wrote {0} records" -f $lines.Count)
exit $exitCode
