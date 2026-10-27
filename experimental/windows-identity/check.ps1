<#
Static gate for the Windows identity lab: parses lab.ps1 and check.ps1 and
compiles WinIdentityLab.cs with Add-Type. It creates no scratch directory or
fixture, starts no process, and calls no native API. Passing it says nothing
about Windows identity semantics.

  powershell -NoProfile -NonInteractive -File check.ps1
#>
$ErrorActionPreference = 'Stop'
$failed = $false

foreach ($script in 'lab.ps1', 'check.ps1') {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $script), [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        $failed = $true
        foreach ($e in $errors) { Write-Output ("parse error {0}:{1}: {2}" -f $script, $e.Extent.StartLineNumber, $e.Message) }
    } else {
        Write-Output "parse ok: $script"
    }
}

try {
    Add-Type -Path (Join-Path $PSScriptRoot 'WinIdentityLab.cs')
    $methods = [WinIdentityLab].GetMethods() | Select-Object -ExpandProperty Name
    foreach ($expected in 'CreateScratch', 'RunSuite', 'Partial', 'Cleanup', 'SuiteError', 'Refused', 'ObservePath', 'ObserveSecurity', 'ObserveProcessPid') {
        if ($methods -notcontains $expected) { throw "missing method: $expected" }
    }
    Write-Output 'compile ok: WinIdentityLab.cs (no method called)'
} catch {
    $failed = $true
    Write-Output ('compile error: ' + $_.Exception.Message)
}

if ($failed) { exit 1 }
exit 0
