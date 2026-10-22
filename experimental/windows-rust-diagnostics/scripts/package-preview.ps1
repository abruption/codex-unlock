[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$BinaryPath,
  [Parameter(Mandatory)][string]$QuickstartPath,
  [Parameter(Mandatory)][string]$Destination,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceSha,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedSha256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$metadata = & cargo metadata --no-deps --locked --offline --format-version 1 --manifest-path (Join-Path $PSScriptRoot '../Cargo.toml')
if ($LASTEXITCODE -ne 0) { throw 'Cannot read Cargo package version' }
$packages = @(($metadata | ConvertFrom-Json).packages | Where-Object { $_.name -ceq 'codex-unlock-windows-diagnostic' })
if ($packages.Count -ne 1) { throw 'Expected one diagnostic Cargo package' }
$expectedVersion = $packages[0].version
$binary = Get-Item -LiteralPath $BinaryPath
$quickstart = Get-Item -LiteralPath $QuickstartPath
foreach ($item in @($binary, $quickstart)) {
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Inputs must be regular files' }
}
if ($binary.Name -cne 'codex-unlock-windows.exe') { throw 'Unexpected binary name' }
if ((Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) { throw 'Binary differs from tested release bytes' }
# Check the final PE before packaging: installed runner runtimes must not hide
# a dependency that would prevent extraction-and-run on a clean Windows host.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or @($installation).Count -ne 1 -or -not $installation) { throw 'Visual Studio C++ tools are required to verify imports' }
Import-Module (Join-Path $installation 'Common7/Tools/Microsoft.VisualStudio.DevShell.dll') -ErrorAction Stop
Enter-VsDevShell -VsInstallPath $installation -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64' | Out-Null
$dependencies = & dumpbin.exe /nologo /dependents $binary.FullName
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect final preview PE dependencies' }
$dependencies | & node (Join-Path $PSScriptRoot 'validate-static-crt-cli.mjs')
if ($LASTEXITCODE -ne 0) { throw 'Preview must statically link the MSVC CRT' }
if ((Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) { throw 'Binary changed during import check' }
$version = & $binary.FullName --version
if ($LASTEXITCODE -ne 0 -or ($version -join "`n").Trim() -cne "codex-unlock-windows $expectedVersion") { throw 'Unexpected preview binary version' }
if ((Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) { throw 'Binary changed during version check' }
# New-Item without -Force refuses existing destinations; do not reuse old output.
$output = New-Item -ItemType Directory -Path $Destination -ErrorAction Stop
$stage = New-Item -ItemType Directory -Path (Join-Path $output.FullName 'payload')
Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $stage.FullName 'codex-unlock-windows.exe')
Copy-Item -LiteralPath $quickstart.FullName -Destination (Join-Path $stage.FullName 'PREVIEW.md')
$manifest = [ordered]@{
  schemaVersion = 1
  sourceSha = $SourceSha
  target = 'x86_64-pc-windows-msvc'
  binary = [ordered]@{
    name = 'codex-unlock-windows.exe'
    version = $expectedVersion
    sha256 = (Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $stage.FullName 'manifest.json') -Encoding utf8NoBOM
$checksums = @('codex-unlock-windows.exe', 'PREVIEW.md', 'manifest.json') | ForEach-Object {
  (Get-FileHash -LiteralPath (Join-Path $stage.FullName $_) -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_
}
$checksums | Set-Content -LiteralPath (Join-Path $stage.FullName 'SHA256SUMS') -Encoding utf8NoBOM
& node (Join-Path $PSScriptRoot 'validate-preview-cli.mjs') $stage.FullName $binary.FullName $SourceSha $quickstart.FullName $expectedVersion
if ($LASTEXITCODE -ne 0) { throw 'Preview staging validation failed' }
$archivePath = Join-Path $output.FullName 'windows-diagnostics-preview-windows-x86_64.zip'
[IO.Compression.ZipFile]::CreateFromDirectory($stage.FullName, $archivePath)
$archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
  $actual = @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
  $expected = @('PREVIEW.md', 'SHA256SUMS', 'codex-unlock-windows.exe', 'manifest.json' | Sort-Object)
  if ($actual.Count -ne 4 -or (Compare-Object -CaseSensitive $expected $actual)) { throw 'Unexpected ZIP entries' }
} finally { $archive.Dispose() }
$extracted = Join-Path $output.FullName 'verified-extraction'
[IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $extracted)
& node (Join-Path $PSScriptRoot 'validate-preview-cli.mjs') $extracted $binary.FullName $SourceSha $quickstart.FullName $expectedVersion
if ($LASTEXITCODE -ne 0) { throw 'Preview ZIP validation failed' }
if ((Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) { throw 'Binary changed during packaging' }
Copy-Item -LiteralPath (Join-Path $stage.FullName 'manifest.json') -Destination $output.FullName
((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + [IO.Path]::GetFileName($archivePath)) |
  Set-Content -LiteralPath (Join-Path $output.FullName 'SHA256SUMS') -Encoding utf8NoBOM
# Keep staging/extraction local to this job; the upload allowlist contains only three sidecars/archive files.
