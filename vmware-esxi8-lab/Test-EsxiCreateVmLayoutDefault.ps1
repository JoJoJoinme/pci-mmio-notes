param(
  [string]$HostName = '172.31.91.10',
  [string]$UserName = 'root',
  [string]$Datastore = 'pci-mmio-local',
  [ValidateSet('Efi', 'Bios')]
  [string]$Firmware = 'Efi',
  [ValidateSet('Auto', 'Acpi', 'I440Bx', 'Observe')]
  [string]$ExpectedLayout = 'Auto',
  [string]$CaveatId = 'esxi8-auto-codex-credentials',
  [ValidatePattern('^[A-Za-z0-9_.-]+$')]
  [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss'),
  [switch]$PowerOn
)

$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'test_esxi_createvm_layout_default.py'
$workspace = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$artifactRoot = Join-Path $workspace '_artifacts\vmware-directpath-runs'
$artifactDir = Join-Path $artifactRoot "$RunId-createvm-default"
$artifactPath = Join-Path $artifactDir 'createvm-layout-default.json'
$vmName = "layout-default-$($Firmware.ToLowerInvariant())-$RunId"
$expectedApiLayout = switch ($ExpectedLayout) {
  'Auto' { if ($Firmware -eq 'Efi') { 'acpiHostBridges' } else { 'i440bxHostBridge' } }
  'Acpi' { 'acpiHostBridges' }
  'I440Bx' { 'i440bxHostBridge' }
  'Observe' { $null }
}

New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null

$savedErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$entry = & wsl -e caveat show $CaveatId 2>$null
$ErrorActionPreference = $savedErrorActionPreference
$text = $entry -join "`n"
if ($text -notmatch 'Password:\s*(\S+)') {
  throw "Caveat '$CaveatId' does not contain a Password field."
}

$oldWslEnv = $env:WSLENV
$env:ESXI_PASSWORD = $Matches[1]
$env:WSLENV = if ($oldWslEnv) { "ESXI_PASSWORD:$oldWslEnv" } else { 'ESXI_PASSWORD' }
$wslScript = (& wsl -e wslpath -a $script).Trim()

try {
  $arguments = @(
    '-d', 'Ubuntu-22.04', '--', 'python3', $wslScript,
    '--host', $HostName,
    '--user', $UserName,
    '--datastore', $Datastore,
    '--name', $vmName,
    '--firmware', $Firmware.ToLowerInvariant()
  )
  if ($expectedApiLayout) {
    $arguments += @('--expected-layout', $expectedApiLayout)
  }
  if ($PowerOn) {
    $arguments += '--power-on'
  }
  $json = & wsl @arguments
  $code = $LASTEXITCODE
  $json | Set-Content -LiteralPath $artifactPath -Encoding utf8
  $json
  if ($code -ne 0) {
    throw "CreateVM layout probe failed with exit code $code."
  }
} finally {
  Remove-Item Env:ESXI_PASSWORD -ErrorAction SilentlyContinue
  if ($null -eq $oldWslEnv) {
    Remove-Item Env:WSLENV -ErrorAction SilentlyContinue
  } else {
    $env:WSLENV = $oldWslEnv
  }
}
