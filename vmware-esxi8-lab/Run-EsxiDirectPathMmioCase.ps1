param(
  [Parameter(Mandatory)]
  [ValidatePattern('^[A-Za-z0-9_-]+$')]
  [string]$CaseId,

  [ValidateSet('Absent', 'False', 'True')]
  [string]$Use64BitMmio = 'Absent',

  [Nullable[int]]$SizeGb,

  [ValidateSet('Efi', 'Bios')]
  [string]$Firmware = 'Efi',

  [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss')
)

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$ssh = Join-Path $PSScriptRoot 'Invoke-EsxiCaveatSsh.ps1'
$scp = Join-Path $PSScriptRoot 'Copy-EsxiCaveatFile.ps1'
$baseVmx = Join-Path $PSScriptRoot 'mf-passthru-probe-local.vmx'
$localDir = Join-Path $PSScriptRoot "vmware-directpath-runs\$RunId\$CaseId"
$wslDir = "/mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/$RunId/$CaseId"
$remoteDir = "/vmfs/volumes/pci-mmio-local/directpath-cases/$RunId-$CaseId"
$remoteVmx = "$remoteDir/$CaseId.vmx"
$serialName = "guest-serial-$CaseId.log"

New-Item -ItemType Directory -Force -Path $localDir | Out-Null

function Invoke-Remote {
  param([Parameter(Mandatory)][string]$Command)
  & $ssh -RemoteCommand $Command 2>$null
}

function Copy-FromEsxiIfPresent {
  param([string]$Source, [string]$Destination)
  try {
    & $scp -Direction FromEsxi -Source $Source -Destination $Destination 2>$null
    return $true
  } catch {
    return $false
  }
}

$lines = Get-Content -LiteralPath $baseVmx -Encoding utf8 |
  Where-Object {
    $_ -notmatch '^pciPassthru\.use64bitMMIO\s*=' -and
    $_ -notmatch '^pciPassthru\.64bitMMIOSizeGB\s*='
  }
$lines = $lines | ForEach-Object {
  if ($_ -match '^displayName\s*=') {
    "displayName = `"$CaseId`""
  } elseif ($_ -match '^serial0\.fileName\s*=') {
    "serial0.fileName = `"$serialName`""
  } elseif ($_ -match '^firmware\s*=') {
    "firmware = `"$($Firmware.ToLowerInvariant())`""
  } elseif ($Firmware -eq 'Bios' -and $_ -match '^chipset\.motherboardLayout\s*=') {
    $null
  } else {
    $_
  }
}

if ($Use64BitMmio -eq 'True') {
  $lines += 'pciPassthru.use64bitMMIO = "TRUE"'
} elseif ($Use64BitMmio -eq 'False') {
  $lines += 'pciPassthru.use64bitMMIO = "FALSE"'
}
if ($null -ne $SizeGb) {
  $lines += "pciPassthru.64bitMMIOSizeGB = `"$SizeGb`""
}

$generatedVmx = Join-Path $localDir "$CaseId.vmx"
[System.IO.File]::WriteAllLines(
  $generatedVmx,
  [string[]]$lines,
  [System.Text.UTF8Encoding]::new($false)
)

$metadata = [ordered]@{
  caseId = $CaseId
  runId = $RunId
  use64BitMmio = $Use64BitMmio
  sizeGb = $SizeGb
  firmware = $Firmware.ToLowerInvariant()
  esxi = '8.0.3-24280767'
  qemuCpuDelta = '-vmx-tsc-scaling'
  verdict = 'running'
}
$metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $localDir 'case.json') -Encoding utf8

Invoke-Remote "mkdir -p $remoteDir; rm -f $remoteDir/*"
& $scp -Direction ToEsxi -Source "$wslDir/$CaseId.vmx" -Destination $remoteVmx 2>$null

$hostState = Invoke-Remote 'esxcli hardware pci pcipassthru list; esxcli hardware pci list | sed -n "/0000:01:00.0/,/^$/p"; esxcli hardware pci list | sed -n "/0000:01:00.1/,/^$/p"; esxcli hardware pci list | sed -n "/0000:01:01.0/,/^$/p"'
$hostState | Set-Content -LiteralPath (Join-Path $localDir 'esxi-pci-before.txt') -Encoding utf8

$activeOwners = @($hostState | Select-String -Pattern '^\s+Current Owner:\s+VM Passthru\s*$')
if ($activeOwners.Count -lt 3) {
  $metadata['verdict'] = 'precondition-failed'
  $metadata['failureId'] = 'passthru-owner-not-active'
  $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $localDir 'case.json') -Encoding utf8
  throw "Expected three devices with Current Owner = VM Passthru; observed $($activeOwners.Count)."
}

$registerOutput = Invoke-Remote "vim-cmd solo/registervm $remoteVmx"
$vmid = $registerOutput |
  ForEach-Object { $_.ToString().Trim() } |
  Where-Object { $_ -match '^\d+$' } |
  Select-Object -Last 1
if (-not $vmid) {
  throw "Unable to parse VMID from register output: $registerOutput"
}

$metadata['vmid'] = [int]$vmid
$powerOutput = $null
try {
  $powerOutput = Invoke-Remote "vim-cmd vmsvc/power.on $vmid"
  $powerOutput | Set-Content -LiteralPath (Join-Path $localDir 'power-on.txt') -Encoding utf8

  $state = ''
  for ($i = 0; $i -lt 80; $i++) {
    Start-Sleep -Seconds 3
    $state = (Invoke-Remote "vim-cmd vmsvc/power.getstate $vmid") -join "`n"
    if ($state -match 'Powered off') {
      break
    }
  }

  $state | Set-Content -LiteralPath (Join-Path $localDir 'final-power-state.txt') -Encoding utf8
  $metadata['finalPowerState'] = $state.Trim()
  $metadata['verdict'] = if ($state -match 'Powered off') { 'guest-completed' } else { 'timeout' }
} catch {
  $_ | Out-String | Set-Content -LiteralPath (Join-Path $localDir 'power-on-error.txt') -Encoding utf8
  $metadata['verdict'] = 'power-on-failed'
} finally {
  Copy-FromEsxiIfPresent "$remoteDir/$serialName" "$wslDir/$serialName" | Out-Null
  Copy-FromEsxiIfPresent "$remoteDir/vmware.log" "$wslDir/vmware.log" | Out-Null
  Copy-FromEsxiIfPresent $remoteVmx "$wslDir/effective.vmx" | Out-Null
  try {
    Invoke-Remote "vim-cmd vmsvc/power.off $vmid >/dev/null 2>&1 || true; vim-cmd vmsvc/unregister $vmid >/dev/null 2>&1 || true" | Out-Null
  } catch {
  }
  $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $localDir 'case.json') -Encoding utf8
}

[pscustomobject]$metadata
