param(
  [Parameter(Mandatory)]
  [ValidatePattern('^[A-Za-z0-9_-]+$')]
  [string]$CaseId,

  [ValidateSet('Absent', 'False', 'True')]
  [string]$Use64BitMmio = 'Absent',

  [Nullable[int]]$SizeGb,

  [ValidateSet('Efi', 'Bios')]
  [string]$Firmware = 'Efi',

  [ValidateSet('Auto', 'Absent', 'I440Bx', 'Acpi')]
  [string]$MotherboardLayout = 'Auto',

  [ValidateSet('Template', 'Auto', 'PcieRootPorts')]
  [string]$BridgePolicy = 'Template',

  [string]$HostName = '172.31.91.10',

  [ValidatePattern('^[A-Za-z0-9_.-]+$')]
  [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss')
)

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$ssh = Join-Path $PSScriptRoot 'Invoke-EsxiCaveatSsh.ps1'
$scp = Join-Path $PSScriptRoot 'Copy-EsxiCaveatFile.ps1'
$baseVmx = Join-Path $PSScriptRoot 'mf-passthru-probe-local.vmx'
$artifactRoot = Join-Path (Split-Path -Parent $workspace) '_artifacts\vmware-directpath-runs'
$localDir = Join-Path $artifactRoot "$RunId\$CaseId"
$remoteDir = "/vmfs/volumes/pci-mmio-local/directpath-cases/$RunId-$CaseId"
$remoteVmx = "$remoteDir/$CaseId.vmx"
$serialName = "guest-serial-$CaseId.log"

New-Item -ItemType Directory -Force -Path $localDir | Out-Null
$wslDir = (& wsl -e wslpath -a $localDir).Trim()
if (-not $wslDir) {
  throw "Unable to translate artifact directory '$localDir' to WSL."
}

function Invoke-Remote {
  param([Parameter(Mandatory)][string]$Command)
  & $ssh -HostName $HostName -RemoteCommand $Command 2>$null
}

function Copy-FromEsxiIfPresent {
  param([string]$Source, [string]$Destination)
  try {
    & $scp -HostName $HostName -Direction FromEsxi -Source $Source -Destination $Destination 2>$null
    return $true
  } catch {
    return $false
  }
}

$inputLayout = switch ($MotherboardLayout) {
  'Auto' { $null }
  'Absent' { $null }
  'I440Bx' { 'i440bx' }
  'Acpi' { 'acpi' }
}

$lines = Get-Content -LiteralPath $baseVmx -Encoding utf8 |
  Where-Object {
    $_ -notmatch '^pciPassthru\.use64bitMMIO\s*=' -and
    $_ -notmatch '^pciPassthru\.64bitMMIOSizeGB\s*=' -and
    $_ -notmatch '^chipset\.motherboardLayout\s*=' -and
    ($BridgePolicy -eq 'Template' -or $_ -notmatch '^pciBridge\d')
  }
$lines = $lines | ForEach-Object {
  if ($_ -match '^displayName\s*=') {
    "displayName = `"$CaseId`""
  } elseif ($_ -match '^serial0\.fileName\s*=') {
    "serial0.fileName = `"$serialName`""
  } elseif ($_ -match '^firmware\s*=') {
    "firmware = `"$($Firmware.ToLowerInvariant())`""
  } else {
    $_
  }
}

if ($null -ne $inputLayout) {
  $lines += "chipset.motherboardLayout = `"$inputLayout`""
}

if ($BridgePolicy -eq 'PcieRootPorts') {
  $lines += @(
    'pciBridge0.present = "TRUE"'
    'pciBridge4.present = "TRUE"'
    'pciBridge4.virtualDev = "pcieRootPort"'
    'pciBridge4.functions = "8"'
    'pciBridge5.present = "TRUE"'
    'pciBridge5.virtualDev = "pcieRootPort"'
    'pciBridge5.functions = "8"'
    'pciBridge6.present = "TRUE"'
    'pciBridge6.virtualDev = "pcieRootPort"'
    'pciBridge6.functions = "8"'
    'pciBridge7.present = "TRUE"'
    'pciBridge7.virtualDev = "pcieRootPort"'
    'pciBridge7.functions = "8"'
  )
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
  motherboardLayout = $MotherboardLayout.ToLowerInvariant()
  inputMotherboardLayout = $inputLayout
  bridgePolicy = $BridgePolicy.ToLowerInvariant()
  hostName = $HostName
  esxi = '8.0.3-24280767'
  qemuCpuDelta = '-vmx-tsc-scaling'
  verdict = 'running'
}
$metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $localDir 'case.json') -Encoding utf8

Invoke-Remote "mkdir -p $remoteDir; rm -f $remoteDir/*"
& $scp -HostName $HostName -Direction ToEsxi -Source "$wslDir/$CaseId.vmx" -Destination $remoteVmx 2>$null

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
$powerOnSucceeded = $false
try {
  try {
    $powerOutput = Invoke-Remote "vim-cmd vmsvc/power.on $vmid"
    $powerOutput | Set-Content -LiteralPath (Join-Path $localDir 'power-on.txt') -Encoding utf8
    $powerOnSucceeded = $true
  } catch {
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $localDir 'power-on-error.txt') -Encoding utf8
    $metadata['verdict'] = 'power-on-failed'
  }

  if ($powerOnSucceeded) {
    $state = ''
    $pollErrors = @()
    for ($i = 0; $i -lt 120; $i++) {
      Start-Sleep -Seconds 3
      try {
        $state = (Invoke-Remote "vim-cmd vmsvc/power.getstate $vmid") -join "`n"
        if ($state -match 'Powered off') {
          break
        }
      } catch {
        $pollErrors += "poll=$i`n$($_ | Out-String)"
      }
    }

    if ($pollErrors.Count -gt 0) {
      $pollErrors | Set-Content -LiteralPath (Join-Path $localDir 'power-poll-errors.txt') -Encoding utf8
    }
    $state | Set-Content -LiteralPath (Join-Path $localDir 'final-power-state.txt') -Encoding utf8
    $metadata['finalPowerState'] = $state.Trim()
    $metadata['verdict'] = if ($state -match 'Powered off') { 'guest-completed' } else { 'timeout' }
  }
} finally {
  Start-Sleep -Seconds 2
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
