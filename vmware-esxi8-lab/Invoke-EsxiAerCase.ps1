param(
  [Parameter(Mandatory)]
  [ValidatePattern('^[A-Za-z0-9_-]+$')]
  [string]$CaseId,

  [ValidateSet('Native', 'PassthruIdle', 'PassthruActive')]
  [string]$OwnerState = 'Native',

  [ValidateSet('Correctable', 'NonFatal')]
  [string]$ErrorClass = 'Correctable',

  [string]$QemuDevice = 'test_fn1',
  [string]$EsxiBdf = '0000:01:00.1',
  [int]$VmwarePassthruIndex = 1,
  [string]$ErrorStatus,
  [switch]$AllowNonFatal,
  [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss'),
  [int]$GuestMarkerTimeoutSeconds = 360,
  [int]$PostInjectionSeconds = 100
)

$ErrorActionPreference = 'Stop'
$ssh = Join-Path $PSScriptRoot 'Invoke-EsxiCaveatSsh.ps1'
$scp = Join-Path $PSScriptRoot 'Copy-EsxiCaveatFile.ps1'
$monitor = Join-Path $PSScriptRoot 'qemu-esxi8-monitor-command.py'
$baseVmx = Join-Path $PSScriptRoot 'mf-passthru-probe-local.vmx'
$localDir = Join-Path $PSScriptRoot "vmware-directpath-runs\$RunId\$CaseId"
$wslDir = "/mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/$RunId/$CaseId"
$remoteDir = "/vmfs/volumes/pci-mmio-local/directpath-cases/$RunId-$CaseId"
$remoteVmx = "$remoteDir/$CaseId.vmx"
$serialName = "guest-serial-$CaseId.log"

if ($ErrorClass -eq 'NonFatal' -and -not $AllowNonFatal) {
  throw 'NonFatal injection requires -AllowNonFatal.'
}
if (-not $ErrorStatus) {
  $ErrorStatus = if ($ErrorClass -eq 'Correctable') { '0x00000001' } else { '0x00100000' }
}

New-Item -ItemType Directory -Force -Path $localDir | Out-Null

function Invoke-Remote {
  param([Parameter(Mandatory)][string]$Command)
  & $ssh -RemoteCommand $Command 2>$null
}

function Save-Remote {
  param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Command)
  Invoke-Remote $Command | Set-Content -LiteralPath (Join-Path $localDir $Name) -Encoding utf8
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

function Invoke-Wsl {
  param([Parameter(Mandatory)][string[]]$Arguments)
  $savedPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $output = & wsl @Arguments 2>$null
    $code = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $savedPreference
  }
  if ($code -ne 0) {
    throw "WSL command failed with exit code ${code}: $($Arguments -join ' ')"
  }
  return $output
}

$kernel = (Invoke-Remote 'localcli system settings kernel list -o enablePCIErrors') -join "`n"
$passthruReporting = (Invoke-Remote 'localcli system settings kernel list -o pcipDisablePciErrReporting') -join "`n"
if ($kernel -notmatch 'enablePCIErrors\s+Bool\s+\S+\s+TRUE') {
  throw 'Precondition failed: enablePCIErrors Runtime is not TRUE.'
}
if ($passthruReporting -notmatch 'pcipDisablePciErrReporting\s+Bool\s+\S+\s+FALSE') {
  throw 'Precondition failed: pcipDisablePciErrReporting Runtime is not FALSE.'
}

$ownerText = (Invoke-Remote "localcli hardware pci list | sed -n '/$EsxiBdf/,/^$/p'") -join "`n"
$expectedOwner = if ($OwnerState -eq 'Native') { 'VMkernel' } else { 'VM Passthru' }
if ($ownerText -notmatch "Current Owner:\s+$([regex]::Escape($expectedOwner))") {
  throw "Precondition failed: $EsxiBdf Current Owner is not $expectedOwner."
}

$metadata = [ordered]@{
  caseId = $CaseId
  runId = $RunId
  ownerState = $OwnerState
  errorClass = $ErrorClass
  errorStatus = $ErrorStatus
  qemuDevice = $QemuDevice
  esxiBdf = $EsxiBdf
  startedAt = (Get-Date).ToString('o')
  verdict = 'running'
}
$metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $localDir 'case.json') -Encoding utf8

Save-Remote 'kernel-before.txt' 'localcli system settings kernel list -o enablePCIErrors'
Save-Remote 'passthru-reporting-before.txt' 'localcli system settings kernel list -o pcipDisablePciErrReporting'
Save-Remote 'pci-before.txt' 'localcli hardware pci list'
Save-Remote 'pcipassthru-before.txt' 'localcli hardware pci pcipassthru list'
Save-Remote 'lspci-ext-before.txt' 'lspci -e'
Save-Remote 'vmkernel-before.txt' 'tail -n 1800 /var/run/log/vmkernel.log'
Save-Remote 'vobd-before.txt' 'tail -n 800 /var/run/log/vobd.log'
Save-Remote 'syslog-before.txt' 'tail -n 800 /var/run/log/syslog.log'

Invoke-Wsl @('-d', 'Ubuntu-22.04', '--exec', 'python3', ($monitor -replace '^E:', '/mnt/e' -replace '\\', '/'), 'info pci') |
  Set-Content -LiteralPath (Join-Path $localDir 'qemu-pci-before.txt') -Encoding utf8
Invoke-Wsl @('-d', 'Ubuntu-22.04', '--exec', 'qemu-system-x86_64', '--version') |
  Set-Content -LiteralPath (Join-Path $localDir 'qemu-version.txt') -Encoding utf8

$vmid = $null
try {
  if ($OwnerState -eq 'PassthruActive') {
    $iso = (Invoke-Remote 'test -f /vmfs/volumes/pci-mmio-local/iso/esxi-l3-aer-probe.iso && echo present') -join ''
    if ($iso -notmatch 'present') {
      throw 'AER guest ISO is not present on the ESXi datastore.'
    }

    $lines = Get-Content -LiteralPath $baseVmx -Encoding utf8 | ForEach-Object {
      if ($_ -match '^displayName\s*=') {
        "displayName = `"$CaseId`""
      } elseif ($_ -match '^serial0\.fileName\s*=') {
        "serial0.fileName = `"$serialName`""
      } elseif ($_ -match '^ide1:0\.fileName\s*=') {
        'ide1:0.fileName = "/vmfs/volumes/pci-mmio-local/iso/esxi-l3-aer-probe.iso"'
      } else {
        $_
      }
    }
    $generatedVmx = Join-Path $localDir "$CaseId.vmx"
    [System.IO.File]::WriteAllLines($generatedVmx, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
    Invoke-Remote "mkdir -p $remoteDir; rm -f $remoteDir/*" | Out-Null
    & $scp -Direction ToEsxi -Source "$wslDir/$CaseId.vmx" -Destination $remoteVmx 2>$null
    $registerOutput = Invoke-Remote "vim-cmd solo/registervm $remoteVmx"
    $vmid = $registerOutput | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ -match '^\d+$' } | Select-Object -Last 1
    if (-not $vmid) {
      throw "Unable to parse VMID from register output: $registerOutput"
    }
    Invoke-Remote "vim-cmd vmsvc/power.on $vmid" | Set-Content -LiteralPath (Join-Path $localDir 'power-on.txt') -Encoding utf8

    $deadline = (Get-Date).AddSeconds($GuestMarkerTimeoutSeconds)
    $markerSeen = $false
    while ((Get-Date) -lt $deadline) {
      $probe = (Invoke-Remote "grep -F '=== AER injection window open ===' $remoteDir/$serialName 2>/dev/null || true") -join "`n"
      if ($probe -match 'injection window open') {
        $markerSeen = $true
        $metadata['injectionTrigger'] = 'guest-serial-marker'
        break
      }
      $vmwareProbe = (Invoke-Remote "grep -E 'FirstToken2Use:.*device:pciPassthru$VmwarePassthruIndex' $remoteDir/vmware.log 2>/dev/null || true") -join "`n"
      if ($vmwareProbe -match 'FirstToken2Use') {
        Start-Sleep -Seconds 12
        $markerSeen = $true
        $metadata['injectionTrigger'] = "vmware-log-first-target-access-plus-12s"
        break
      }
      Start-Sleep -Seconds 2
    }
    if (-not $markerSeen) {
      throw 'Guest did not open the AER injection window before timeout.'
    }
    Copy-FromEsxiIfPresent "$remoteDir/$serialName" "$wslDir/guest-serial-before.txt" | Out-Null
  }

  Invoke-Remote "logger -t PCI-AER-TEST $CaseId-$ErrorClass-BEFORE" | Out-Null
  $hmp = if ($ErrorClass -eq 'Correctable') {
    "pcie_aer_inject_error -c $QemuDevice $ErrorStatus"
  } else {
    "pcie_aer_inject_error $QemuDevice $ErrorStatus 0 0 0 0"
  }
  $metadata['hmpCommand'] = $hmp
  $monitorWsl = $monitor -replace '^E:', '/mnt/e' -replace '\\', '/'
  $injection = Invoke-Wsl @('-d', 'Ubuntu-22.04', '--exec', 'python3', $monitorWsl, $hmp)
  $injection | Set-Content -LiteralPath (Join-Path $localDir 'qemu-injection.txt') -Encoding utf8
  if (($injection -join "`n") -notmatch "OK id:\s+$([regex]::Escape($QemuDevice))") {
    throw 'QEMU did not confirm the AER injection.'
  }

  Start-Sleep -Seconds $PostInjectionSeconds
  $metadata['verdict'] = 'injected-and-host-responsive'
} catch {
  $metadata['verdict'] = 'failed'
  $metadata['failure'] = $_.Exception.Message
  $_ | Out-String | Set-Content -LiteralPath (Join-Path $localDir 'failure.txt') -Encoding utf8
  throw
} finally {
  try { Save-Remote 'kernel-after.txt' 'localcli system settings kernel list -o enablePCIErrors' } catch {}
  try { Save-Remote 'passthru-reporting-after.txt' 'localcli system settings kernel list -o pcipDisablePciErrReporting' } catch {}
  try { Save-Remote 'pci-after.txt' 'localcli hardware pci list' } catch {}
  try { Save-Remote 'pcipassthru-after.txt' 'localcli hardware pci pcipassthru list' } catch {}
  try { Save-Remote 'lspci-ext-after.txt' 'lspci -e' } catch {}
  try { Save-Remote 'vmkernel-after.txt' 'tail -n 1800 /var/run/log/vmkernel.log' } catch {}
  try { Save-Remote 'vobd-after.txt' 'tail -n 800 /var/run/log/vobd.log' } catch {}
  try { Save-Remote 'syslog-after.txt' 'tail -n 800 /var/run/log/syslog.log' } catch {}
  try { Save-Remote 'uptime-after.txt' 'uptime' } catch {}
  if ($vmid) {
    Copy-FromEsxiIfPresent "$remoteDir/$serialName" "$wslDir/guest-serial-after.txt" | Out-Null
    Copy-FromEsxiIfPresent "$remoteDir/vmware.log" "$wslDir/vmware.log" | Out-Null
    Copy-FromEsxiIfPresent $remoteVmx "$wslDir/effective.vmx" | Out-Null
    try { Invoke-Remote "vim-cmd vmsvc/power.off $vmid >/dev/null 2>&1 || true" | Out-Null } catch {}
    try { Invoke-Remote "vim-cmd vmsvc/unregister $vmid >/dev/null 2>&1 || true" | Out-Null } catch {}
  }
  $metadata['finishedAt'] = (Get-Date).ToString('o')
  $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $localDir 'case.json') -Encoding utf8
}

[pscustomobject]$metadata
