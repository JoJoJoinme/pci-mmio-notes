param(
  [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss'),
  [int]$ForceOffAfterSeconds = 70
)

$ErrorActionPreference = 'Stop'
$ssh = Join-Path $PSScriptRoot 'Invoke-EsxiCaveatSsh.ps1'
$scp = Join-Path $PSScriptRoot 'Copy-EsxiCaveatFile.ps1'
$baseVmx = Join-Path $PSScriptRoot 'mf-passthru-probe-local.vmx'
$caseId = 'L00-L01-R02-lifecycle'
$localDir = Join-Path $PSScriptRoot "vmware-directpath-runs\$RunId\$caseId"
$wslDir = "/mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/$RunId/$caseId"
$remoteDir = "/vmfs/volumes/pci-mmio-local/directpath-cases/$RunId-$caseId"
$remoteVmx = "$remoteDir/$caseId.vmx"
$serialName = "guest-serial-$caseId.log"

New-Item -ItemType Directory -Force -Path $localDir | Out-Null

function Invoke-Remote([string]$Command) {
  & $ssh -RemoteCommand $Command 2>$null
}

$lines = Get-Content -LiteralPath $baseVmx -Encoding utf8 | ForEach-Object {
  if ($_ -match '^displayName\s*=') {
    "displayName = `"$caseId`""
  } elseif ($_ -match '^serial0\.fileName\s*=') {
    "serial0.fileName = `"$serialName`""
  } else {
    $_
  }
}
$generatedVmx = Join-Path $localDir "$caseId.vmx"
[System.IO.File]::WriteAllLines($generatedVmx, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))

Invoke-Remote "mkdir -p $remoteDir; rm -f $remoteDir/*" | Out-Null
& $scp -Direction ToEsxi -Source "$wslDir/$caseId.vmx" -Destination $remoteVmx 2>$null
$vmid = (Invoke-Remote "vim-cmd solo/registervm $remoteVmx" | Where-Object { $_ -match '^\d+$' } | Select-Object -Last 1).Trim()
if (-not $vmid) { throw 'Unable to register lifecycle VM.' }

try {
  Invoke-Remote "vim-cmd vmsvc/power.on $vmid" | Set-Content -Encoding utf8 (Join-Path $localDir 'power-on.txt')
  Start-Sleep -Seconds 12

  Invoke-Remote "vim-cmd vmsvc/snapshot.create $vmid directpath-snapshot-test test 0 0 2>&1; echo __RC=`$?" |
    Set-Content -Encoding utf8 (Join-Path $localDir 'snapshot-result.txt')
  Invoke-Remote "vim-cmd vmsvc/power.suspend $vmid 2>&1; echo __RC=`$?" |
    Set-Content -Encoding utf8 (Join-Path $localDir 'suspend-result.txt')

  Start-Sleep -Seconds ([Math]::Max(0, $ForceOffAfterSeconds - 12))
  Invoke-Remote "vim-cmd vmsvc/power.off $vmid 2>&1; echo __RC=`$?" |
    Set-Content -Encoding utf8 (Join-Path $localDir 'forced-power-off-result.txt')

  Start-Sleep -Seconds 4
  Invoke-Remote "vim-cmd vmsvc/power.on $vmid 2>&1; echo __RC=`$?" |
    Set-Content -Encoding utf8 (Join-Path $localDir 'restart-after-force-off.txt')
  Start-Sleep -Seconds 12
  Invoke-Remote "vim-cmd vmsvc/power.off $vmid >/dev/null 2>&1 || true" | Out-Null
} finally {
  foreach ($name in $serialName, 'vmware.log') {
    try {
      & $scp -Direction FromEsxi -Source "$remoteDir/$name" -Destination "$wslDir/$name" 2>$null
    } catch {
    }
  }
  try { Invoke-Remote "vim-cmd vmsvc/unregister $vmid >/dev/null 2>&1 || true" | Out-Null } catch {}
}

[pscustomobject]@{
  runId = $RunId
  vmid = [int]$vmid
  snapshot = (Get-Content (Join-Path $localDir 'snapshot-result.txt') -Raw).Trim()
  suspend = (Get-Content (Join-Path $localDir 'suspend-result.txt') -Raw).Trim()
  forceOff = (Get-Content (Join-Path $localDir 'forced-power-off-result.txt') -Raw).Trim()
  restart = (Get-Content (Join-Path $localDir 'restart-after-force-off.txt') -Raw).Trim()
}
