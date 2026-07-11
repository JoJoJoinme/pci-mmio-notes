param(
  [int]$Cycles = 10,
  [int]$PoweredOnSeconds = 10,
  [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss')
)

$ErrorActionPreference = 'Stop'
$ssh = Join-Path $PSScriptRoot 'Invoke-EsxiCaveatSsh.ps1'
$scp = Join-Path $PSScriptRoot 'Copy-EsxiCaveatFile.ps1'
$caseId = 'R03-ten-cycle-stress'
$localDir = Join-Path $PSScriptRoot "vmware-directpath-runs\$RunId\$caseId"
$wslDir = "/mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/$RunId/$caseId"
$remoteDir = "/vmfs/volumes/pci-mmio-local/directpath-cases/$RunId-$caseId"
$remoteVmx = "$remoteDir/$caseId.vmx"
New-Item -ItemType Directory -Force -Path $localDir | Out-Null

function Invoke-Remote([string]$Command) {
  & $ssh -RemoteCommand $Command 2>$null
}

$vmx = Get-Content (Join-Path $PSScriptRoot 'mf-passthru-probe-local.vmx') -Encoding utf8 | ForEach-Object {
  if ($_ -match '^displayName\s*=') { "displayName = `"$caseId`"" } else { $_ }
}
$localVmx = Join-Path $localDir "$caseId.vmx"
[System.IO.File]::WriteAllLines($localVmx, [string[]]$vmx, [System.Text.UTF8Encoding]::new($false))
Invoke-Remote "mkdir -p $remoteDir; rm -f $remoteDir/*" | Out-Null
& $scp -Direction ToEsxi -Source "$wslDir/$caseId.vmx" -Destination $remoteVmx 2>$null
$vmid = (Invoke-Remote "vim-cmd solo/registervm $remoteVmx" | Where-Object { $_ -match '^\d+$' } | Select-Object -Last 1).Trim()

$results = @()
try {
  for ($cycle = 1; $cycle -le $Cycles; $cycle++) {
    $on = (Invoke-Remote "vim-cmd vmsvc/power.on $vmid 2>&1; echo __RC=`$?") -join "`n"
    Start-Sleep -Seconds $PoweredOnSeconds
    $stateOn = (Invoke-Remote "vim-cmd vmsvc/power.getstate $vmid") -join "`n"
    $off = (Invoke-Remote "vim-cmd vmsvc/power.off $vmid 2>&1; echo __RC=`$?") -join "`n"
    Start-Sleep -Seconds 3
    $stateOff = (Invoke-Remote "vim-cmd vmsvc/power.getstate $vmid") -join "`n"
    $results += [pscustomobject]@{
      cycle = $cycle
      powerOnRc = if ($on -match '__RC=(\d+)') { [int]$Matches[1] } else { -1 }
      observedOn = $stateOn -match 'Powered on'
      powerOffRc = if ($off -match '__RC=(\d+)') { [int]$Matches[1] } else { -1 }
      observedOff = $stateOff -match 'Powered off'
    }
    $results | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $localDir 'cycles.json')
  }
} finally {
  try { Invoke-Remote "vim-cmd vmsvc/power.off $vmid >/dev/null 2>&1 || true; vim-cmd vmsvc/unregister $vmid >/dev/null 2>&1 || true" | Out-Null } catch {}
  try { & $scp -Direction FromEsxi -Source "$remoteDir/vmware.log" -Destination "$wslDir/vmware.log" 2>$null } catch {}
}

$results
if (@($results | Where-Object { $_.powerOnRc -ne 0 -or -not $_.observedOn -or $_.powerOffRc -ne 0 -or -not $_.observedOff }).Count) {
  throw 'At least one DirectPath stress cycle failed.'
}
