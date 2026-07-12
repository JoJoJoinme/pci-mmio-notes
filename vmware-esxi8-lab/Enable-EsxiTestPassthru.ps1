param(
  [string]$HostName = '169.254.239.77',
  [string]$CaveatId = 'esxi8-auto-codex-credentials',
  [string[]]$Device = @('0000:01:00.0', '0000:01:00.1', '0000:01:01.0')
)

$ErrorActionPreference = 'Stop'
$ssh = Join-Path $PSScriptRoot 'Invoke-EsxiCaveatSsh.ps1'

foreach ($bdf in $Device) {
  $deviceState = & $ssh -HostName $HostName -CaveatId $CaveatId `
    -RemoteCommand "esxcli hardware pci list | sed -n '/$bdf/,/^$/p'" 2>$null
  $deviceText = $deviceState -join "`n"
  if ($deviceText -notmatch '(?m)^\s+Current Owner:\s+VM Passthru\s*$') {
    & $ssh -HostName $HostName -CaveatId $CaveatId `
      -RemoteCommand "esxcli hardware pci pcipassthru set -d $bdf -e true -a" 2>$null
  }
}

$state = foreach ($bdf in $Device) {
  & $ssh -HostName $HostName -CaveatId $CaveatId `
    -RemoteCommand "esxcli hardware pci list | sed -n '/$bdf/,/^$/p'" 2>$null
}

$currentOwners = @($state | Select-String -Pattern '^\s+Current Owner:\s+VM Passthru\s*$')
if ($currentOwners.Count -ne $Device.Count) {
  $state
  throw "Only $($currentOwners.Count) of $($Device.Count) devices have Current Owner = VM Passthru."
}

$state | Select-String -Pattern '^[0-9]|Configured Owner|Current Owner|Passthru Capable|Parent Device|Dependent Device|Reset Method'
