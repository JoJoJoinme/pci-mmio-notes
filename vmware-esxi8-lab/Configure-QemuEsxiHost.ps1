param(
  [Parameter(Mandatory)]
  [string]$CurrentAddress,
  [Parameter(Mandatory)]
  [string]$StaticAddress,
  [Parameter(Mandatory)]
  [string]$Fqdn,
  [string]$InterfaceName = 'vmk0',
  [string]$Gateway = '172.31.91.1',
  [string]$Netmask = '255.255.255.0',
  [string]$NfsHost = '172.31.91.1',
  [string]$NfsShare = '/root/vm/esxi8-mf/nfsds',
  [string]$NfsVolume = 'qemu-shared',
  [string]$PortGroup = 'Management Network',
  [string]$VmkMac = '',
  [string]$RemoveInterface = '',
  [string]$VcenterNetwork = '192.168.91.0/24',
  [string]$TunnelNetwork = '10.255.91.0/30',
  [string]$CaveatId = 'esxi8-auto-codex-credentials',
  [int]$TimeoutSeconds = 420
)

$ErrorActionPreference = 'Stop'
$ssh = Join-Path $PSScriptRoot 'Invoke-EsxiCaveatSsh.ps1'
$wait = Join-Path $PSScriptRoot 'Wait-EsxiReady.ps1'

$copy = Join-Path $PSScriptRoot 'Copy-EsxiCaveatFile.ps1'
$remoteScript = '/tmp/codex-configure-host.sh'
$localScript = Join-Path $PSScriptRoot 'configure-qemu-esxi-host.sh'
$wslScript = (& wsl -e wslpath -a $localScript).Trim()
if (-not $wslScript) {
  throw "Unable to translate '$localScript' to a WSL path."
}

& $copy -HostName $CurrentAddress -CaveatId $CaveatId -Direction ToEsxi `
  -Source $wslScript -Destination $remoteScript

$launch = "chmod 700 $remoteScript; rm -f /tmp/codex-configure-host.done; " +
  "nohup /bin/sh $remoteScript '$StaticAddress' '$Fqdn' '$InterfaceName' " +
  "'$Gateway' '$Netmask' '$NfsHost' '$NfsShare' '$NfsVolume' " +
  "'$PortGroup' '$VmkMac' '$RemoveInterface' '$VcenterNetwork' '$TunnelNetwork' " +
  ">/tmp/codex-configure-host.log 2>&1 </dev/null &"

& $ssh -HostName $CurrentAddress -CaveatId $CaveatId -RemoteCommand $launch
& $wait -HostName $StaticAddress -CaveatId $CaveatId `
  -TimeoutSeconds $TimeoutSeconds -PollSeconds 5

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$complete = $false
while ((Get-Date) -lt $deadline) {
  $state = & $ssh -HostName $StaticAddress -CaveatId $CaveatId `
    -RemoteCommand 'if [ -f /tmp/codex-configure-host.done ]; then echo DONE; else echo WAITING; fi'
  if ($state -contains 'DONE') {
    $complete = $true
    break
  }
  Start-Sleep -Seconds 3
}
if (-not $complete) {
  throw "ESXi host configuration did not finish within $TimeoutSeconds seconds."
}

$verify = "cat /tmp/codex-configure-host.log; echo UUID; esxcfg-info -u; " +
  "echo NETWORK; esxcli network ip interface ipv4 get; " +
  "echo ROUTES; esxcli network ip route ipv4 list; " +
  "echo TAGS; esxcli network ip interface tag get -i '$InterfaceName'; " +
  "echo NFS; esxcli storage nfs list; " +
  "echo PASSTHRU; esxcli hardware pci pcipassthru list"
& $ssh -HostName $StaticAddress -CaveatId $CaveatId -RemoteCommand $verify
