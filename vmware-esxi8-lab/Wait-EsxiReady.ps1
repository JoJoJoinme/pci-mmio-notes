param(
  [string]$HostName = '169.254.239.77',
  [string]$CaveatId = 'esxi8-auto-codex-credentials',
  [int]$TimeoutSeconds = 420,
  [int]$PollSeconds = 10
)

$ErrorActionPreference = 'Stop'
$ssh = Join-Path $PSScriptRoot 'Invoke-EsxiCaveatSsh.ps1'
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$lastError = $null

while ((Get-Date) -lt $deadline) {
  try {
    $version = & $ssh -HostName $HostName -CaveatId $CaveatId `
      -RemoteCommand 'vim-cmd hostsvc/hostsummary >/dev/null && vmware -vl' 2>$null
    if ($LASTEXITCODE -eq 0 -and $version) {
      $version
      exit 0
    }
  } catch {
    $lastError = $_
  }
  Start-Sleep -Seconds $PollSeconds
}

throw "ESXi did not become SSH-ready within $TimeoutSeconds seconds. Last error: $lastError"
