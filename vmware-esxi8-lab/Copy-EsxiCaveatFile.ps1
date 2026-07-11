param(
  [string]$HostName = '169.254.239.77',
  [string]$UserName = 'root',
  [string]$CaveatId = 'esxi8-auto-codex-credentials',
  [Parameter(Mandatory)]
  [ValidateSet('ToEsxi', 'FromEsxi')]
  [string]$Direction,
  [Parameter(Mandatory)]
  [string]$Source,
  [Parameter(Mandatory)]
  [string]$Destination
)

$ErrorActionPreference = 'Stop'
$savedErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$entry = & wsl -e caveat show $CaveatId 2>$null
$ErrorActionPreference = $savedErrorActionPreference
$text = $entry -join "`n"
if ($text -notmatch 'Password:\s*(\S+)') {
  throw "Caveat '$CaveatId' does not contain a Password field."
}

$oldWslEnv = $env:WSLENV
$env:SSHPASS = $Matches[1]
$env:WSLENV = if ($oldWslEnv) { "SSHPASS:$oldWslEnv" } else { 'SSHPASS' }

try {
  $ErrorActionPreference = 'Continue'
  $common = @(
    '-e', 'sshpass', '-e', 'scp',
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=/dev/null',
    '-o', 'LogLevel=ERROR',
    '-o', 'ConnectTimeout=8'
  )
  if ($Direction -eq 'ToEsxi') {
    & wsl @common $Source "${UserName}@${HostName}:$Destination"
  } else {
    & wsl @common "${UserName}@${HostName}:$Source" $Destination
  }
  $code = $LASTEXITCODE
  $ErrorActionPreference = $savedErrorActionPreference
  if ($code -ne 0) {
    throw "ESXi SCP failed with exit code $code."
  }
} finally {
  Remove-Item Env:SSHPASS -ErrorAction SilentlyContinue
  if ($null -eq $oldWslEnv) {
    Remove-Item Env:WSLENV -ErrorAction SilentlyContinue
  } else {
    $env:WSLENV = $oldWslEnv
  }
}
