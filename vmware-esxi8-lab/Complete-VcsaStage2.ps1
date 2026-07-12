param(
  [string]$HostName = '192.168.91.131',
  [string]$ApplianceFqdn = 'vcsa.pci.test',
  [string]$ApplianceAddress = '192.168.91.131',
  [int]$PrefixLength = 24,
  [string]$DefaultGateway = '192.168.91.2',
  [string[]]$DnsServers = @('192.168.91.2'),
  [string]$SsoDomain = 'vsphere.local',
  [string]$CaveatId = 'vcsa803-codex-credentials',
  [int]$TimeoutMinutes = 90,
  [switch]$SkipNetworkConfiguration,
  [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$baseUri = "https://${HostName}:5480/rest"
$script:sessionToken = $null

function Get-CaveatCredential {
  $savedPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $entry = (& wsl -e caveat show $CaveatId 2>$null) -join "`n"
  $ErrorActionPreference = $savedPreference

  if ($entry -notmatch 'Root Password:\s*(\S+)') {
    throw "Caveat '$CaveatId' does not contain a Root Password field."
  }
  $rootPassword = $Matches[1]
  if ($entry -notmatch 'SSO Password:\s*(\S+)') {
    throw "Caveat '$CaveatId' does not contain an SSO Password field."
  }

  [pscustomobject]@{
    RootPassword = $rootPassword
    SsoPassword = $Matches[1]
  }
}

function Invoke-CurlJson {
  param(
    [Parameter(Mandatory)][string]$Method,
    [Parameter(Mandatory)][string]$Uri,
    [object]$Body,
    [string[]]$Headers = @()
  )

  $bodyPath = $null
  try {
    $arguments = @(
      '--insecure', '--silent', '--show-error',
      '--connect-timeout', '10', '--max-time', '180',
      '--request', $Method,
      '--header', 'Accept: application/json',
      '--write-out', "`n%{http_code}",
      $Uri
    )
    foreach ($header in $Headers) {
      $arguments += @('--header', $header)
    }
    if ($null -ne $Body) {
      $bodyPath = [IO.Path]::GetTempFileName()
      $json = $Body | ConvertTo-Json -Depth 12 -Compress
      [IO.File]::WriteAllText($bodyPath, $json, [Text.UTF8Encoding]::new($false))
      $arguments += @(
        '--header', 'Content-Type: application/json',
        '--data-binary', "@$bodyPath"
      )
    }

    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $raw = (& curl.exe @arguments 2>&1) -join "`n"
    $curlExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($curlExitCode -ne 0) {
      throw "curl failed for $Method $Uri (exit $curlExitCode): $raw"
    }
    if ($raw -notmatch '(?s)^(.*)\r?\n(\d{3})$') {
      throw "Could not parse HTTP status for $Method $Uri."
    }
    $responseBody = $Matches[1]
    $statusCode = [int]$Matches[2]
    if ($statusCode -lt 200 -or $statusCode -ge 300) {
      $exception = [InvalidOperationException]::new(
        "HTTP $statusCode for $Method $Uri`: $responseBody"
      )
      $exception.Data['StatusCode'] = $statusCode
      throw $exception
    }
    if ([string]::IsNullOrWhiteSpace($responseBody)) {
      return $null
    }
    return $responseBody | ConvertFrom-Json
  } finally {
    if ($bodyPath) {
      Remove-Item -LiteralPath $bodyPath -Force -ErrorAction SilentlyContinue
    }
  }
}

function New-VamiSession {
  param([Parameter(Mandatory)][string]$RootPassword)

  $basic = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes("root:$RootPassword")
  )
  $response = Invoke-CurlJson -Method POST `
    -Uri "$baseUri/com/vmware/cis/session" `
    -Body @{} `
    -Headers @("Authorization: Basic $basic")
  if (-not $response.value) {
    throw 'VAMI did not return an API session token.'
  }
  $script:sessionToken = $response.value
}

function Invoke-Vami {
  param(
    [Parameter(Mandatory)][string]$Method,
    [Parameter(Mandatory)][string]$Path,
    [object]$Body,
    [Parameter(Mandatory)][string]$RootPassword
  )

  if (-not $script:sessionToken) {
    New-VamiSession -RootPassword $RootPassword
  }
  try {
    return Invoke-CurlJson -Method $Method -Uri "$baseUri/$Path" -Body $Body `
      -Headers @("vmware-api-session-id: $script:sessionToken")
  } catch {
    if ($_.Exception.Data['StatusCode'] -ne 401) {
      throw
    }
    New-VamiSession -RootPassword $RootPassword
    return Invoke-CurlJson -Method $Method -Uri "$baseUri/$Path" -Body $Body `
      -Headers @("vmware-api-session-id: $script:sessionToken")
  }
}

function Wait-VamiSession {
  param(
    [Parameter(Mandatory)][string]$RootPassword,
    [int]$TimeoutSeconds = 900
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    try {
      $script:sessionToken = $null
      New-VamiSession -RootPassword $RootPassword
      return
    } catch {
      if ((Get-Date) -ge $deadline) {
        throw
      }
      Start-Sleep -Seconds 10
    }
  } while ($true)
}

function Set-VcsaHostRecord {
  $ssh = Join-Path $PSScriptRoot 'Invoke-EsxiCaveatSsh.ps1'
  $shortName = $ApplianceFqdn.Split('.')[0]
  $command = "grep -Eq '^127[.]0[.]0[.]1[[:space:]]+.*localhost' /etc/hosts || echo 127.0.0.1 localhost localhost.localdomain >> /etc/hosts; grep -q $ApplianceFqdn /etc/hosts || echo $ApplianceAddress $ApplianceFqdn $shortName >> /etc/hosts"
  & $ssh -HostName $HostName -CaveatId $CaveatId -RemoteCommand $command | Out-Null
}

function Set-VcsaNetworkConfiguration {
  param([Parameter(Mandatory)][string]$RootPassword)

  Write-Host "Configuring VCSA system name as $ApplianceFqdn"
  Set-VcsaHostRecord
  $network = Invoke-Vami -Method GET -Path 'appliance/networking' `
    -RootPassword $RootPassword
  if ($network.dns.hostname -ne $ApplianceFqdn) {
    Invoke-Vami -Method PUT -Path 'appliance/networking/dns/hostname' `
      -Body @{ name = $ApplianceFqdn } -RootPassword $RootPassword | Out-Null
  }

  Wait-VamiSession -RootPassword $RootPassword -TimeoutSeconds 300
  $network = Invoke-Vami -Method GET -Path 'appliance/networking' `
    -RootPassword $RootPassword
  $nic = $network.interfaces | Where-Object key -eq 'nic0' | Select-Object -ExpandProperty value
  if ($nic.ipv4.mode -ne 'STATIC' -or
      $nic.ipv4.address -ne $ApplianceAddress -or
      $nic.ipv4.prefix -ne $PrefixLength -or
      $nic.ipv4.default_gateway -ne $DefaultGateway) {
    try {
      Invoke-Vami -Method PUT -Path 'appliance/networking/interfaces/nic0/ipv4' `
        -Body @{ config = @{
            mode = 'STATIC'
            address = $ApplianceAddress
            prefix = $PrefixLength
            default_gateway = $DefaultGateway
          } } -RootPassword $RootPassword | Out-Null
    } catch {
      Write-Host 'The IPv4 control connection was interrupted by the network reload; reconnecting to verify.'
    }
    Wait-VamiSession -RootPassword $RootPassword -TimeoutSeconds 600
    $network = Invoke-Vami -Method GET -Path 'appliance/networking' `
      -RootPassword $RootPassword
    $nic = $network.interfaces | Where-Object key -eq 'nic0' | Select-Object -ExpandProperty value
    if ($nic.ipv4.mode -ne 'STATIC' -or $nic.ipv4.address -ne $ApplianceAddress) {
      throw 'VCSA IPv4 configuration did not survive the network reload.'
    }
  }

  $configuredDns = @($network.dns.servers | Sort-Object) -join ','
  $requestedDns = @($DnsServers | Sort-Object) -join ','
  if ($configuredDns -ne $requestedDns -or $network.dns.mode -eq 'DHCP') {
    Invoke-Vami -Method PUT -Path 'appliance/networking/dns/servers' `
      -Body @{ config = @{ mode = 'is_static'; servers = $DnsServers } } `
      -RootPassword $RootPassword | Out-Null
  }
  if ($nic.ipv6.dhcp -or $nic.ipv6.autoconf) {
    Invoke-Vami -Method PUT -Path 'appliance/networking/interfaces/nic0/ipv6' `
      -Body @{ config = @{
          addresses = @()
          autoconf = $false
          default_gateway = ''
          dhcp = $false
        } } -RootPassword $RootPassword | Out-Null
  }
  $timesync = Invoke-Vami -Method GET -Path 'appliance/timesync' `
    -RootPassword $RootPassword
  if ($timesync.value -ne 'HOST') {
    Invoke-Vami -Method PUT -Path 'appliance/timesync' `
      -Body @{ mode = 'HOST' } -RootPassword $RootPassword | Out-Null
  }
  $ssh = Invoke-Vami -Method GET -Path 'appliance/access/ssh' `
    -RootPassword $RootPassword
  if (-not $ssh.value) {
    Invoke-Vami -Method PUT -Path 'appliance/access/ssh' `
      -Body @{ enabled = $true } -RootPassword $RootPassword | Out-Null
  }

  Set-VcsaHostRecord
  $network = Invoke-Vami -Method GET -Path 'appliance/networking' `
    -RootPassword $RootPassword
  $nic = $network.interfaces | Where-Object key -eq 'nic0' | Select-Object -ExpandProperty value
  $timesync = Invoke-Vami -Method GET -Path 'appliance/timesync' `
    -RootPassword $RootPassword
  if ($network.dns.hostname -ne $ApplianceFqdn -or
      $nic.ipv4.mode -ne 'STATIC' -or
      $nic.ipv4.address -ne $ApplianceAddress -or
      $nic.ipv6.dhcp -or $nic.ipv6.autoconf -or
      $timesync.value -ne 'HOST') {
    throw 'VCSA network verification did not match the requested static configuration.'
  }
  Write-Host "VCSA network verified: $($network.dns.hostname) $($nic.ipv4.address)/$($nic.ipv4.prefix)"
}

$credential = Get-CaveatCredential
Wait-VamiSession -RootPassword $credential.RootPassword -TimeoutSeconds 300

$state = Invoke-Vami -Method GET -Path 'vcenter/deployment/state' `
  -RootPassword $credential.RootPassword
Write-Host "Initial Stage 2 state: $($state.current_state)"
if ($state.current_state -eq 'SUCCEEDED') {
  Write-Host 'VCSA Stage 2 is already complete.'
  exit 0
}
if ($state.current_state -notin @('NOT_STARTED', 'FAILED')) {
  Write-Host 'A Stage 2 workflow is already active; monitoring it without resubmitting.'
} else {
  if (-not $SkipNetworkConfiguration) {
    Set-VcsaNetworkConfiguration -RootPassword $credential.RootPassword
  }

  $installSpec = @{
    spec = @{
      auto_answer = $true
      vcsa_embedded = @{
        ceip_enabled = $false
        standalone = @{
          sso_domain_name = $SsoDomain
          sso_admin_password = $credential.SsoPassword
        }
      }
    }
  }
  Write-Host "Checking embedded VCSA install spec for SSO domain $SsoDomain"
  $check = Invoke-Vami -Method POST -Path 'vcenter/deployment/install?action=check' `
    -Body $installSpec -RootPassword $credential.RootPassword
  if ($check.status -ne 'SUCCESS') {
    throw "VCSA Stage 2 precheck failed: $($check | ConvertTo-Json -Depth 12 -Compress)"
  }
  Write-Host 'VCSA Stage 2 precheck: SUCCESS'
  if ($CheckOnly) {
    exit 0
  }

  Invoke-Vami -Method POST -Path 'vcenter/deployment/install?action=start' `
    -Body $installSpec -RootPassword $credential.RootPassword | Out-Null
  Write-Host 'VCSA Stage 2 start request accepted.'
}

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$lastState = $null
do {
  try {
    $state = Invoke-Vami -Method GET -Path 'vcenter/deployment/state' `
      -RootPassword $credential.RootPassword
    if ($state.current_state -ne $lastState) {
      Write-Host "Stage 2 state: $($state.current_state)"
      $lastState = $state.current_state
    }
    if ($state.current_state -eq 'SUCCEEDED') {
      Write-Host 'VCSA Stage 2 completed successfully.'
      exit 0
    }
    if ($state.current_state -eq 'FAILED') {
      $details = Invoke-Vami -Method GET -Path 'vcenter/deployment/state/details' `
        -RootPassword $credential.RootPassword
      throw "VCSA Stage 2 failed: $($details | ConvertTo-Json -Depth 12 -Compress)"
    }
  } catch {
    if ($_.Exception.Message -like 'VCSA Stage 2 failed:*') {
      throw
    }
    if ((Get-Date) -ge $deadline) {
      throw
    }
    Write-Host 'VAMI is restarting or temporarily unavailable; retrying.'
    Start-Sleep -Seconds 15
    Wait-VamiSession -RootPassword $credential.RootPassword -TimeoutSeconds 600
    continue
  }
  if ((Get-Date) -ge $deadline) {
    throw "Timed out after $TimeoutMinutes minutes waiting for VCSA Stage 2."
  }
  Start-Sleep -Seconds 15
} while ($true)
