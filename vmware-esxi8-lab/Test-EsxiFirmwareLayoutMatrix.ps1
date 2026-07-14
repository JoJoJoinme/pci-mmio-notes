param(
  [string]$HostName = '172.31.91.10',

  [ValidatePattern('^[A-Za-z0-9_.-]+$')]
  [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-firmware-layout',

  [switch]$IncludeDefaultControls,

  [switch]$AnalyzeOnly,

  [ValidateSet('Auto', 'Template', 'PcieRootPorts')]
  [string]$BridgePolicy = 'Auto',

  [string[]]$CaseId = @()
)

$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot 'Run-EsxiDirectPathMmioCase.ps1'
$workspace = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path (Split-Path -Parent $workspace) '_artifacts\vmware-directpath-runs'
$runRoot = Join-Path $artifactRoot $RunId
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null

$cases = @(
  [ordered]@{ id = 'LF00-i440bx-bios'; firmware = 'Bios'; layout = 'I440Bx'; expected = 'guest-completed'; largeBarMapped = $false },
  [ordered]@{ id = 'LF01-i440bx-efi'; firmware = 'Efi'; layout = 'I440Bx'; expected = 'guest-completed'; largeBarMapped = $true },
  [ordered]@{ id = 'LF02-acpi-efi'; firmware = 'Efi'; layout = 'Acpi'; expected = 'guest-completed'; largeBarMapped = $true },
  [ordered]@{ id = 'LF03-acpi-bios-negative'; firmware = 'Bios'; layout = 'Acpi'; expected = 'power-on-failed'; largeBarMapped = $null }
)
if ($IncludeDefaultControls) {
  $cases += @(
    [ordered]@{ id = 'LF04-absent-bios-default'; firmware = 'Bios'; layout = 'Absent'; expected = 'guest-completed'; largeBarMapped = $false },
    [ordered]@{ id = 'LF05-absent-efi-default'; firmware = 'Efi'; layout = 'Absent'; expected = 'guest-completed'; largeBarMapped = $true }
  )
}
if ($CaseId.Count -gt 0) {
  $known = @($cases.id)
  $unknown = @($CaseId | Where-Object { $_ -notin $known })
  if ($unknown.Count -gt 0) {
    throw "Unknown case id(s): $($unknown -join ', ')"
  }
  $cases = @($cases | Where-Object { $_.id -in $CaseId })
}

function Read-TextIfPresent {
  param([string]$Path)
  if (Test-Path -LiteralPath $Path) {
    return Get-Content -LiteralPath $Path -Raw -Encoding utf8
  }
  return ''
}

function Select-Lines {
  param([string]$Text, [string]$Pattern)
  if (-not $Text) {
    return @()
  }
  return @($Text -split "`r?`n" | Where-Object { $_ -match $Pattern })
}

$summary = [ordered]@{
  schemaVersion = 1
  runId = $RunId
  host = $HostName
  startedAt = (Get-Date).ToUniversalTime().ToString('o')
  invariant = [ordered]@{
    virtualHardwareVersion = 20
    passthruBarSizeGiB = 2
    use64bitMmio = 'absent'
    bridgePolicy = $BridgePolicy.ToLowerInvariant()
  }
  cases = @()
  verdict = 'running'
}
$summaryPath = Join-Path $runRoot 'firmware-layout-matrix.json'

foreach ($case in $cases) {
  $runnerFault = $null
  if (-not $AnalyzeOnly) {
    try {
      & $runner -CaseId $case.id -Firmware $case.firmware `
        -MotherboardLayout $case.layout -BridgePolicy $BridgePolicy `
        -Use64BitMmio Absent -HostName $HostName -RunId $RunId | Out-Null
    } catch {
      $runnerFault = $_ | Out-String
    }
  }

  $caseRoot = Join-Path $runRoot $case.id
  $caseJsonPath = Join-Path $caseRoot 'case.json'
  $caseMetadata = $null
  if (Test-Path -LiteralPath $caseJsonPath) {
    $caseMetadata = Get-Content -LiteralPath $caseJsonPath -Raw -Encoding utf8 | ConvertFrom-Json
  }
  $inputVmx = Read-TextIfPresent (Join-Path $caseRoot "$($case.id).vmx")
  $effectiveVmx = Read-TextIfPresent (Join-Path $caseRoot 'effective.vmx')
  $vmwareLog = Read-TextIfPresent (Join-Path $caseRoot 'vmware.log')
  $serialPath = Get-ChildItem -LiteralPath $caseRoot -Filter 'guest-serial*.log' -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
  $serial = if ($serialPath) { Read-TextIfPresent $serialPath } else { '' }

  $targetLines = @()
  $captureTarget = $false
  foreach ($line in ($serial -split "`r?`n")) {
    if ($line -match '^\S+\s+vendor=0x1af4\s+device=0x1110\b') {
      $captureTarget = $true
      $targetLines += $line
      continue
    }
    if ($captureTarget -and $line -match '^\S+\s+vendor=0x[0-9a-f]+\s+device=') {
      $captureTarget = $false
    }
    if ($captureTarget -and ($line -match '^\s+(resource|BAR)' -or -not $line.Trim())) {
      $targetLines += $line
    }
  }

  $runnerVerdict = if ($caseMetadata) { $caseMetadata.verdict } elseif ($runnerFault) { 'runner-failed' } else { 'missing-result' }
  $actual = if ($serial -match '=== done ===') { 'guest-completed' } else { $runnerVerdict }
  $negativeMessage = $vmwareLog -match 'ACPI motherboard layout requires EFI\.'
  $targetVisible = $serial -match 'vendor=0x1af4\s+device=0x1110'
  $iommuMapped = $vmwareLog -match 'successfully created the IOMMU mappings'
  $guestCompleted = $actual -eq 'guest-completed' -and $serial -match '=== done ==='
  $targetText = $targetLines -join "`n"
  $largeBarMapped = $false
  if ($targetText -match '(?m)^\s*resource2\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+') {
    $barStart = [Convert]::ToUInt64($Matches[1], 16)
    $barEnd = [Convert]::ToUInt64($Matches[2], 16)
    $largeBarMapped = $barStart -ne 0 -and ($barEnd - $barStart + 1) -eq 2GB
  }
  $largeBarMatches = $null -eq $case.largeBarMapped -or $largeBarMapped -eq $case.largeBarMapped
  $behaviorMatches = if ($case.expected -eq 'power-on-failed') {
    $actual -eq 'power-on-failed' -and $negativeMessage
  } else {
    $guestCompleted -and $targetVisible -and $iommuMapped -and $largeBarMatches
  }

  $requestedLayout = $case.layout.ToLowerInvariant()
  $layoutInputMatches = if ($requestedLayout -eq 'absent') {
    $inputVmx -notmatch '(?m)^chipset\.motherboardLayout\s*='
  } else {
    $expectedLayout = if ($requestedLayout -eq 'i440bx') { 'i440bx' } else { 'acpi' }
    $inputVmx -match "(?m)^chipset\.motherboardLayout\s*=\s*`"$expectedLayout`""
  }
  $firmwareInputMatches = $inputVmx -match "(?m)^firmware\s*=\s*`"$($case.firmware.ToLowerInvariant())`""

  $summary.cases += [ordered]@{
    id = $case.id
    request = [ordered]@{
      firmware = $case.firmware.ToLowerInvariant()
      motherboardLayout = $requestedLayout
      expected = $case.expected
      expectedLargeBarMapped = $case.largeBarMapped
    }
    observed = [ordered]@{
      runnerVerdict = $runnerVerdict
      effectiveVerdict = $actual
      guestCompleted = $guestCompleted
      directPathTargetVisible = $targetVisible
      iommuMappingsCreated = $iommuMapped
      largeBarMapped = $largeBarMapped
      acpiRequiresEfiMessage = $negativeMessage
      rootBridgeLines = @(Select-Lines $serial 'ACPI: PCI Root Bridge|PCI host bridge to bus|root bus resource')
      chipsetLines = @(Select-Lines $serial '\[8086:(7190|7191|7110|7111|7113)\]|vendor=0x8086 device=0x(7190|7191|7110|7111|7113)')
      targetLines = $targetLines
      vmxDictLines = @(Select-Lines $vmwareLog 'DICT\s+(firmware|chipset\.motherboardLayout)|Chipset version|RootBridge:')
      powerOnFailureLines = @(Select-Lines $vmwareLog 'Power on failure messages:|DevicePowerOnEarly')
    }
    assertions = [ordered]@{
      layoutInputMatches = $layoutInputMatches
      firmwareInputMatches = $firmwareInputMatches
      largeBarMatches = $largeBarMatches
      behaviorMatches = $behaviorMatches
    }
    runnerFault = $runnerFault
    pass = $layoutInputMatches -and $firmwareInputMatches -and $behaviorMatches
  }
  $summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding utf8
}

$summary.verdict = if ($summary.cases.Count -gt 0 -and -not ($summary.cases.pass -contains $false)) { 'pass' } else { 'fail' }
$summary.finishedAt = (Get-Date).ToUniversalTime().ToString('o')
$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding utf8
$summary | ConvertTo-Json -Depth 12

if ($summary.verdict -ne 'pass') {
  exit 1
}
