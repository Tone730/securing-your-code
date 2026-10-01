<#
.SYNOPSIS
  Shows a read-only snapshot of local processes and Windows Defender.

.DESCRIPTION
  Reports process name, ID, executable path, company, start time, CPU time,
  working set, and Authenticode status/signer where accessible. Also reports
  Windows Defender status and recent detection identifiers when its cmdlets
  are available. No command lines are collected and no system state is changed.

.PARAMETER Watch
  Repeats snapshots until stopped with Ctrl+C or the requested iteration limit.

.PARAMETER IntervalSeconds
  Delay between snapshots when -Watch is used. Defaults to 60 seconds.

.PARAMETER Iterations
  Maximum snapshots when -Watch is used. Zero (the default) means no limit.

.PARAMETER AsJson
  Writes each snapshot as JSON instead of formatted console output.

.EXAMPLE
  .\tools\windows-process-monitor.ps1

.EXAMPLE
  .\tools\windows-process-monitor.ps1 -Watch -IntervalSeconds 30 -Iterations 4 -AsJson

.NOTES
  Windows PowerShell 5.1 or later. Some process fields and Defender data may
  require permissions or Defender cmdlets and can be unavailable. Signature
  status depends on local trust/revocation checks; NotSigned does not mean
  malicious. Execution policy may block unsigned scripts; follow local policy.
  This is not a malware scanner.
#>

[CmdletBinding()]
param (
  [switch] $Watch,
  [ValidateRange(5, 3600)]
  [int] $IntervalSeconds = 60,
  [ValidateRange(0, 100000)]
  [int] $Iterations = 0,
  [switch] $AsJson
)

function Get-ProcessProperty {
  param (
    [System.Diagnostics.Process] $Process,
    [string] $Name
  )

  try {
    return $Process.$Name
  } catch {
    return $null
  }
}

function Get-ProcessSnapshot {
  $signatureCache = @{}
  $processes = @(Get-Process -ErrorAction Stop | Sort-Object ProcessName, Id | ForEach-Object {
    $process = $_
    $path = Get-ProcessProperty -Process $process -Name 'Path'
    $company = Get-ProcessProperty -Process $process -Name 'Company'
    $startTime = Get-ProcessProperty -Process $process -Name 'StartTime'
    $cpuSeconds = Get-ProcessProperty -Process $process -Name 'CPU'
    $workingSetBytes = Get-ProcessProperty -Process $process -Name 'WorkingSet64'
    $signatureStatus = 'Unavailable'
    $signer = $null
    $signatureError = $null

    if ($path) {
      if (-not $signatureCache.ContainsKey($path)) {
        try {
          $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
          $signatureCache[$path] = [pscustomobject]@{
            Status = $signature.Status.ToString()
            Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
            Error = $null
          }
        } catch {
          $signatureCache[$path] = [pscustomobject]@{
            Status = 'Error'
            Signer = $null
            Error = $_.Exception.Message
          }
        }
      }
      $signatureStatus = $signatureCache[$path].Status
      $signer = $signatureCache[$path].Signer
      $signatureError = $signatureCache[$path].Error
    }

    $unavailableFields = @()
    if (-not $path) { $unavailableFields += 'ExecutablePath' }
    if (-not $company) { $unavailableFields += 'Company' }
    if ($null -eq $startTime) { $unavailableFields += 'StartTime' }
    if ($null -eq $cpuSeconds) { $unavailableFields += 'CpuSeconds' }
    if ($null -eq $workingSetBytes) { $unavailableFields += 'WorkingSetBytes' }

    [pscustomobject]@{
      ProcessName = $process.ProcessName
      ProcessId = $process.Id
      ExecutablePath = $path
      Company = $company
      StartTimeUtc = if ($startTime) { $startTime.ToUniversalTime().ToString('o') } else { $null }
      CpuSeconds = if ($null -ne $cpuSeconds) { [math]::Round($cpuSeconds, 2) } else { $null }
      WorkingSetMB = if ($null -ne $workingSetBytes) { [math]::Round($workingSetBytes / 1MB, 2) } else { $null }
      AuthenticodeStatus = $signatureStatus
      Signer = $signer
      SignatureError = $signatureError
      UnavailableFields = $unavailableFields
    }
  })

  $defenderStatus = [pscustomobject]@{
    Available = $false
    AMServiceEnabled = $null
    AntivirusEnabled = $null
    RealTimeProtectionEnabled = $null
    AntivirusSignatureLastUpdated = $null
    Error = $null
  }
  if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    try {
      $status = Get-MpComputerStatus -ErrorAction Stop
      $defenderStatus.Available = $true
      $defenderStatus.AMServiceEnabled = $status.AMServiceEnabled
      $defenderStatus.AntivirusEnabled = $status.AntivirusEnabled
      $defenderStatus.RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
      $defenderStatus.AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
    } catch {
      $defenderStatus.Error = $_.Exception.Message
    }
  } else {
    $defenderStatus.Error = 'Get-MpComputerStatus is unavailable.'
  }

  $defenderDetections = [pscustomobject]@{
    Available = $false
    Count = $null
    Recent = @()
    Error = $null
  }
  if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
    try {
      $detections = @(Get-MpThreatDetection -ErrorAction Stop)
      $defenderDetections.Available = $true
      $defenderDetections.Count = $detections.Count
      $defenderDetections.Recent = @($detections |
        Sort-Object InitialDetectionTime -Descending |
        Select-Object -First 20 |
        Select-Object @{ Name = 'ThreatId'; Expression = { $_.ThreatID } }, InitialDetectionTime, ActionSuccess)
    } catch {
      $defenderDetections.Error = $_.Exception.Message
    }
  } else {
    $defenderDetections.Error = 'Get-MpThreatDetection is unavailable.'
  }

  [pscustomobject]@{
    CapturedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    ProcessCount = $processes.Count
    Processes = $processes
    DefenderStatus = $defenderStatus
    DefenderDetections = $defenderDetections
  }
}

function Show-ProcessSnapshot {
  param ([pscustomobject] $Snapshot)

  Write-Output ("Snapshot UTC: {0} ({1} processes)" -f $Snapshot.CapturedAtUtc, $Snapshot.ProcessCount)
  if ($Snapshot.DefenderStatus.Available) {
    Write-Output ("Defender: service={0}; antivirus={1}; real-time={2}; signatures updated={3}" -f
      $Snapshot.DefenderStatus.AMServiceEnabled,
      $Snapshot.DefenderStatus.AntivirusEnabled,
      $Snapshot.DefenderStatus.RealTimeProtectionEnabled,
      $Snapshot.DefenderStatus.AntivirusSignatureLastUpdated)
  } else {
    Write-Warning ("Defender status unavailable: {0}" -f $Snapshot.DefenderStatus.Error)
  }
  if ($Snapshot.DefenderDetections.Available) {
    Write-Output ("Defender detections: {0} total; showing at most 20 recent detection IDs" -f $Snapshot.DefenderDetections.Count)
    if ($Snapshot.DefenderDetections.Recent.Count -gt 0) {
      $Snapshot.DefenderDetections.Recent | Format-Table -AutoSize | Out-String | Write-Output
    }
  } else {
    Write-Warning ("Defender detections unavailable: {0}" -f $Snapshot.DefenderDetections.Error)
  }
  $Snapshot.Processes |
    Select-Object ProcessName, ProcessId, Company, AuthenticodeStatus, Signer, CpuSeconds, WorkingSetMB, ExecutablePath |
    Format-Table -AutoSize |
    Out-String |
    Write-Output
}

$iteration = 0
do {
  $snapshot = Get-ProcessSnapshot
  if ($AsJson) {
    $snapshot | ConvertTo-Json -Depth 6
  } else {
    Show-ProcessSnapshot -Snapshot $snapshot
  }
  $iteration++
  if (-not $Watch -or ($Iterations -gt 0 -and $iteration -ge $Iterations)) {
    break
  }
  Start-Sleep -Seconds $IntervalSeconds
} while ($true)
