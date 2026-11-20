#requires -version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Menu', 'UpdateAndReport', 'VerifyOnly')]
    [string]$Mode = 'Menu',
    [string]$OutputDirectory = (Join-Path $env:ProgramData 'StandaloneUpdater\Reports'),
    [switch]$NoOpenReport,
    [switch]$Launcher
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($WhatIfPreference) {
    [void]$PSCmdlet.ShouldProcess($PSScriptRoot, "Offline maintenance: $Mode")
    return
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if (-not $Launcher) { throw 'Run Windows PowerShell as Administrator, or use Start-OfflineUpdate.cmd.' }
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path "$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe") { $powershell = "$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe" }
    $arguments = "-NoProfile -File `"$PSCommandPath`" -Mode $Mode -OutputDirectory `"$OutputDirectory`" -Launcher"
    if ($NoOpenReport) { $arguments += ' -NoOpenReport' }
    try { $child = Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -Wait -PassThru; exit $child.ExitCode }
    catch { throw "Administrator approval was not completed. No updates were installed. $($_.Exception.Message)" }
}
if ($Mode -eq 'Menu') {
    Write-Host ''
    Write-Host 'Standalone Updater'
    Write-Host '  1  Update Defender, Edge and Office, then create a report'
    Write-Host '  2  Verify only: refresh Windows scan and software inventory (default)'
    Write-Host '  3  Exit'
    do { $choice = Read-Host 'Choose 1, 2 or 3 [2]' } while ($choice -notin @('', '1', '2', '3'))
    if ($choice -eq '3') { return }
    $Mode = if ($choice -eq '1') { 'UpdateAndReport' } else { 'VerifyOnly' }
}
if (-not $PSCmdlet.ShouldProcess($PSScriptRoot, $Mode)) { return }
if ($Mode -eq 'UpdateAndReport') {
    Write-Host 'Save your work, close Office apps and open Edge windows, and confirm an approved backup/maintenance window is available.'
    if ((Read-Host 'Press Enter to start product updates; type anything to cancel') -cne '') { Write-Host 'Cancelled. Nothing was installed.'; return }
}
Import-Module (Join-Path $PSScriptRoot '00-Control\OfflineUpdate.Common.psm1') -Force -DisableNameChecking
$directory = New-LocalReportDirectory -BaseDirectory $OutputDirectory
$exitCode = 0
Start-Transcript -Path (Join-Path $directory 'Maintenance.log') | Out-Null
try {
    Write-Host "Mode: $Mode"
    Write-Host "Reports and logs stay local: $directory"
    Write-Host 'Package verification and the offline Windows scan may take several minutes.'
    $report = Invoke-OfflineMaintenance -Mode $Mode -Root $PSScriptRoot -Directory $directory
    Write-Host "Scan: $($report.Scan.Status)"
    Write-ProductUpdateSummary -Mode $Mode -Results $report.ProductResults
    Write-Host "Report: $($report.ReportPath)"
    $failures = @($report.ProductResults | Where-Object { $_.Status -in @('Failed', 'Blocked', 'Unsupported') })
    if ($report.Scan.Status -ne 'Succeeded' -or $failures.Count -gt 0) { $exitCode = 1 }
    elseif (@($report.ProductResults | Where-Object { $_.Status -eq 'RebootRequired' }).Count -gt 0 -or
        ($null -ne $report.Inventory -and $report.Inventory.PendingReboot.Any)) { $exitCode = 3010 }
    if (-not $NoOpenReport) {
        try { Start-Process -FilePath $report.ReportPath | Out-Null }
        catch { Write-Warning "Could not open the report automatically. Open $($report.ReportPath) locally." }
    }
    Write-Host 'Install required Windows patches manually. After servicing and any restart, run Verify Only again.'
}
catch { $exitCode = 1; Write-Warning "Maintenance failed: $($_.Exception.Message). Review $directory" }
finally { Stop-Transcript | Out-Null }
exit $exitCode