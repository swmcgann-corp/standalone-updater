#requires -version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CabPath,
    [string]$OutputDirectory = (Join-Path $env:ProgramData 'StandaloneUpdater\Reports'),
    [switch]$NoOpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\00-Control\OfflineUpdate.Common.psm1') -Force -DisableNameChecking
$directory = New-LocalReportDirectory -BaseDirectory $OutputDirectory
Start-Transcript -Path (Join-Path $directory 'Scan.log') | Out-Null
try {
    $package = $null
    $metadataPath = Join-Path $PSScriptRoot '..\00-Control\Package.json'
    if (Test-Path -LiteralPath $metadataPath) { $package = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json }
    $report = Invoke-OfflineAssessment -CabPath $CabPath -Directory $directory -Package $package
    Write-Host "Scan: $($report.Scan.Status)"
    Write-Host "Local report: $($report.ReportPath)"
    if (-not $NoOpenReport) {
        try { Start-Process -FilePath $report.ReportPath | Out-Null }
        catch { Write-Warning "Could not open the report automatically. Open $($report.ReportPath) locally." }
    }
    if ($report.Scan.Status -ne 'Succeeded') { throw 'Scan failed. Review the saved report; missing patch count is unknown.' }
}
finally { Stop-Transcript | Out-Null }
