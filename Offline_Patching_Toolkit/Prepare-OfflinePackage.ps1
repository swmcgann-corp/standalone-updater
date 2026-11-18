#requires -version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'Deployments'),
    [uri]$Proxy,
    [switch]$ProxyUseDefaultCredentials
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '00-Control\OfflineUpdate.Common.psm1') -Force -DisableNameChecking
if (-not $PSCmdlet.ShouldProcess($OutputDirectory, 'Download Microsoft payloads and create a dated deployment folder (several GB)')) { return }
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Run preparation in 64-bit Windows PowerShell on the connected Windows PC.' }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($OutputDirectory))
if ($drive.AvailableFreeSpace -lt 25GB) { throw 'Preparation requires at least 25 GB free on the output drive.' }
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force)
$name = 'Deploy_{0}_{1}' -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 6)
$staging = Join-Path $OutputDirectory ($name + '.incomplete')
[void](New-Item -ItemType Directory -Path $staging)
$work = Join-Path $staging '.preparation'
[void](New-Item -ItemType Directory -Path $work)
$transcribing = $false
try {
    Start-Transcript -Path (Join-Path $work 'Preparation.log') | Out-Null
    $transcribing = $true
    $files = @('Run-OfflineMaintenance.ps1', 'Start-OfflineUpdate.cmd', 'README.md',
        '00-Control\OfflineUpdate.Common.psm1', '00-Control\Test-PayloadManifest.ps1', '10-Scan\Scan-OfflinePC.ps1')
    foreach ($relative in $files) {
        $source = Join-Path $PSScriptRoot $relative
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Toolkit source file missing: $relative" }
        $destination = Join-Path $staging $relative
        [void](New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force)
        Copy-Item -LiteralPath $source -Destination $destination
    }
    $downloadOptions = @{}
    $metadataOptions = @{ UseBasicParsing = $true; TimeoutSec = 120; ErrorAction = 'Stop' }
    if ($null -ne $Proxy) { $downloadOptions.Proxy = $Proxy; $metadataOptions.Proxy = $Proxy }
    if ($ProxyUseDefaultCredentials) { $downloadOptions.ProxyUseDefaultCredentials = $true; $metadataOptions.ProxyUseDefaultCredentials = $true }

    Write-Host '[1/5] Downloading the latest Microsoft offline scan catalog...'
    $catalog = Invoke-OfficialDownload -Uri 'https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab' `
        -Destination (Join-Path $staging '10-Scan\wsusscn2.cab') -Kind Cab @downloadOptions

    Write-Host '[2/5] Downloading Defender x64 security intelligence and engine...'
    [xml]$definitionInfo = (Invoke-WebRequest -Uri 'https://definitionupdates.microsoft.com/packages?action=info' @metadataOptions).Content
    $defenderPath = '20-Payload\Defender\mpam-fe.exe'
    $defenderDownload = Invoke-OfficialDownload -Uri 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64' `
        -Destination (Join-Path $staging $defenderPath) -Kind Exe @downloadOptions
    $signatureVersion = (Get-Item -LiteralPath (Join-Path $staging $defenderPath)).VersionInfo.FileVersion
    [void](Test-VersionAtLeast $signatureVersion $signatureVersion)

    Write-Host '[3/5] Downloading Edge Stable x64 enterprise MSI...'
    $products = (Invoke-WebRequest -Uri 'https://edgeupdates.microsoft.com/api/products?view=enterprise' @metadataOptions).Content | ConvertFrom-Json
    $edge = Get-EdgeStableArtifact -Products $products
    $edgePath = '20-Payload\Edge\MicrosoftEdgeEnterpriseX64.msi'
    $edgeDownload = Invoke-OfficialDownload -Uri $edge.Uri -Destination (Join-Path $staging $edgePath) -Kind Msi @downloadOptions
    if ((Get-FileHash -LiteralPath (Join-Path $staging $edgePath) -Algorithm SHA256).Hash -ne $edge.SHA256) {
        throw 'Edge MSI does not match the SHA256 hash published in the Microsoft enterprise feed.'
    }

    Write-Host '[4/5] Downloading the current Office Deployment Tool...'
    $setupPath = '30-Office\setup.exe'
    $odt = Invoke-OfficialDownload -Uri 'https://officecdn.microsoft.com/pr/wsus/setup.exe' `
        -Destination (Join-Path $staging $setupPath) -Kind Exe @downloadOptions
    $setup = Join-Path $staging $setupPath

    Write-Host '[5/5] Downloading complete Office LTSC 2021 and 2024 en-US sources (several GB)...'
    Write-Host 'Office download progress is recorded by the Office Deployment Tool. Do not close this window.'
    $officeReleases = @(foreach ($release in Get-OfficeReleaseDefinitions) {
        $officeVersion = ''
        $sourceRoot = "30-Office\Source\$($release.Year)"
        foreach ($architecture in @('x86', 'x64')) {
            Write-Host "Downloading Office LTSC $($release.Year) $architecture..."
            $edition = if ($architecture -eq 'x86') { '32' } else { '64' }
            $source = Join-Path $staging "$sourceRoot\$architecture"
            [void](New-Item -ItemType Directory -Path $source -Force)
            $configuration = Join-Path $work "Download-$($release.Year)-$architecture.xml"
            New-OfficeDownloadConfiguration -Path $configuration -SourcePath $source -Edition $edition -Release $release -Version $officeVersion
            [void](Invoke-CheckedProcess -FilePath $setup -Arguments "/download `"$configuration`"" -WorkingDirectory $work -SuccessCodes @(0))
            if (-not $officeVersion) {
                $versions = @(Get-ChildItem -LiteralPath (Join-Path $source 'Office\Data') -Directory | Where-Object { $_.Name -match '^16\.0\.\d+\.\d+$' })
                if ($versions.Count -ne 1) { throw "Could not identify one complete Office LTSC $($release.Year) build from the fresh x86 download." }
                $officeVersion = $versions[0].Name
            }
            Assert-OfficeSource -SourcePath $source -Architecture $architecture -Version $officeVersion
        }
        [ordered]@{
            ProductId = $release.ProductId; Channel = $release.Channel; Language = $release.Language; Version = $officeVersion
            X86Path = "$sourceRoot\x86"; X64Path = "$sourceRoot\x64"
        }
    })
    $package = [ordered]@{
        SchemaVersion = 2
        State = 'Ready'
        CreatedUtc = [datetime]::UtcNow.ToString('o')
        WindowsArchitecture = 'x64'
        Catalog = [ordered]@{ Path = '10-Scan\wsusscn2.cab'; Source = $catalog.Source; DownloadedUtc = $catalog.DownloadedUtc; LastModifiedUtc = $catalog.LastModifiedUtc }
        Defender = [ordered]@{
            Path = $defenderPath; SignatureVersion = $signatureVersion; EngineVersion = [string]$definitionInfo.versions.engine
            Source = $defenderDownload.Source; DownloadedUtc = $defenderDownload.DownloadedUtc
            PlatformUpdates = 'Manual (KB4052623)'
        }
        Edge = [ordered]@{ Path = $edgePath; Version = $edge.Version; SHA256 = $edge.SHA256; Source = $edgeDownload.Source; DownloadedUtc = $edgeDownload.DownloadedUtc }
        Office = [ordered]@{ SetupPath = $setupPath; ToolSource = $odt.Source; Releases = $officeReleases }
    }
    $package | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $staging '00-Control\Package.json') -Encoding UTF8
    Stop-Transcript | Out-Null
    $transcribing = $false
    $preparationLog = Join-Path $OutputDirectory ($name + '-Preparation.log')
    Copy-Item -LiteralPath (Join-Path $work 'Preparation.log') -Destination $preparationLog
    Remove-Item -LiteralPath $work -Recurse -Force
    Write-Host 'Creating and checking the SHA256 payload manifest...'
    & (Join-Path $PSScriptRoot '00-Control\New-PayloadManifest.ps1') -PayloadRoot $staging -OutputDirectory (Join-Path $staging '00-Control')
    & (Join-Path $PSScriptRoot '00-Control\Test-PayloadManifest.ps1') -PayloadRoot $staging `
        -ManifestPath (Join-Path $staging '00-Control\PayloadManifest.csv') -ReportPath (Join-Path $OutputDirectory ($name + '-Verification.csv'))
    $ready = Join-Path $OutputDirectory $name
    Rename-Item -LiteralPath $staging -NewName $name
    Write-Host ''
    Write-Host "READY: $ready"
    Write-Host 'Transfer this entire folder through approved media controls, then run Start-OfflineUpdate.cmd on the standalone PC.'
    Write-Warning 'Office 2021 is out of support. This contains its newest available build, not an Office upgrade.'
}
catch {
    if (Test-Path -LiteralPath $staging) {
        Set-Content -LiteralPath (Join-Path $staging 'PREPARATION-FAILED.txt') -Value $_.Exception.Message -Encoding UTF8
    }
    throw "Package preparation failed. Do NOT deploy the .incomplete folder. $($_.Exception.Message)"
}
finally { if ($transcribing) { Stop-Transcript | Out-Null } }