#requires -version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-OptionalProperty {
    param($InputObject, [string]$Name, $Default = $null)
    if ($null -ne $InputObject) {
        $property = $InputObject.PSObject.Properties[$Name]
        if ($null -ne $property -and $null -ne $property.Value) { return $property.Value }
    }
    return $Default
}

function ConvertFrom-WuaSearchResult {
    param([Parameter(Mandatory = $true)]$Result)
    $resultCode = Get-OptionalProperty $Result 'ResultCode' 0
    if ([int]$resultCode -ne 2) {
        throw "Offline Windows scan did not complete successfully (WUA result $resultCode). Missing update count is unknown."
    }
    $rows = New-Object 'System.Collections.Generic.List[object]'
    for ($index = 0; $index -lt $Result.Updates.Count; $index++) {
        $update = $Result.Updates.Item($index)
        $categories = @($update.Categories | ForEach-Object { $_.Name })
        $rows.Add([pscustomobject][ordered]@{
            KBArticleIDs = @($update.KBArticleIDs) -join ';'
            Title = $update.Title
            MsrcSeverity = Get-OptionalProperty $update 'MsrcSeverity' ''
            Categories = $categories -join ';'
            UpdateID = $update.Identity.UpdateID
            RevisionNumber = $update.Identity.RevisionNumber
            RebootRequired = $update.RebootRequired
        })
    }
    $rows | Sort-Object KBArticleIDs, Title
}

function Invoke-NativeOfflineWuaScan {
    param([Parameter(Mandatory = $true)][string]$ScanCab)
    $serviceManager = $null
    $scanService = $null
    $session = $null
    $searcher = $null
    $result = $null
    try {
        $resolvedCab = (Resolve-Path -LiteralPath $ScanCab -ErrorAction Stop).Path
        $serviceManager = New-Object -ComObject Microsoft.Update.ServiceManager
        $session = New-Object -ComObject Microsoft.Update.Session
        $scanService = $serviceManager.AddScanPackageService('Standalone Updater Offline Scan', $resolvedCab, 1)
        $searcher = $session.CreateUpdateSearcher()
        $searcher.ServerSelection = 3
        $searcher.ServiceID = [string]$scanService.ServiceID
        $result = $searcher.Search("IsInstalled=0 and Type='Software'")
        ConvertFrom-WuaSearchResult -Result $result
    }
    finally {
        if ($null -ne $serviceManager -and $null -ne $scanService) {
            try { $serviceManager.RemoveService($scanService.ServiceID) }
            catch { Write-Warning "Could not remove temporary offline scan service: $($_.Exception.Message)" }
        }
        foreach ($comObject in @($result, $searcher, $scanService, $session, $serviceManager)) {
            if ($null -ne $comObject -and [Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
                [void][Runtime.InteropServices.Marshal]::ReleaseComObject($comObject)
            }
        }
    }
}

function Export-ReportCsv {
    param([object[]]$Rows = @(), [string[]]$Columns, [string]$Path)
    if (@($Rows).Count -gt 0) {
        $Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    }
    else {
        $emptyRow = [ordered]@{}
        foreach ($column in $Columns) { $emptyRow[$column] = '' }
        $header = @([pscustomobject]$emptyRow | ConvertTo-Csv -NoTypeInformation)[0]
        Set-Content -LiteralPath $Path -Value $header -Encoding UTF8
    }
}

function Get-RegistryValues {
    param([string]$Path, [Microsoft.Win32.RegistryView]$View = 'Registry64')
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $View)
    $key = $null
    try {
        $key = $baseKey.OpenSubKey($Path)
        if ($null -eq $key) { return $null }
        $values = [ordered]@{}
        foreach ($name in $key.GetValueNames()) {
            if ($name) { $values[$name] = $key.GetValue($name) }
        }
        return [pscustomobject]$values
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        $baseKey.Dispose()
    }
}

function Get-OfficeInventory {
    foreach ($view in @('Registry64', 'Registry32')) {
        $configuration = Get-RegistryValues 'SOFTWARE\Microsoft\Office\ClickToRun\Configuration' $view
        if ($null -ne $configuration) {
            return [pscustomobject]@{
                Detected = $true
                Version = Get-OptionalProperty $configuration 'VersionToReport' ''
                Platform = Get-OptionalProperty $configuration 'Platform' ''
                ProductReleaseIds = Get-OptionalProperty $configuration 'ProductReleaseIds' ''
                Language = Get-OptionalProperty $configuration 'ClientCulture' ''
                Channel = Get-OptionalProperty $configuration 'UpdateChannel' ''
                CDNBaseUrl = Get-OptionalProperty $configuration 'CDNBaseUrl' ''
            }
        }
    }
    [pscustomobject]@{ Detected = $false; Version = ''; Platform = ''; ProductReleaseIds = ''; Language = ''; Channel = ''; CDNBaseUrl = '' }
}

function Get-EdgeInventory {
    foreach ($directory in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if (-not $directory) { continue }
        $executable = Join-Path $directory 'Microsoft\Edge\Application\msedge.exe'
        if (Test-Path -LiteralPath $executable -PathType Leaf) {
            return [pscustomobject]@{ Detected = $true; Version = (Get-Item -LiteralPath $executable).VersionInfo.FileVersion; ExecutablePath = $executable }
        }
    }
    [pscustomobject]@{ Detected = $false; Version = ''; ExecutablePath = '' }
}

function Get-PendingReboot {
    $renamePending = Get-RegistryValues 'SYSTEM\CurrentControlSet\Control\Session Manager'
    [pscustomobject]@{
        Any = ((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
               [bool](Get-OptionalProperty $renamePending 'PendingFileRenameOperations' $false))
    }
}

function Get-SystemInventory {
    $current = Get-RegistryValues 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $defender = [pscustomobject]@{ Available = $false; Error = ''; PlatformVersion = ''; EngineVersion = ''; SignatureVersion = ''; SignatureUpdated = ''; SignatureAgeDays = $null; AntivirusEnabled = $null; RunningMode = '' }
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $defender.Available = $true
        $defender.PlatformVersion = Get-OptionalProperty $status 'AMProductVersion' ''
        $defender.EngineVersion = Get-OptionalProperty $status 'AMEngineVersion' ''
        $defender.SignatureVersion = Get-OptionalProperty $status 'AntivirusSignatureVersion' ''
        $defender.SignatureUpdated = Get-OptionalProperty $status 'AntivirusSignatureLastUpdated' ''
        if ($defender.SignatureUpdated) { $defender.SignatureAgeDays = [math]::Round(((Get-Date) - [datetime]$defender.SignatureUpdated).TotalDays, 1) }
        $defender.AntivirusEnabled = Get-OptionalProperty $status 'AntivirusEnabled'
        $defender.RunningMode = Get-OptionalProperty $status 'AMRunningMode' ''
    }
    catch { $defender.Error = $_.Exception.Message }
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        OS = [pscustomobject]@{
            ProductName = $operatingSystem.Caption
            Edition = Get-OptionalProperty $current 'EditionID' ''
            Release = Get-OptionalProperty $current 'DisplayVersion' ''
            Build = Get-OptionalProperty $current 'CurrentBuild' ''
            FullBuild = '{0}.{1}' -f (Get-OptionalProperty $current 'CurrentBuild' ''), (Get-OptionalProperty $current 'UBR' '')
            Architecture = $operatingSystem.OSArchitecture
            InstallationType = Get-OptionalProperty $current 'InstallationType' ''
        }
        PendingReboot = Get-PendingReboot
        Office = Get-OfficeInventory
        Edge = Get-EdgeInventory
        Defender = $defender
    }
}

function ConvertFrom-SoftwareInstallDate {
    param([string]$Value)
    $culture = [Globalization.CultureInfo]::InvariantCulture
    $date = [datetime]::MinValue
    if ([datetime]::TryParseExact($Value, 'yyyyMMdd', $culture, [Globalization.DateTimeStyles]::None, [ref]$date)) {
        return $date.ToString('yyyy-MM-dd', $culture)
    }
    return ''
}

function Get-DesktopSoftwareInventory {
    [CmdletBinding()]
    param()
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($view in @('Registry64', 'Registry32')) {
        foreach ($hive in @('LocalMachine', 'Users')) {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            try {
                $roots = @([pscustomobject]@{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine' })
                if ($hive -eq 'Users') {
                    $roots = @($baseKey.GetSubKeyNames() | Where-Object { $_ -match '^S-1-5-21-[\d-]+$|^S-1-12-1-[\d-]+$' } | ForEach-Object {
                        [pscustomobject]@{ Path = "$_\Software\Microsoft\Windows\CurrentVersion\Uninstall"; Scope = "User:$_" }
                    })
                }
                foreach ($root in $roots) {
                    $uninstall = $null
                    try {
                        $uninstall = $baseKey.OpenSubKey($root.Path)
                        if ($null -eq $uninstall) { continue }
                        foreach ($subKeyName in $uninstall.GetSubKeyNames()) {
                            $application = $null
                            try {
                                $application = $uninstall.OpenSubKey($subKeyName)
                                if ($null -eq $application) { continue }
                                $name = [string]$application.GetValue('DisplayName')
                                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                                $rows.Add([pscustomobject]@{
                                    Name = $name
                                    Version = [string]$application.GetValue('DisplayVersion')
                                    Publisher = [string]$application.GetValue('Publisher')
                                    Scope = $root.Scope
                                    RegistryView = $view
                                    InstallDate = ConvertFrom-SoftwareInstallDate $application.GetValue('InstallDate')
                                })
                            }
                            catch { Write-Warning "Could not read software registration $subKeyName : $($_.Exception.Message)" }
                            finally { if ($null -ne $application) { $application.Dispose() } }
                        }
                    }
                    catch { Write-Warning "Software inventory incomplete for $($root.Scope): $($_.Exception.Message)" }
                    finally { if ($null -ne $uninstall) { $uninstall.Dispose() } }
                }
            }
            finally { $baseKey.Dispose() }
        }
    }
    $rows | Sort-Object Name, Version, Publisher, Scope, RegistryView, InstallDate -Unique
}

function New-LocalReportDirectory {
    param([string]$BaseDirectory = (Join-Path $env:ProgramData 'StandaloneUpdater\Reports'))
    $fullPath = [IO.Path]::GetFullPath($BaseDirectory)
    $drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($fullPath))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'Reports must be written to a local fixed drive, not transfer media or a network share.' }
    $directory = Join-Path (Join-Path $fullPath $env:COMPUTERNAME) ('{0}_{1}' -f (Get-Date -Format 'yyyy-MM-dd_HHmmss_fff'), [guid]::NewGuid().ToString('N').Substring(0, 6))
    [void](New-Item -ItemType Directory -Path $directory -ErrorAction Stop)
    return $directory
}

function ConvertTo-ReportTable {
    param([string]$Caption, [object[]]$Rows, [System.Collections.IDictionary]$Columns)
    $captionText = [Net.WebUtility]::HtmlEncode($Caption)
    $tableId = 'table-' + ($Caption.ToLowerInvariant() -replace '[^a-z0-9]+', '-')
    $tableClass = if ($Columns.Count -le 2) { 'compact' } else { 'wide' }
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append("<div class=`"table-wrap`" tabindex=`"0`" role=`"region`" aria-labelledby=`"$tableId`"><table class=`"$tableClass`"><caption id=`"$tableId`">$captionText</caption><thead><tr>")
    foreach ($label in $Columns.Values) { [void]$builder.Append('<th scope="col">' + [Net.WebUtility]::HtmlEncode([string]$label) + '</th>') }
    [void]$builder.Append('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        [void]$builder.Append('<tr>')
        $columnIndex = 0
        foreach ($propertyName in $Columns.Keys) {
            $value = [Net.WebUtility]::HtmlEncode([string](Get-OptionalProperty $row $propertyName ''))
            if ($columnIndex -eq 0) { [void]$builder.Append('<th scope="row">' + $value + '</th>') }
            else { [void]$builder.Append('<td>' + $value + '</td>') }
            $columnIndex++
        }
        [void]$builder.Append('</tr>')
    }
    [void]$builder.Append('</tbody></table></div>')
    $builder.ToString()
}

function Write-OfflineReport {
    param([Parameter(Mandatory = $true)]$Report, [Parameter(Mandatory = $true)][string]$Directory)
    $missingColumns = @('KBArticleIDs', 'Title', 'MsrcSeverity', 'Categories', 'UpdateID', 'RevisionNumber', 'RebootRequired')
    Export-ReportCsv -Rows @($Report.MissingUpdates) -Columns $missingColumns -Path (Join-Path $Directory 'MissingWindowsUpdates.csv')
    Export-ReportCsv -Rows @($Report.Software) -Columns @('Name', 'Version', 'Publisher', 'Scope', 'RegistryView', 'InstallDate') -Path (Join-Path $Directory 'InstalledSoftware.csv')
    Export-ReportCsv -Rows @($Report.ProductResults) -Columns @('Component', 'Before', 'After', 'Target', 'Status', 'Message') -Path (Join-Path $Directory 'ProductUpdates.csv')
    $Report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $Directory 'SystemInventory.json') -Encoding UTF8
    $summary = 'Missing update count unknown: scan failed or was not completed.'
    if ($Report.Scan.Status -eq 'Succeeded') {
        $summary = '{0} missing catalog-covered update(s).' -f @($Report.MissingUpdates).Count
        if (@($Report.MissingUpdates).Count -eq 0) { $summary = 'No missing catalog-covered updates detected.' }
    }
    $computer = [Net.WebUtility]::HtmlEncode([string]$Report.ComputerName)
    $timestamp = [Net.WebUtility]::HtmlEncode([string]$Report.Timestamp)
    $summaryHtml = [Net.WebUtility]::HtmlEncode($summary)
    $scanMessage = [Net.WebUtility]::HtmlEncode([string]$Report.Scan.Message)
    $warningsHtml = (@($Report.Warnings | ForEach-Object { '<li>' + [Net.WebUtility]::HtmlEncode([string]$_) + '</li>' }) -join '')
    $systemRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($group in @('OS', 'PendingReboot', 'Office', 'Edge', 'Defender')) {
        $value = Get-OptionalProperty $Report.Inventory $group
        if ($null -eq $value) { continue }
        foreach ($property in $value.PSObject.Properties) {
            $systemRows.Add([pscustomobject]@{ Field = "$group.$($property.Name)"; Value = [string]$property.Value })
        }
    }
    $systemRows.Add([pscustomobject]@{ Field = 'Catalog.DownloadedUtc'; Value = $Report.Catalog.DownloadedUtc })
    $systemRows.Add([pscustomobject]@{ Field = 'Catalog.LastModifiedUtc'; Value = $Report.Catalog.LastModifiedUtc })
    $systemRows.Add([pscustomobject]@{ Field = 'Catalog.SHA256'; Value = $Report.Catalog.SHA256 })
    $missingTable = ConvertTo-ReportTable 'Missing Windows updates' @($Report.MissingUpdates) ([ordered]@{ KBArticleIDs = 'KB'; Title = 'Update'; MsrcSeverity = 'Severity'; Categories = 'Categories' })
    $softwareTable = ConvertTo-ReportTable 'Registered desktop software' @($Report.Software) ([ordered]@{ Name = 'Software'; Version = 'Version'; InstallDate = 'Install date'; Publisher = 'Publisher'; Scope = 'Scope'; RegistryView = 'Registry view' })
    $systemTable = ConvertTo-ReportTable 'System and product versions' $systemRows.ToArray() ([ordered]@{ Field = 'Field'; Value = 'Value' })
    $productTable = ConvertTo-ReportTable 'Product update results' @($Report.ProductResults) ([ordered]@{ Component = 'Product'; Before = 'Before'; After = 'After'; Target = 'Package target'; Status = 'Result'; Message = 'Details' })
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>$computer - Offline update report - $timestamp</title>
<style>
:root{font-family:Bahnschrift,Calibri,sans-serif;color:#202825;background:#f4f6f5;font-size:16px;letter-spacing:0}
*{box-sizing:border-box}body{margin:0}header,main,footer{max-width:1280px;margin:auto;padding:1.5rem}header{border-top:6px solid #28644a}
h1{font-size:1.75rem;margin:.25rem 0}h2{font-size:1.25rem;margin:2rem 0 .75rem}p,li{line-height:1.6;overflow-wrap:anywhere}
.summary{border-left:4px solid #28644a;padding:.75rem 1rem;background:#fff}.warnings{border-left:4px solid #986019;padding:.75rem 1rem;background:#fff}
.table-wrap{overflow:auto;max-width:100%;margin-bottom:1.5rem;background:#fff}.table-wrap:focus-visible{outline:3px solid #28644a;outline-offset:3px}
table{width:100%;min-width:48rem;border-collapse:separate;border-spacing:0;font-size:.9375rem}table.compact{min-width:32rem}caption{text-align:left;font-weight:bold;padding:.8rem}
th,td{text-align:left;vertical-align:top;padding:.65rem .8rem;border-bottom:1px solid #d6deda;overflow-wrap:anywhere;min-width:7rem;max-width:38rem}
thead th{background:#e5ebe8;position:sticky;top:0;z-index:1}tbody th{font-weight:500}tbody tr:nth-child(even){background:#f7f9f8}
footer{font-size:.875rem;color:#4f5c55}@media print{:root{background:#fff;font-size:11pt}header,main,footer{padding:.5rem}header{border:0}.table-wrap{overflow:visible}table,table.compact{table-layout:fixed;min-width:0}thead{display:table-header-group}thead th{position:static}tr{break-inside:avoid}th,td{min-width:0;max-width:none;padding:.35rem}}
</style></head><body><header><p>STANDALONE UPDATER</p><h1>$computer</h1><p>$timestamp</p></header>
<main><section><h2>Assessment</h2><p class="summary">$summaryHtml</p><p>$scanMessage</p><ul class="warnings">$warningsHtml</ul></section>
<section><h2>Windows updates</h2>$missingTable</section><section><h2>Product maintenance</h2>$productTable</section>
<section><h2>System inventory</h2>$systemTable</section><section><h2>Software inventory</h2>$softwareTable</section></main>
<footer><p>Catalog-based assessment only. Optional updates, drivers, feature upgrades and third-party patch compliance are not certified. Desktop inventory covers machine and accessible loaded-user registrations; Store apps, unloaded user profiles and portable programs are not enumerated.</p></footer></body></html>
"@
    Set-Content -LiteralPath (Join-Path $Directory 'OfflineUpdateReport.html') -Value $html -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $Directory 'ScanSummary.txt') -Value @($summary, $Report.Scan.Message, $Report.Warnings) -Encoding UTF8
}

function Invoke-OfflineAssessment {
    param([string]$CabPath, [string]$Directory, $Package = $null, [object[]]$ProductResults = @(), [string[]]$Issues = @(), [string]$SkipScanReason = '')
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    foreach ($issue in $Issues) { $warnings.Add($issue) }
    $inventory = $null
    $software = @()
    try { $inventory = Get-SystemInventory }
    catch { $warnings.Add("System inventory incomplete: $($_.Exception.Message)") }
    try {
        $inventoryWarnings = @()
        $software = @(Get-DesktopSoftwareInventory -WarningVariable inventoryWarnings)
        foreach ($warning in $inventoryWarnings) { $warnings.Add([string]$warning) }
    }
    catch { $warnings.Add("Software inventory incomplete: $($_.Exception.Message)") }
    $catalog = [pscustomobject]@{ Path = $CabPath; DownloadedUtc = ''; LastModifiedUtc = ''; SHA256 = '' }
    $packageCatalog = Get-OptionalProperty $Package 'Catalog'
    $catalog.DownloadedUtc = Get-OptionalProperty $packageCatalog 'DownloadedUtc' ''
    $catalog.LastModifiedUtc = Get-OptionalProperty $packageCatalog 'LastModifiedUtc' ''
    $downloaded = [datetime]::MinValue
    if ([datetime]::TryParse($catalog.DownloadedUtc, [ref]$downloaded)) {
        if (((Get-Date).ToUniversalTime() - $downloaded.ToUniversalTime()).TotalDays -gt 35) {
            $warnings.Add('The scan catalog was downloaded more than 35 days ago. Prepare a new package to assess newer updates.')
        }
    }
    else { $warnings.Add('Catalog acquisition date is unknown; confirm this catalog is current before using the results.') }
    $scan = [pscustomobject]@{ Status = 'Failed'; Message = ''; MissingCount = $null }
    $missing = @()
    try {
        if ($SkipScanReason) { throw $SkipScanReason }
        $catalog.SHA256 = (Get-FileHash -LiteralPath $CabPath -Algorithm SHA256 -ErrorAction Stop).Hash
        $missing = @(Invoke-NativeOfflineWuaScan -ScanCab $CabPath)
        $scan.Status = 'Succeeded'
        $scan.Message = 'Assessment uses only the packaged Microsoft offline catalog; Windows updates are installed manually.'
        $scan.MissingCount = $missing.Count
    }
    catch { $scan.Message = $_.Exception.Message; $warnings.Add('Windows scan failed. Missing patch count is UNKNOWN, not zero.') }
    if ($null -ne $inventory) {
        if ($inventory.PendingReboot.Any) { $warnings.Add('A restart is pending. Restart manually and run Verify Only again before closing maintenance.') }
        if ($inventory.Office.Detected -and $inventory.Office.ProductReleaseIds -match '2021') { $warnings.Add('Office LTSC 2021 support ended on October 13, 2026. This tool does not upgrade Office to a supported edition.') }
        if (-not $inventory.Defender.Available) { $warnings.Add("Defender status unavailable: $($inventory.Defender.Error)") }
    }
    $warnings.Add('Defender intelligence/engine updates are automatic in Update and Report; Defender platform updates (KB4052623) are manual.')
    $report = [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o'); ComputerName = $env:COMPUTERNAME
        Inventory = $inventory; Catalog = $catalog; Scan = $scan
        MissingUpdates = @($missing); Software = @($software); ProductResults = @($ProductResults)
        Warnings = $warnings.ToArray(); ReportPath = (Join-Path $Directory 'OfflineUpdateReport.html')
    }
    Write-OfflineReport -Report $report -Directory $Directory
    return $report
}

function Test-VersionAtLeast {
    param([string]$Installed, [string]$Target)
    $installedVersion = $null
    $targetVersion = $null
    if (-not [version]::TryParse($Installed, [ref]$installedVersion)) { throw "Cannot determine installed version: '$Installed'." }
    if (-not [version]::TryParse($Target, [ref]$targetVersion)) { throw "Cannot determine package version: '$Target'." }
    return ($installedVersion -ge $targetVersion)
}

function Resolve-PackagePath {
    param([string]$Root, [string]$RelativePath)
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or [IO.Path]::IsPathRooted($RelativePath) -or $RelativePath.Contains(':')) {
        throw "Package path must be relative: '$RelativePath'."
    }
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $fullPath = [IO.Path]::GetFullPath((Join-Path $rootPath $RelativePath))
    if (-not $fullPath.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase)) { throw "Package path escapes the deployment folder: '$RelativePath'." }
    return $fullPath
}

function Assert-MicrosoftSignature {
    param([string]$Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $subject = ''
    if ($null -ne $signature.SignerCertificate) { $subject = $signature.SignerCertificate.Subject }
    if ($signature.Status -ne 'Valid' -or $subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "Microsoft signature validation failed for '$Path' ($($signature.Status)). Check approved certificate trust; do not bypass validation."
    }
}

function Assert-DownloadedFile {
    param([string]$Path, [ValidateSet('Exe', 'Msi', 'Cab')][string]$Kind)
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.Length -lt 1024) { throw "Downloaded $Kind is empty or too small: $Path" }
    $stream = [IO.File]::OpenRead($file.FullName)
    try {
        $header = New-Object byte[] 8
        [void]$stream.Read($header, 0, $header.Length)
        $magic = [BitConverter]::ToString($header)
    }
    finally { $stream.Dispose() }
    $expected = switch ($Kind) { 'Exe' { '4D-5A-*' } 'Msi' { 'D0-CF-11-E0-A1-B1-1A-E1' } 'Cab' { '4D-53-43-46-*' } }
    if ($magic -notlike $expected) { throw "Download is not a valid $Kind file (possibly a proxy, sign-in or error page): $Path" }
    Assert-MicrosoftSignature -Path $Path
}

function Invoke-OfficialDownload {
    param([uri]$Uri, [string]$Destination, [ValidateSet('Exe', 'Msi', 'Cab')][string]$Kind, [uri]$Proxy, [switch]$ProxyUseDefaultCredentials)
    if ($Uri.Scheme -ne 'https' -or $Uri.DnsSafeHost -notmatch '(^|\.)(microsoft\.com|windowsupdate\.com|office\.com)$') {
        throw "Download must use an official Microsoft HTTPS source: $Uri"
    }
    [void](New-Item -ItemType Directory -Path (Split-Path $Destination -Parent) -Force)
    $request = @{ Uri = $Uri; OutFile = $Destination; UseBasicParsing = $true; PassThru = $true; TimeoutSec = 1800; ErrorAction = 'Stop' }
    if ($null -ne $Proxy) { $request.Proxy = $Proxy }
    if ($ProxyUseDefaultCredentials) { $request.ProxyUseDefaultCredentials = $true }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $response = Invoke-WebRequest @request
            Assert-DownloadedFile -Path $Destination -Kind $Kind
            return [pscustomobject]@{
                Source = $Uri.AbsoluteUri
                DownloadedUtc = [datetime]::UtcNow.ToString('o')
                LastModifiedUtc = [string]$response.Headers['Last-Modified']
            }
        }
        catch {
            if ($attempt -eq 3) { throw "Download failed after $attempt attempts: $Uri. $($_.Exception.Message)" }
            Write-Warning "Download attempt $attempt failed for $Uri. Retrying."
        }
    }
}

function Get-EdgeStableArtifact {
    param([object[]]$Products)
    $releases = @($Products | Where-Object { $_.Product -eq 'Stable' } | ForEach-Object { $_.Releases } |
        Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq 'x64' } |
        Sort-Object { [version]$_.ProductVersion } -Descending)
    foreach ($release in $releases) {
        $artifacts = @($release.Artifacts | Where-Object { $_.ArtifactName -eq 'msi' -and $_.HashAlgorithm -eq 'SHA256' })
        if ($artifacts.Count -gt 0) {
            return [pscustomobject]@{ Version = $release.ProductVersion; Uri = $artifacts[0].Location; SHA256 = $artifacts[0].Hash }
        }
    }
    throw 'The Microsoft Edge enterprise feed contains no Stable Windows x64 MSI with a SHA256 hash.'
}

function Get-OfficeReleaseDefinitions {
    [pscustomobject]@{ Year = '2021'; ProductId = 'ProPlus2021Volume'; Channel = 'PerpetualVL2021'; ChannelId = '5030841d-c919-4594-8d2d-84ae4f96e58e'; Language = 'en-us' }
    [pscustomobject]@{ Year = '2024'; ProductId = 'ProPlus2024Volume'; Channel = 'PerpetualVL2024'; ChannelId = '7983bac0-e531-40cf-be00-fd24fe66619c'; Language = 'en-us' }
}

function Get-OfficePackageReleases {
    param($OfficePackage)
    if ($null -eq $OfficePackage) { return }
    if ($null -eq $OfficePackage.PSObject.Properties['Releases']) { return $OfficePackage }
    $OfficePackage.Releases
}

function Get-OfficePackageRelease {
    param($OfficePackage, $Installed)
    if ($Installed.Language -ne 'en-us' -or $Installed.Platform -notin @('x86', 'x64')) { return }
    $definition = Get-OfficeReleaseDefinitions | Where-Object ProductId -EQ $Installed.ProductReleaseIds
    if ($null -eq $definition) { return }
    $channelMatches = @($Installed.Channel, $Installed.CDNBaseUrl) | Where-Object {
        $_ -eq $definition.Channel -or $_ -match "(?:^|/)$($definition.ChannelId)/?$"
    }
    if (-not $channelMatches) { return }
    $releases = @(Get-OfficePackageReleases $OfficePackage | Where-Object {
        $_.ProductId -eq $definition.ProductId -and $_.Channel -eq $definition.Channel -and $_.Language -eq $definition.Language
    })
    if ($releases.Count -eq 1) { return $releases[0] }
}

function New-OfficeDownloadConfiguration {
    param([string]$Path, [string]$SourcePath, [ValidateSet('32', '64')][string]$Edition, $Release, [string]$Version = '')
    $document = New-Object Xml.XmlDocument
    $configuration = $document.CreateElement('Configuration')
    [void]$document.AppendChild($configuration)
    $add = $document.CreateElement('Add')
    $add.SetAttribute('SourcePath', $SourcePath)
    $add.SetAttribute('OfficeClientEdition', $Edition)
    $add.SetAttribute('Channel', $Release.Channel)
    $add.SetAttribute('AllowCdnFallback', 'FALSE')
    if ($Version) { $add.SetAttribute('Version', $Version) }
    [void]$configuration.AppendChild($add)
    $product = $document.CreateElement('Product')
    $product.SetAttribute('ID', $Release.ProductId)
    [void]$add.AppendChild($product)
    $language = $document.CreateElement('Language')
    $language.SetAttribute('ID', $Release.Language)
    [void]$product.AppendChild($language)
    $document.Save($Path)
}

function Assert-OfficeSource {
    param([string]$SourcePath, [ValidateSet('x86', 'x64')][string]$Architecture, [string]$Version)
    $parsedVersion = $null
    if (-not [version]::TryParse($Version, [ref]$parsedVersion)) { throw "Invalid Office source version: $Version" }
    $bitness = if ($Architecture -eq 'x86') { '32' } else { '64' }
    $files = @("Office\Data\v${bitness}_$Version.cab",
        "Office\Data\$Version\stream.$Architecture.x-none.dat", "Office\Data\$Version\stream.$Architecture.en-us.dat",
        "Office\Data\$Version\stream.$Architecture.x-none.dat.cat", "Office\Data\$Version\stream.$Architecture.en-us.dat.cat")
    foreach ($relative in $files) {
        $file = Join-Path $SourcePath $relative
        if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or (Get-Item -LiteralPath $file).Length -eq 0) {
            throw "Office $Architecture source is incomplete; required file missing or empty: $relative"
        }
    }
}

function Invoke-CheckedProcess {
    param([string]$FilePath, [string]$Arguments, [string]$WorkingDirectory, [int[]]$SuccessCodes = @(0, 3010, 1641),
        [string]$Activity = "Running $([IO.Path]::GetFileName($FilePath))")
    $options = @{ FilePath = $FilePath; ArgumentList = $Arguments; Wait = $true; PassThru = $true; ErrorAction = 'Stop' }
    if ($WorkingDirectory) { $options.WorkingDirectory = $WorkingDirectory }
    $runner = [powershell]::Create()
    try {
        [void]$runner.AddCommand('Microsoft.PowerShell.Management\Start-Process').AddParameters($options)
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $operation = $runner.BeginInvoke()
        do {
            Write-Progress -Activity $Activity -Status ('Elapsed: {0:hh\:mm\:ss}' -f $timer.Elapsed)
        } until ($operation.AsyncWaitHandle.WaitOne(1000))
        $process = @($runner.EndInvoke($operation))
        if ($runner.HadErrors) { throw $runner.Streams.Error[0] }
        if ($process.Count -ne 1) { throw "Could not get the exit code for '$FilePath'. Review the local installer logs." }
        $exitCode = $process[0].ExitCode
        if ($exitCode -notin $SuccessCodes) { throw "'$FilePath' failed with exit code $exitCode. Review the local installer logs." }
        return [int]$exitCode
    }
    finally {
        $runner.Dispose()
        Write-Progress -Activity $Activity -Completed
    }
}

function Assert-DeploymentPackage {
    param([string]$Root, [string]$Directory)
    if ((Split-Path $Root -Leaf) -like '*.incomplete') { throw 'This package is incomplete. Prepare a new ready deployment folder.' }
    $metadataPath = Join-Path $Root '00-Control\Package.json'
    $manifestPath = Join-Path $Root '00-Control\PayloadManifest.csv'
    $package = Get-Content -LiteralPath $metadataPath -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($package.SchemaVersion -notin @(1, 2) -or $package.State -ne 'Ready' -or $package.WindowsArchitecture -ne 'x64') { throw 'Unrecognized or unfinished deployment metadata.' }
    $manifest = @(Import-Csv -LiteralPath $manifestPath -ErrorAction Stop)
    if ($manifest.Count -eq 0) { throw 'The payload manifest is empty.' }
    foreach ($entry in $manifest) { [void](Resolve-PackagePath $Root $entry.RelativePath) }
    $required = @('00-Control\Package.json', '00-Control\OfflineUpdate.Common.psm1', '00-Control\Test-PayloadManifest.ps1',
        'Run-OfflineMaintenance.ps1', 'Start-OfflineUpdate.cmd', '10-Scan\Scan-OfflinePC.ps1',
        $package.Catalog.Path, $package.Defender.Path, $package.Edge.Path, $package.Office.SetupPath)
    foreach ($relative in $required) {
        [void](Resolve-PackagePath $Root $relative)
        if ($relative -notin @($manifest.RelativePath)) { throw "Required file is not controlled by the manifest: $relative" }
    }
    foreach ($reparsePoint in @(Get-ChildItem -LiteralPath $Root -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })) {
        throw "Deployment folders must not contain links or reparse points: $($reparsePoint.FullName)"
    }
    & (Join-Path $Root '00-Control\Test-PayloadManifest.ps1') -PayloadRoot $Root -ManifestPath $manifestPath -ReportPath (Join-Path $Directory 'PayloadVerification.csv')
    $releases = @(Get-OfficePackageReleases $package.Office)
    if ($releases.Count -eq 0) { throw 'The package has no Office sources.' }
    $definitions = @(Get-OfficeReleaseDefinitions)
    $seen = @{}
    foreach ($release in $releases) {
        $definition = $definitions | Where-Object ProductId -EQ $release.ProductId
        if ($null -eq $definition -or $release.Channel -ne $definition.Channel -or
            $release.Language -ne $definition.Language -or $seen.ContainsKey($release.ProductId)) {
            throw "Unrecognized or duplicate Office release in the package: $($release.ProductId)"
        }
        $seen[$release.ProductId] = $true
        Assert-OfficeSource (Resolve-PackagePath $Root $release.X86Path) 'x86' $release.Version
        Assert-OfficeSource (Resolve-PackagePath $Root $release.X64Path) 'x64' $release.Version
    }
    return $package
}

function Get-ProductUpdatePlan {
    param($Inventory, $Package)
    foreach ($component in @('Defender', 'Edge', 'Office')) {
        $installed = $Inventory.$component
        $target = $Package.$component
        $before = [string](Get-OptionalProperty $installed 'Version' '')
        $detected = [bool](Get-OptionalProperty $installed 'Detected' $false)
        if ($component -eq 'Office' -and $detected) { $target = Get-OfficePackageRelease $target $installed }
        $targetVersion = [string](Get-OptionalProperty $target 'Version' '')
        $message = ''
        if ($component -eq 'Defender') {
            $before = $installed.SignatureVersion
            $targetVersion = $target.SignatureVersion
            $detected = $installed.Available
        }
        $status = 'Absent'
        if ($detected) {
            $status = 'Required'
            if ($component -eq 'Office' -and $null -eq $target) {
                $status = 'Unsupported'
                $message = 'No prepared Office source matches the installed LTSC edition, language, channel and architecture; no migration was attempted.'
            }
            else {
                try {
                    $current = Test-VersionAtLeast $before $targetVersion
                    if ($component -eq 'Defender') { $current = $current -and (Test-VersionAtLeast $installed.EngineVersion $target.EngineVersion) }
                    if ($current) { $status = 'Current'; $message = 'Installed version meets or exceeds this dated package; no installer was run.' }
                }
                catch { $status = 'Blocked'; $message = $_.Exception.Message }
            }
        }
        else { $message = 'Product/status not available; no new product was installed.' }
        [pscustomobject]@{ Component = $component; Before = $before; After = $before; Target = $targetVersion; Status = $status; Message = $message }
    }
}

function New-OfficeUpdateConfiguration {
    param([string]$Path, [string]$SourcePath, [string]$Version, [string]$Channel)
    $document = New-Object Xml.XmlDocument
    $configuration = $document.CreateElement('Configuration')
    [void]$document.AppendChild($configuration)
    $updates = $document.CreateElement('Updates')
    $updates.SetAttribute('Enabled', 'TRUE')
    $updates.SetAttribute('UpdatePath', $SourcePath)
    $updates.SetAttribute('TargetVersion', $Version)
    $updates.SetAttribute('Channel', $Channel)
    [void]$configuration.AppendChild($updates)
    $document.Save($Path)
}

function Save-OfficeUpdateSettings {
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    try {
        foreach ($path in @('SOFTWARE\Microsoft\Office\ClickToRun\Configuration', 'SOFTWARE\Microsoft\Office\ClickToRun\Updates')) {
            $key = $baseKey.OpenSubKey($path)
            try {
                foreach ($name in @('UpdateUrl', 'UpdatePath', 'UpdateToVersion', 'UpdatesEnabled', 'UpdateChannel', 'UpdateChannelChanged', 'CDNBaseUrl')) {
                    $exists = ($null -ne $key -and $name -in $key.GetValueNames())
                    [pscustomobject]@{
                        Path = $path; Name = $name; Existed = $exists
                        Value = if ($exists) { $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null }
                        Kind = if ($exists) { $key.GetValueKind($name).ToString() } else { 'String' }
                    }
                }
            }
            finally { if ($null -ne $key) { $key.Dispose() } }
        }
    }
    finally { $baseKey.Dispose() }
}

function Restore-OfficeUpdateSettings {
    param([object[]]$Settings)
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    try {
        foreach ($setting in $Settings) {
            $key = $baseKey.OpenSubKey($setting.Path, $true)
            try {
                if ($null -eq $key) {
                    if ($setting.Existed) { throw "Cannot restore Office setting $($setting.Name): registry key unavailable." }
                    continue
                }
                if ($setting.Existed) { $key.SetValue($setting.Name, $setting.Value, [Microsoft.Win32.RegistryValueKind]$setting.Kind) }
                else { $key.DeleteValue($setting.Name, $false) }
            }
            finally { if ($null -ne $key) { $key.Dispose() } }
        }
    }
    finally { $baseKey.Dispose() }
}

function Wait-UpdatePoll { Start-Sleep -Seconds 2 }

function Wait-ProductTarget {
    param([string]$Component, $Package, [int]$TimeoutSeconds = 120)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $activity = "Waiting for $Component update"
    try {
        do {
            Write-Progress -Activity $activity -Status ('Elapsed: {0:hh\:mm\:ss}' -f $timer.Elapsed)
            $inventory = Get-SystemInventory
            $plan = @(Get-ProductUpdatePlan $inventory $Package | Where-Object { $_.Component -eq $Component })[0]
            $finished = ($plan.Status -eq 'Current')
            if ($finished -and $Component -eq 'Office') {
                $finished = ((Get-ScheduledTask -TaskPath '\Microsoft\Office\' -TaskName 'Office Automatic Updates 2.0' -ErrorAction Stop).State -ne 'Running')
            }
            if ($finished) { return $inventory }
            if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw "$Component did not reach the packaged target version within $TimeoutSeconds seconds. Verification is required; success was NOT assumed." }
            Wait-UpdatePoll
        } while ($true)
    }
    finally { Write-Progress -Activity $activity -Completed }
}

function Invoke-OfficeLocalUpdate {
    param([string]$Root, [string]$Directory, $Package, $Inventory, [int]$TimeoutSeconds = 1800)
    $release = Get-OfficePackageRelease $Package.Office $Inventory.Office
    if ($null -eq $release) { throw 'No prepared Office source matches the installed release.' }
    foreach ($view in @('Registry64', 'Registry32')) {
        $policy = Get-RegistryValues 'SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' $view
        if ($null -ne $policy -and @($policy.PSObject.Properties).Count -gt 0) { throw 'Office update policy is managed by IT. No policy was overridden; arrange the local update with IT.' }
    }
    $configurationValues = Get-RegistryValues 'SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    if ((Get-OptionalProperty $configurationValues 'OfficeMgmtCOM' 'False') -match '^(True|1)$') { throw 'Office updates are managed by Configuration Manager; no management settings were changed.' }
    $task = Get-ScheduledTask -TaskPath '\Microsoft\Office\' -TaskName 'Office Automatic Updates 2.0' -ErrorAction Stop
    if ($task.State -in @('Disabled', 'Running')) { throw 'The Office update task is disabled or already running. Resolve this and retry.' }
    if ((Get-Service -Name ClickToRunSvc -ErrorAction Stop).Status -ne 'Running') { throw 'Office Click-to-Run service is not running. Ask IT to restore normal Office servicing, then retry.' }
    $relative = if ($Inventory.Office.Platform -eq 'x86') { $release.X86Path } else { $release.X64Path }
    $source = Resolve-PackagePath $Root $relative
    Assert-OfficeSource $source $Inventory.Office.Platform $release.Version
    $configuration = Join-Path $Directory 'Office-LocalUpdate.xml'
    New-OfficeUpdateConfiguration $configuration $source $release.Version $release.Channel
    $settings = @(Save-OfficeUpdateSettings)
    $settings | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Directory 'OfficeSettingsBefore.json') -Encoding UTF8
    try {
        [void](Invoke-CheckedProcess (Resolve-PackagePath $Root $Package.Office.SetupPath) "/configure `"$configuration`"" $Directory @(0) -Activity 'Configuring Office offline update')
        Start-ScheduledTask -TaskPath '\Microsoft\Office\' -TaskName 'Office Automatic Updates 2.0' -ErrorAction Stop
        [void](Wait-ProductTarget -Component Office -Package $Package -TimeoutSeconds $TimeoutSeconds)
    }
    finally { Restore-OfficeUpdateSettings -Settings $settings }
    return 0
}

function Invoke-LocalProductUpdates {
    param([string]$Root, [string]$Directory, $Package, $Inventory)
    $results = @(Get-ProductUpdatePlan $Inventory $Package)
    $stop = $false
    foreach ($result in $results) {
        if ($stop -and $result.Status -eq 'Required') { $result.Status = 'NotRun'; $result.Message = 'Stopped after a failure or reboot requirement. Resolve it and run Update and Report again.'; continue }
        if ($result.Status -eq 'Blocked') { $stop = $true; continue }
        if ($result.Status -ne 'Required') { continue }
        try {
            $processNames = switch ($result.Component) {
                'Edge' { 'msedge' }
                'Office' { 'WINWORD', 'EXCEL', 'OUTLOOK', 'POWERPNT', 'MSACCESS', 'MSPUB', 'ONENOTE', 'VISIO', 'WINPROJ' }
            }
            if ($processNames) {
                $applications = @(Get-Process -Name $processNames -ErrorAction SilentlyContinue)
                if ($applications.Count -gt 0) {
                    $names = ($applications.ProcessName | Sort-Object -Unique) -join ', '
                    $result.Status = 'Blocked'
                    $result.Message = "Close the listed $($result.Component) processes ($names), then run Update and Report again. Nothing was force-closed."
                    Write-Warning "$($result.Component): $($result.Message)"
                    continue
                }
            }
            Write-Host "Updating $($result.Component)..."
            $exitCode = switch ($result.Component) {
                'Defender' { Invoke-CheckedProcess (Resolve-PackagePath $Root $Package.Defender.Path) '/q' $Directory -Activity 'Installing Defender update' }
                'Edge' {
                    $installer = Resolve-PackagePath $Root $Package.Edge.Path
                    $log = Join-Path $Directory 'EdgeInstaller.log'
                    Invoke-CheckedProcess "$env:SystemRoot\System32\msiexec.exe" "/i `"$installer`" /qn /norestart REBOOT=ReallySuppress /L*v `"$log`"" $Directory -Activity 'Installing Edge update'
                }
                'Office' { Invoke-OfficeLocalUpdate $Root $Directory $Package $Inventory }
            }
            if ($exitCode -in @(3010, 1641)) {
                $result.Status = 'RebootRequired'
                $result.Message = "Installer exit $exitCode. Restart manually, then run Update and Report again."
                $stop = $true
            }
            else {
                $after = Wait-ProductTarget -Component $result.Component -Package $Package
                $result.After = if ($result.Component -eq 'Defender') { $after.Defender.SignatureVersion } else { $after.($result.Component).Version }
                $result.Status = 'Updated'
                $result.Message = 'Observed installed version meets or exceeds the packaged target.'
                if ($after.PendingReboot.Any) { $result.Status = 'RebootRequired'; $result.Message += ' Restart manually before continuing.'; $stop = $true }
            }
        }
        catch { $result.Status = 'Failed'; $result.Message = $_.Exception.Message; $stop = $true }
    }
    return $results
}

function Invoke-OfflineMaintenance {
    param([ValidateSet('UpdateAndReport', 'VerifyOnly')][string]$Mode, [string]$Root, [string]$Directory)
    $package = $null
    $results = @()
    $issues = @()
    $skipScan = ''
    try { $package = Assert-DeploymentPackage -Root $Root -Directory $Directory }
    catch { $skipScan = "Package verification failed: $($_.Exception.Message)"; $issues += $skipScan }
    if ($Mode -eq 'UpdateAndReport' -and $null -ne $package) {
        try {
            $inventory = Get-SystemInventory
            if (-not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or
                [int]$inventory.OS.Build -lt 22000 -or $inventory.OS.InstallationType -ne 'Client') { throw 'Installation requires Windows 11 x64 and a 64-bit PowerShell process.' }
            if ($inventory.PendingReboot.Any) { throw 'A reboot is pending. Restart manually before installing products; this run will report only.' }
            $drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($env:SystemRoot))
            if ($drive.AvailableFreeSpace -lt 8GB) { throw 'At least 8 GB free is required on the system drive before installing products.' }
            $results = @(Invoke-LocalProductUpdates $Root $Directory $package $inventory)
            foreach ($result in $results | Where-Object { $_.Status -in @('Failed', 'Blocked', 'Unsupported', 'RebootRequired', 'NotRun') }) { $issues += "$($result.Component): $($result.Status). $($result.Message)" }
        }
        catch {
            $issues += "Installations blocked: $($_.Exception.Message)"
            $results = @([pscustomobject]@{ Component = 'Maintenance'; Before = ''; After = ''; Target = ''; Status = 'Blocked'; Message = $_.Exception.Message })
        }
    }
    $cabPath = Join-Path $Root '10-Scan\wsusscn2.cab'
    if ($null -ne $package) { $cabPath = Resolve-PackagePath $Root $package.Catalog.Path }
    Invoke-OfflineAssessment -CabPath $cabPath -Directory $Directory -Package $package -ProductResults $results -Issues $issues -SkipScanReason $skipScan
}