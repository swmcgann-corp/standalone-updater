param([switch]$Run, [string]$PesterManifest = '')

if ($Run) {
    if ($PesterManifest) { Import-Module $PesterManifest -Force -ErrorAction Stop }
    else { Import-Module Pester -MinimumVersion 5.7.1 -ErrorAction Stop }
    $result = Invoke-Pester -Path $PSCommandPath -Output Detailed -PassThru
    if ($result.Result -ne 'Passed') { throw 'Workflow tests failed.' }
    return
}

BeforeAll {
    $script:Toolkit = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $script:Toolkit '00-Control\OfflineUpdate.Common.psm1') -Force -DisableNameChecking
    function New-TestState {
        [pscustomobject]@{
            Package = [pscustomobject]@{
                Defender = [pscustomobject]@{ SignatureVersion = '1.2.0.0'; EngineVersion = '1.1.0.0'; Path = 'Defender\mpam-fe.exe' }
                Edge = [pscustomobject]@{ Version = '130.0.1.0'; Path = 'Edge\edge.msi' }
                Office = [pscustomobject]@{
                    Version = '16.0.2.0'; ProductId = 'ProPlus2021Volume'; Channel = 'PerpetualVL2021'; Language = 'en-us'
                    X86Path = 'Office\x86'; X64Path = 'Office\x64'; SetupPath = 'Office\setup.exe'
                }
            }
            Inventory = [pscustomobject]@{
                Defender = [pscustomobject]@{ Available = $true; SignatureVersion = '1.1.0.0'; EngineVersion = '1.1.0.0' }
                Edge = [pscustomobject]@{ Detected = $true; Version = '129.0.0.0' }
                Office = [pscustomobject]@{ Detected = $true; Version = '16.0.1.0'; ProductReleaseIds = 'ProPlus2021Volume'; Language = 'en-us'; Platform = 'x86'; Channel = 'PerpetualVL2021'; CDNBaseUrl = '' }
                PendingReboot = [pscustomobject]@{ Any = $false }
            }
        }
    }
    function New-TestMixedOfficePackage {
        [pscustomobject]@{
            SetupPath = 'Office\setup.exe'
            Releases = @(
                [pscustomobject]@{
                    ProductId = 'ProPlus2021Volume'; Channel = 'PerpetualVL2021'; Language = 'en-us'; Version = '16.0.14334.21048'
                    X86Path = 'Office\2021\x86'; X64Path = 'Office\2021\x64'
                }
                [pscustomobject]@{
                    ProductId = 'ProPlus2024Volume'; Channel = 'PerpetualVL2024'; Language = 'en-us'; Version = '16.0.17932.21140'
                    X86Path = 'Office\2024\x86'; X64Path = 'Office\2024\x64'
                }
            )
        }
    }
}

Describe 'Offline scan result handling' {
    It 'rejects unsuccessful and partially successful results' -TestCases @(@{ Code = 0 }, @{ Code = 1 }, @{ Code = 3 }, @{ Code = 4 }, @{ Code = 5 }) {
        param($Code)
        { ConvertFrom-WuaSearchResult ([pscustomobject]@{ ResultCode = $Code; Updates = @() }) } | Should -Throw '*unknown*'
    }

    It 'accepts a complete successful scan with no updates' {
        @(ConvertFrom-WuaSearchResult ([pscustomobject]@{ ResultCode = 2; Updates = @() })).Count | Should -Be 0
    }

    It 'preserves KBs, titles and severity for one or multiple missing updates' -TestCases @(@{ Count = 1 }, @{ Count = 3 }) {
        param($Count)
        $rows = @(foreach ($index in 1..$Count) {
            [pscustomobject]@{
                KBArticleIDs = @("12345$index"); Title = "Security update $index"; MsrcSeverity = 'Critical'
                Categories = @([pscustomobject]@{ Name = 'Security Updates' })
                Identity = [pscustomobject]@{ UpdateID = "ID$index"; RevisionNumber = 1 }; RebootRequired = $false
            }
        })
        $collection = [pscustomobject]@{ Count = $rows.Count; Rows = $rows }
        $collection | Add-Member -MemberType ScriptMethod -Name Item -Value { param($Index) $this.Rows[$Index] }
        $result = @(ConvertFrom-WuaSearchResult ([pscustomobject]@{ ResultCode = 2; Updates = $collection }))
        $result.Count | Should -Be $Count
        $result[0].KBArticleIDs | Should -Be '123451'
        $result[0].MsrcSeverity | Should -Be 'Critical'
    }

    It 'removes its temporary catalog service when the WUA search fails' {
        $manager = [pscustomobject]@{ Removed = ''; Service = [pscustomobject]@{ ServiceID = 'TEST-OFFLINE-ID' } }
        $manager | Add-Member -MemberType ScriptMethod -Name AddScanPackageService -Value { param($Name, $Path, $Flags) $this.Service }
        $manager | Add-Member -MemberType ScriptMethod -Name RemoveService -Value { param($ServiceId) $this.Removed = $ServiceId }
        $searcher = [pscustomobject]@{ ServerSelection = 0; ServiceID = '' }
        $searcher | Add-Member -MemberType ScriptMethod -Name Search -Value { param($Criteria) throw 'Simulated WUA error' }
        $session = [pscustomobject]@{ Searcher = $searcher }
        $session | Add-Member -MemberType ScriptMethod -Name CreateUpdateSearcher -Value { $this.Searcher }
        $cab = Join-Path $TestDrive 'fake.cab'
        Set-Content -LiteralPath $cab -Value 'not a real scan package'
        InModuleScope OfflineUpdate.Common -Parameters @{ FakeManager = $manager; FakeSession = $session; Cab = $cab } {
            param($FakeManager, $FakeSession, $Cab)
            Mock New-Object -ParameterFilter { $ComObject -eq 'Microsoft.Update.ServiceManager' } { $FakeManager }
            Mock New-Object -ParameterFilter { $ComObject -eq 'Microsoft.Update.Session' } { $FakeSession }
            { Invoke-NativeOfflineWuaScan $Cab } | Should -Throw '*Simulated WUA error*'
            $FakeManager.Removed | Should -Be 'TEST-OFFLINE-ID'
            $FakeSession.Searcher.ServerSelection | Should -Be 3
            $FakeSession.Searcher.ServiceID | Should -Be 'TEST-OFFLINE-ID'
        }
    }
}

Describe 'Offline report safety' {
    It 'retains CSV headers when a result list is empty' {
        $path = Join-Path $TestDrive 'empty.csv'
        Export-ReportCsv -Columns @('Name', 'Version') -Path $path
        (Get-Content -LiteralPath $path -Raw).Trim() | Should -Be '"Name","Version"'
    }

    It 'escapes table values and provides native accessible headers' {
        $html = ConvertTo-ReportTable 'Software' @([pscustomobject]@{ Name = '<script>alert(1)</script>'; Version = '1&2' }) ([ordered]@{ Name = 'Name'; Version = 'Version' })
        $html | Should -Not -Match '<script>'
        $html | Should -Match '&lt;script&gt;'
        $html | Should -Match '1&amp;2'
        $html | Should -Match 'scope="col"'
        $html | Should -Match 'scope="row"'
        $html | Should -Match 'tabindex="0"'
    }

    It 'shows only valid registered install dates in the software inventory' {
        InModuleScope OfflineUpdate.Common {
            ConvertFrom-SoftwareInstallDate '20261118' | Should -Be '2026-11-18'
            ConvertFrom-SoftwareInstallDate '20260230' | Should -Be ''
            ConvertFrom-SoftwareInstallDate $null | Should -Be ''
        }
        $report = [pscustomobject]@{
            ComputerName = 'TEST-PC'; Timestamp = '2026-11-19'; Inventory = $null
            Catalog = [pscustomobject]@{ DownloadedUtc = ''; LastModifiedUtc = ''; SHA256 = '' }
            Scan = [pscustomobject]@{ Status = 'Succeeded'; Message = ''; MissingCount = 0 }
            MissingUpdates = @(); ProductResults = @(); Warnings = @()
            Software = @(
                [pscustomobject]@{ Name = 'Registered'; Version = '1'; Publisher = ''; Scope = 'Machine'; RegistryView = 'Registry64'; InstallDate = '2026-11-18' }
                [pscustomobject]@{ Name = 'Undated'; Version = '2'; Publisher = ''; Scope = 'Machine'; RegistryView = 'Registry64'; InstallDate = '' }
            )
        }
        Write-OfflineReport -Report $report -Directory $TestDrive
        $software = Import-Csv (Join-Path $TestDrive 'InstalledSoftware.csv')
        $software[0].InstallDate | Should -Be '2026-11-18'
        $software[1].InstallDate | Should -Be ''
        $html = Get-Content (Join-Path $TestDrive 'OfflineUpdateReport.html') -Raw
        $html | Should -Match '<th scope="col">Install date</th>'
        $html | Should -Match '<td>2026-11-18</td>'
    }

    It 'never presents a failed scan as zero missing updates' {
        $report = [pscustomobject]@{
            ComputerName = 'TEST-PC'; Timestamp = '2026-11-17'; Inventory = $null
            Catalog = [pscustomobject]@{ DownloadedUtc = ''; LastModifiedUtc = ''; SHA256 = '' }
            Scan = [pscustomobject]@{ Status = 'Failed'; Message = 'Test scan failure'; MissingCount = $null }
            MissingUpdates = @(); Software = @(); ProductResults = @(); Warnings = @('Test warning')
        }
        Write-OfflineReport -Report $report -Directory $TestDrive
        $html = Get-Content (Join-Path $TestDrive 'OfflineUpdateReport.html') -Raw
        $html | Should -Match 'Missing update count unknown'
        $html | Should -Not -Match 'No missing catalog-covered updates detected'
        $html | Should -Not -Match '<script|<link|<img|https://'
    }

    It 'makes separate report directories on consecutive runs' {
        $first = New-LocalReportDirectory -BaseDirectory $TestDrive
        $second = New-LocalReportDirectory -BaseDirectory $TestDrive
        $first | Should -Not -Be $second
        Test-Path -LiteralPath $first | Should -BeTrue
        Test-Path -LiteralPath $second | Should -BeTrue
    }

    It 'carries incomplete-software-inventory warnings into the report' {
        InModuleScope OfflineUpdate.Common {
            Mock Get-SystemInventory { $null }
            Mock Get-DesktopSoftwareInventory { Write-Warning 'Software inventory incomplete: locked profile' }
            Mock Get-FileHash { [pscustomobject]@{ Hash = 'TEST' } }
            Mock Invoke-NativeOfflineWuaScan { @() }
            Mock Write-OfflineReport {}
            $report = Invoke-OfflineAssessment -CabPath 'fake.cab' -Directory $TestDrive
            ($report.Warnings -join ' ') | Should -Match 'locked profile'
            $report.Scan.Status | Should -Be 'Succeeded'
        }
    }
}

Describe 'Package preparation contracts' {
    It 'compares product versions numerically and refuses unknown versions' {
        Test-VersionAtLeast '130.0.10.1' '99.0.999.9' | Should -BeTrue
        Test-VersionAtLeast '16.0.1.0' '16.0.2.0' | Should -BeFalse
        { Test-VersionAtLeast '' '1.2.3.4' } | Should -Throw
    }

    It 'rejects absolute and escaping payload paths' {
        { Resolve-PackagePath $TestDrive '..\outside.exe' } | Should -Throw '*escapes*'
        { Resolve-PackagePath $TestDrive 'C:\outside.exe' } | Should -Throw '*relative*'
        Resolve-PackagePath $TestDrive 'Office files\setup.exe' | Should -Be (Join-Path $TestDrive 'Office files\setup.exe')
    }

    It 'creates correctly escaped Office LTSC <Year> download XML and pins an explicit build' -TestCases @(
        @{ Year = '2021'; Bitness = '32'; Version = '16.0.14334.21048' }
        @{ Year = '2024'; Bitness = '64'; Version = '16.0.17932.21140' }
    ) {
        param($Year, $Bitness, $Version)
        $path = Join-Path $TestDrive 'office.xml'
        $release = Get-OfficeReleaseDefinitions | Where-Object Year -EQ $Year
        New-OfficeDownloadConfiguration $path 'C:\Office & files' $Bitness $release $Version
        [xml]$xml = Get-Content -LiteralPath $path -Raw
        $xml.Configuration.Add.SourcePath | Should -Be 'C:\Office & files'
        $xml.Configuration.Add.OfficeClientEdition | Should -Be $Bitness
        $xml.Configuration.Add.Version | Should -Be $Version
        $xml.Configuration.Add.Channel | Should -Be "PerpetualVL$Year"
        $xml.Configuration.Add.Product.ID | Should -Be "ProPlus${Year}Volume"
        $xml.Configuration.Add.Product.Language.ID | Should -Be 'en-us'
        $xml.Configuration.Add.AllowCdnFallback | Should -Be 'FALSE'
    }

    It 'rejects an incomplete Office source' {
        { Assert-OfficeSource $TestDrive 'x64' '16.0.1.2' } | Should -Throw '*incomplete*'
    }

    It 'verifies both releases and rejects a missing Office 2024 source file even with a matching manifest' {
        $root = Join-Path $TestDrive 'combined-package'
        $control = Join-Path $root '00-Control'
        $office = New-TestMixedOfficePackage
        $office.SetupPath = 'Office\setup.test'
        $metadata = @{
            SchemaVersion = 2; State = 'Ready'; WindowsArchitecture = 'x64'; Office = $office
            Catalog = @{ Path = '10-Scan\wsusscn2.cab' }; Defender = @{ Path = 'Defender\payload.test' }; Edge = @{ Path = 'Edge\payload.test' }
        }
        $files = @('Run-OfflineMaintenance.ps1', 'Start-OfflineUpdate.cmd', '10-Scan\Scan-OfflinePC.ps1', '00-Control\OfflineUpdate.Common.psm1',
            $metadata.Catalog.Path, $metadata.Defender.Path, $metadata.Edge.Path, $office.SetupPath)
        foreach ($release in $office.Releases) {
            foreach ($architecture in @('x86', 'x64')) {
                $bitness = if ($architecture -eq 'x86') { '32' } else { '64' }
                $data = $release."${architecture}Path" + '\Office\Data'
                $files += "$data\v${bitness}_$($release.Version).cab"
                foreach ($language in @('x-none', 'en-us')) {
                    $stream = "$data\$($release.Version)\stream.$architecture.$language.dat"
                    $files += @($stream, "$stream.cat")
                }
            }
        }
        foreach ($relative in $files) {
            $path = Join-Path $root $relative
            [void](New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force)
            Set-Content -LiteralPath $path -Value 'test payload'
        }
        Copy-Item (Join-Path $script:Toolkit '00-Control\Test-PayloadManifest.ps1') -Destination $control
        $metadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $control 'Package.json')
        $newManifest = Join-Path $script:Toolkit '00-Control\New-PayloadManifest.ps1'
        & $newManifest -PayloadRoot $root -OutputDirectory $control
        (Assert-DeploymentPackage $root $TestDrive).Office.Releases.Count | Should -Be 2
        Remove-Item -LiteralPath (Join-Path $root 'Office\2024\x64\Office\Data\v64_16.0.17932.21140.cab')
        & $newManifest -PayloadRoot $root -OutputDirectory $control
        { Assert-DeploymentPackage $root $TestDrive } | Should -Throw '*v64_16.0.17932.21140.cab*'
    }

    It 'validates a pinned <Architecture> Office source without a rolling version cabinet' -TestCases @(
        @{ Architecture = 'x86'; Bitness = '32' }, @{ Architecture = 'x64'; Bitness = '64' }
    ) {
        param($Architecture, $Bitness)
        $source = Join-Path $TestDrive $Architecture
        $version = '16.0.1.2'
        [void](New-Item -ItemType Directory -Path (Join-Path $source "Office\Data\$version") -Force)
        $files = @("Office\Data\v${Bitness}_$version.cab",
            "Office\Data\$version\stream.$Architecture.x-none.dat", "Office\Data\$version\stream.$Architecture.en-us.dat",
            "Office\Data\$version\stream.$Architecture.x-none.dat.cat", "Office\Data\$version\stream.$Architecture.en-us.dat.cat")
        foreach ($relative in $files) { Set-Content -LiteralPath (Join-Path $source $relative) -Value 'test payload' }
        { Assert-OfficeSource $source $Architecture $version } | Should -Not -Throw
        foreach ($relative in $files) {
            $path = Join-Path $source $relative
            Remove-Item -LiteralPath $path
            { Assert-OfficeSource $source $Architecture $version } | Should -Throw '*required file missing or empty*'
            [void](New-Item -ItemType File -Path $path)
            { Assert-OfficeSource $source $Architecture $version } | Should -Throw '*required file missing or empty*'
            Set-Content -LiteralPath $path -Value 'test payload'
        }
    }

    It 'rejects non-Microsoft and insecure download URLs without requesting them' {
        { Invoke-OfficialDownload 'https://example.com/update.exe' (Join-Path $TestDrive 'bad.exe') 'Exe' } | Should -Throw '*official*'
        { Invoke-OfficialDownload 'http://go.microsoft.com/update.exe' (Join-Path $TestDrive 'bad.exe') 'Exe' } | Should -Throw '*official*'
    }

    It 'does not create or download a package in WhatIf mode' {
        $destination = Join-Path $TestDrive 'not-created'
        & (Join-Path $script:Toolkit 'Prepare-OfflinePackage.ps1') -OutputDirectory $destination -WhatIf
        Test-Path -LiteralPath $destination | Should -BeFalse
    }

    It 'selects only the newest Stable Windows x64 MSI' {
        $releases = @(
            [pscustomobject]@{ Platform = 'Windows'; Architecture = 'x64'; ProductVersion = '130.0.1.0'; Artifacts = @([pscustomobject]@{ ArtifactName = 'msi'; Location = 'old'; HashAlgorithm = 'SHA256'; Hash = '1' }) }
            [pscustomobject]@{ Platform = 'Windows'; Architecture = 'x64'; ProductVersion = '131.0.1.0'; Artifacts = @([pscustomobject]@{ ArtifactName = 'msi'; Location = 'new'; HashAlgorithm = 'SHA256'; Hash = '2' }) }
            [pscustomobject]@{ Platform = 'Windows'; Architecture = 'arm64'; ProductVersion = '132.0.1.0'; Artifacts = @([pscustomobject]@{ ArtifactName = 'msi'; Location = 'wrong'; HashAlgorithm = 'SHA256'; Hash = '3' }) }
        )
        $result = Get-EdgeStableArtifact @([pscustomobject]@{ Product = 'Stable'; Releases = $releases }, [pscustomobject]@{ Product = 'Dev'; Releases = $releases })
        $result.Uri | Should -Be 'new'
        $result.Version | Should -Be '131.0.1.0'
    }

    It 'rejects a downloaded HTML/error page before checking its signature' {
        $path = Join-Path $TestDrive 'error.exe'
        Set-Content -LiteralPath $path -Value ('<html>proxy authentication required</html>' * 100)
        InModuleScope OfflineUpdate.Common -Parameters @{ File = $path } {
            param($File)
            Mock Assert-MicrosoftSignature { throw 'Signature check should not be reached' }
            { Assert-DownloadedFile $File 'Exe' } | Should -Throw '*possibly a proxy*'
            Should -Invoke Assert-MicrosoftSignature -Times 0 -Exactly
        }
    }

    It 'rejects a valid signature from a different publisher' {
        InModuleScope OfflineUpdate.Common {
            Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Example, O=Example Corporation, C=US' } } }
            { Assert-MicrosoftSignature 'fake.exe' } | Should -Throw '*Microsoft signature validation failed*'
        }
    }
}

Describe 'Native process progress' {
    It 'shows and clears elapsed progress while preserving the installer exit code' {
        InModuleScope OfflineUpdate.Common {
            Mock Write-Progress {}
            $command = Join-Path $env:SystemRoot 'System32\cmd.exe'
            Invoke-CheckedProcess $command '/d /c exit 23' $TestDrive @(23) -Activity 'Test process' | Should -Be 23
            Should -Invoke Write-Progress -ParameterFilter { $Activity -eq 'Test process' -and $Status -match '^Elapsed:' -and -not $Completed }
            Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Activity -eq 'Test process' -and $Completed }
        }
    }

    It 'clears progress and reports failure for an unaccepted exit code' {
        InModuleScope OfflineUpdate.Common {
            Mock Write-Progress {}
            $command = Join-Path $env:SystemRoot 'System32\cmd.exe'
            { Invoke-CheckedProcess $command '/d /c exit 23' $TestDrive } | Should -Throw '*exit code 23*'
            Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Activity -eq 'Running cmd.exe' -and $Completed }
        }
    }
}

Describe 'Offline mode separation' {
    It 'runs no product installers in VerifyOnly mode' {
        InModuleScope OfflineUpdate.Common {
            Mock Assert-DeploymentPackage { [pscustomobject]@{ Catalog = [pscustomobject]@{ Path = '10-Scan\wsusscn2.cab' } } }
            Mock Invoke-OfflineAssessment { [pscustomobject]@{ Scan = 'Mock assessment' } }
            Mock Invoke-LocalProductUpdates { throw 'Unexpected installer path' }
            Mock Invoke-OfficeLocalUpdate { throw 'Unexpected Office update' }
            Mock Invoke-CheckedProcess { throw 'Unexpected process launch' }
            Mock Get-SystemInventory { throw 'Unexpected installation preflight' }
            Invoke-OfflineMaintenance -Mode VerifyOnly -Root $TestDrive -Directory $TestDrive
            Should -Invoke Invoke-OfflineAssessment -Times 1 -Exactly
            Should -Invoke Invoke-LocalProductUpdates -Times 0 -Exactly
            Should -Invoke Invoke-OfficeLocalUpdate -Times 0 -Exactly
            Should -Invoke Invoke-CheckedProcess -Times 0 -Exactly
            Should -Invoke Get-SystemInventory -Times 0 -Exactly
        }
    }

    It 'does not scan unverified payloads and still produces an assessment' {
        InModuleScope OfflineUpdate.Common {
            Mock Assert-DeploymentPackage { throw 'Hash mismatch' }
            Mock Invoke-OfflineAssessment { param($SkipScanReason) $SkipScanReason }
            Invoke-OfflineMaintenance -Mode VerifyOnly -Root $TestDrive -Directory $TestDrive | Should -Match 'Hash mismatch'
            Should -Invoke Invoke-OfflineAssessment -Times 1 -ParameterFilter { $SkipScanReason -like '*verification failed*' }
        }
    }
}

Describe 'Office update configuration safety' {
    It 'configures updates without installing or removing products or changing bitness' {
        $path = Join-Path $TestDrive 'update.xml'
        New-OfficeUpdateConfiguration $path 'C:\Offline Office & source' '16.0.1.2' 'PerpetualVL2021'
        [xml]$xml = Get-Content -LiteralPath $path -Raw
        $xml.Configuration.Updates.UpdatePath | Should -Be 'C:\Offline Office & source'
        $xml.Configuration.Updates.Channel | Should -Be 'PerpetualVL2021'
        $xml.SelectNodes('//Add|//Remove|//RemoveMSI|//Property|//@MigrateArch').Count | Should -Be 0
    }

    It 'applies only the matching Office 2024 <Architecture> source and verifies its build' -TestCases @(
        @{ Architecture = 'x86' }, @{ Architecture = 'x64' }
    ) {
        param($Architecture)
        $state = New-TestState
        $state.Package.Office = New-TestMixedOfficePackage
        $state.Inventory.Office.ProductReleaseIds = 'ProPlus2024Volume'
        $state.Inventory.Office.Platform = $Architecture
        $state.Inventory.Office.Channel = ''
        $state.Inventory.Office.CDNBaseUrl = 'http://officecdn.microsoft.com/pr/7983bac0-e531-40cf-be00-fd24fe66619c'
        $state.Inventory.Office.Version = '16.0.17932.21056'
        InModuleScope OfflineUpdate.Common -Parameters @{ Fixture = $state } {
            param($Fixture)
            Mock Get-RegistryValues { $null }
            Mock Get-ScheduledTask { [pscustomobject]@{ State = 'Ready' } }
            Mock Get-Service { [pscustomobject]@{ Status = 'Running' } }
            Mock Assert-OfficeSource {}
            Mock Save-OfficeUpdateSettings { [pscustomobject]@{ Name = 'UpdateUrl'; Existed = $false } }
            Mock Restore-OfficeUpdateSettings {}
            Mock Invoke-CheckedProcess { 0 }
            Mock Start-ScheduledTask {}
            Mock Get-SystemInventory {
                $Fixture.Inventory.Office.Version = '16.0.17932.21140'
                $Fixture.Inventory
            }
            Invoke-OfficeLocalUpdate $TestDrive $TestDrive $Fixture.Package $Fixture.Inventory -TimeoutSeconds 0 | Should -Be 0
            [xml]$xml = Get-Content -LiteralPath (Join-Path $TestDrive 'Office-LocalUpdate.xml') -Raw
            $xml.Configuration.Updates.UpdatePath | Should -Be (Join-Path $TestDrive "Office\2024\$($Fixture.Inventory.Office.Platform)")
            $xml.Configuration.Updates.TargetVersion | Should -Be '16.0.17932.21140'
            $xml.Configuration.Updates.Channel | Should -Be 'PerpetualVL2024'
            $xml.Configuration.ChildNodes.Count | Should -Be 1
            Should -Invoke Start-ScheduledTask -Times 1 -Exactly
            Should -Invoke Restore-OfficeUpdateSettings -Times 1 -Exactly
        }
    }

    It 'restores previous update settings even when Office configuration fails' {
        $state = New-TestState
        InModuleScope OfflineUpdate.Common -Parameters @{ Fixture = $state } {
            param($Fixture)
            Mock Get-RegistryValues { $null }
            Mock Get-ScheduledTask { [pscustomobject]@{ State = 'Ready' } }
            Mock Get-Service { [pscustomobject]@{ Status = 'Running' } }
            Mock Assert-OfficeSource {}
            Mock Save-OfficeUpdateSettings { [pscustomobject]@{ Name = 'UpdateUrl'; Existed = $false } }
            Mock Restore-OfficeUpdateSettings {}
            Mock Invoke-CheckedProcess { throw 'Simulated Office configuration failure' }
            Mock Start-ScheduledTask {}
            { Invoke-OfficeLocalUpdate $TestDrive $TestDrive $Fixture.Package $Fixture.Inventory } | Should -Throw '*configuration failure*'
            Should -Invoke Restore-OfficeUpdateSettings -Times 1 -Exactly
            Should -Invoke Start-ScheduledTask -Times 0 -Exactly
        }
    }

    It 'refuses to override an IT update policy' {
        $state = New-TestState
        InModuleScope OfflineUpdate.Common -Parameters @{ Fixture = $state } {
            param($Fixture)
            Mock Get-RegistryValues { [pscustomobject]@{ UpdatePath = '\\IT\ManagedOffice' } }
            Mock Save-OfficeUpdateSettings { throw 'Must not change managed Office' }
            Mock Invoke-CheckedProcess { throw 'Must not run setup' }
            { Invoke-OfficeLocalUpdate $TestDrive $TestDrive $Fixture.Package $Fixture.Inventory } | Should -Throw '*managed by IT*'
            Should -Invoke Save-OfficeUpdateSettings -Times 0 -Exactly
            Should -Invoke Invoke-CheckedProcess -Times 0 -Exactly
        }
    }
}

Describe 'Entrypoint safety and syntax' {
    It 'parses all workflow scripts without running them' {
        $paths = @('Prepare-OfflinePackage.ps1', 'Run-OfflineMaintenance.ps1', '10-Scan\Scan-OfflinePC.ps1', '00-Control\OfflineUpdate.Common.psm1')
        foreach ($relative in $paths) {
            $tokens = $null
            $errors = $null
            [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Toolkit $relative), [ref]$tokens, [ref]$errors)
            @($errors).Count | Should -Be 0 -Because "$relative must parse"
        }
    }

    It 'allows a no-operation preview without elevation or scanning' {
        & (Join-Path $script:Toolkit 'Run-OfflineMaintenance.ps1') -Mode VerifyOnly -WhatIf
    }

    It 'does not bypass execution policy in the launcher' {
        Get-Content (Join-Path $script:Toolkit 'Start-OfflineUpdate.cmd') -Raw | Should -Not -Match 'ExecutionPolicy|Bypass|Unrestricted'
    }
}

Describe 'Installed product selection' {
    It 'supports both existing Office architectures without migration' -TestCases @(@{ Architecture = 'x86' }, @{ Architecture = 'x64' }) {
        param($Architecture)
        $state = New-TestState
        $state.Inventory.Office.Platform = $Architecture
        $plan = @(Get-ProductUpdatePlan $state.Inventory $state.Package)
        ($plan | Where-Object Component -EQ Office).Status | Should -Be 'Required'
    }

    It 'selects the installed LTSC <Year> release from a package with both Office releases' -TestCases @(
        @{ Year = '2021'; TargetVersion = '16.0.14334.21048' }
        @{ Year = '2024'; TargetVersion = '16.0.17932.21140' }
    ) {
        param($Year, $TargetVersion)
        $state = New-TestState
        $state.Package.Office = New-TestMixedOfficePackage
        $state.Inventory.Office.ProductReleaseIds = "ProPlus${Year}Volume"
        $state.Inventory.Office.Channel = "PerpetualVL$Year"
        $office = Get-ProductUpdatePlan $state.Inventory $state.Package | Where-Object Component -EQ Office
        $office.Target | Should -Be $TargetVersion
        $office.Status | Should -Be 'Required'
    }

    It 'skips products that already meet or exceed the package versions' {
        $state = New-TestState
        $state.Inventory.Defender.SignatureVersion = '1.3.0.0'
        $state.Inventory.Edge.Version = '131.0.0.0'
        $state.Inventory.Office.Version = '16.0.3.0'
        @(Get-ProductUpdatePlan $state.Inventory $state.Package | Where-Object Status -NE Current).Count | Should -Be 0
    }

    It 'does not install absent software' {
        $state = New-TestState
        $state.Inventory.Defender.Available = $false
        $state.Inventory.Edge.Detected = $false
        $state.Inventory.Office.Detected = $false
        @(Get-ProductUpdatePlan $state.Inventory $state.Package | Where-Object Status -NE Absent).Count | Should -Be 0
    }

    It 'does not fall back to Office 2021 when the package lacks a 2024 source' {
        $state = New-TestState
        $state.Inventory.Office.ProductReleaseIds = 'ProPlus2024Volume'
        $state.Inventory.Office.Channel = 'PerpetualVL2024'
        (Get-ProductUpdatePlan $state.Inventory $state.Package | Where-Object Component -EQ Office).Status | Should -Be 'Unsupported'
    }

    It 'limits the effect of a running <RunningProcess> process' -TestCases @(
        @{ RunningProcess = 'msedge'; BlockedComponent = 'Edge' }
        @{ RunningProcess = 'WINWORD'; BlockedComponent = 'Office' }
        @{ RunningProcess = 'OfficeClickToRun'; BlockedComponent = '' }
    ) {
        param($RunningProcess, $BlockedComponent)
        InModuleScope OfflineUpdate.Common -Parameters @{ Fixture = (New-TestState); RunningProcess = $RunningProcess; BlockedComponent = $BlockedComponent } {
            param($Fixture, $RunningProcess, $BlockedComponent)
            Mock Get-Process { if ($Name -contains $RunningProcess) { [pscustomobject]@{ ProcessName = $RunningProcess } } }
            Mock Invoke-CheckedProcess { 0 }
            Mock Invoke-OfficeLocalUpdate { 0 }
            Mock Wait-ProductTarget { $Fixture.Inventory }
            $results = @(Invoke-LocalProductUpdates $TestDrive $TestDrive $Fixture.Package $Fixture.Inventory)
            $results.Count | Should -Be 3
            foreach ($result in $results) {
                if ($result.Component -eq $BlockedComponent) {
                    $result.Status | Should -Be 'Blocked'
                    $result.Message | Should -Match $RunningProcess
                }
                else { $result.Status | Should -Be 'Updated' }
            }
            $expectedOfficeCalls = if ($BlockedComponent -eq 'Office') { 0 } else { 1 }
            Should -Invoke Invoke-OfficeLocalUpdate -Times $expectedOfficeCalls -Exactly
            $expectedInstallerCalls = if ($BlockedComponent -eq 'Edge') { 1 } else { 2 }
            Should -Invoke Invoke-CheckedProcess -Times $expectedInstallerCalls -Exactly
        }
    }

    It 'stops further installers after the first product fails' {
        $state = New-TestState
        InModuleScope OfflineUpdate.Common -Parameters @{ Fixture = $state } {
            param($Fixture)
            Mock Invoke-CheckedProcess { throw 'Simulated installer failure' }
            Mock Invoke-OfficeLocalUpdate { throw 'Must not reach Office' }
            Mock Wait-ProductTarget { throw 'Must not wait after failure' }
            $results = @(Invoke-LocalProductUpdates $TestDrive $TestDrive $Fixture.Package $Fixture.Inventory)
            $results[0].Status | Should -Be 'Failed'
            $results[1].Status | Should -Be 'NotRun'
            $results[2].Status | Should -Be 'NotRun'
            Should -Invoke Invoke-CheckedProcess -Times 1 -Exactly
            Should -Invoke Invoke-OfficeLocalUpdate -Times 0 -Exactly
            Should -Invoke Wait-ProductTarget -Times 0 -Exactly
        }
    }

    It 'stops for a requested reboot without starting the next installer' {
        $state = New-TestState
        InModuleScope OfflineUpdate.Common -Parameters @{ Fixture = $state } {
            param($Fixture)
            Mock Invoke-CheckedProcess { 3010 }
            Mock Wait-ProductTarget { throw 'Must not wait before a reboot' }
            $results = @(Invoke-LocalProductUpdates $TestDrive $TestDrive $Fixture.Package $Fixture.Inventory)
            $results[0].Status | Should -Be 'RebootRequired'
            $results[1].Status | Should -Be 'NotRun'
            Should -Invoke Invoke-CheckedProcess -Times 1 -Exactly
            Should -Invoke Wait-ProductTarget -Times 0 -Exactly
        }
    }

    It 'does not assume asynchronous update success when the version never advances' {
        $state = New-TestState
        InModuleScope OfflineUpdate.Common -Parameters @{ Fixture = $state } {
            param($Fixture)
            Mock Get-SystemInventory { $Fixture.Inventory }
            Mock Wait-UpdatePoll { throw 'A zero-timeout test must not sleep' }
            Mock Write-Progress {}
            { Wait-ProductTarget -Component Edge -Package $Fixture.Package -TimeoutSeconds 0 } | Should -Throw '*NOT assumed*'
            Should -Invoke Wait-UpdatePoll -Times 0 -Exactly
            Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Activity -eq 'Waiting for Edge update' -and $Completed }
        }
    }
}