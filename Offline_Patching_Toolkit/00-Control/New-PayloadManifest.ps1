#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$PayloadRoot,
    [string]$OutputDirectory = $PSScriptRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PayloadRoot = (Resolve-Path $PayloadRoot).Path
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

function Test-ManifestExcludedPath {
    param([string]$RelativePath)
    return ($RelativePath -like '40-Logs\*' -or
            $RelativePath -like '50-Reports\*' -or
            $RelativePath -in @('00-Control\PayloadManifest.csv','00-Control\PayloadManifest.json'))
}

$rows = foreach ($f in Get-ChildItem $PayloadRoot -File -Recurse | Sort-Object FullName) {
    $relative = $f.FullName.Substring($PayloadRoot.Length).TrimStart('\')
    if (Test-ManifestExcludedPath $relative) { continue }
    $sig = $null
    if ($f.Extension -in @('.exe','.msi','.ps1','.psm1','.dll')) {
        $sig = Get-AuthenticodeSignature -FilePath $f.FullName
    }
    [pscustomobject]@{
        RelativePath=$relative
        Length=$f.Length
        SHA256=(Get-FileHash $f.FullName -Algorithm SHA256).Hash
        SignatureStatus=if ($sig) {$sig.Status.ToString()} else {'ContainerOrNotChecked'}
        SignerSubject=if ($sig -and $sig.SignerCertificate) {$sig.SignerCertificate.Subject} else {$null}
        LastWriteTimeUtc=$f.LastWriteTimeUtc.ToString('o')
    }
}
$rows | Export-Csv (Join-Path $OutputDirectory 'PayloadManifest.csv') -NoTypeInformation -Encoding UTF8
$rows | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $OutputDirectory 'PayloadManifest.json') -Encoding UTF8
Write-Host "Manifest created for $($rows.Count) controlled files."
