#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateScript({Test-Path $_ -PathType Container})][string]$PayloadRoot,
    [Parameter(Mandatory=$true)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$ManifestPath,
    [string]$ReportPath = (Join-Path $PSScriptRoot '..\50-Reports\PayloadVerification.csv')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PayloadRoot=(Resolve-Path $PayloadRoot).Path
$manifest=Import-Csv $ManifestPath

function Test-ManifestExcludedPath {
    param([string]$RelativePath)
    return ($RelativePath -like '40-Logs\*' -or
            $RelativePath -like '50-Reports\*' -or
            $RelativePath -in @('00-Control\PayloadManifest.csv','00-Control\PayloadManifest.json'))
}

$report=New-Object System.Collections.Generic.List[object]
foreach($m in $manifest){
    $path=Join-Path $PayloadRoot $m.RelativePath
    $exists=Test-Path $path -PathType Leaf
    $hash=$null; $hashMatch=$false; $sigStatus='NotChecked'; $signer=$null; $signatureAcceptable=$true
    if($exists){
        $hash=(Get-FileHash $path -Algorithm SHA256).Hash
        $hashMatch=($hash -eq $m.SHA256)
        if([IO.Path]::GetExtension($path).ToLowerInvariant() -in @('.exe','.msi')){
            $sig=Get-AuthenticodeSignature $path
            $sigStatus=$sig.Status.ToString()
            $signer=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{$null}
            $signatureAcceptable=($sig.Status -eq 'Valid' -and $signer -match 'Microsoft')
        }
    }
    $report.Add([pscustomobject]@{RelativePath=$m.RelativePath;Finding='ManifestEntry';Exists=$exists;HashMatch=$hashMatch;SignatureStatus=$sigStatus;SignerSubject=$signer;SignatureAcceptable=$signatureAcceptable;Pass=($exists -and $hashMatch -and $signatureAcceptable)})
}

$manifestPaths=@($manifest.RelativePath)
foreach($f in Get-ChildItem $PayloadRoot -File -Recurse){
    $relative=$f.FullName.Substring($PayloadRoot.Length).TrimStart('\')
    if(Test-ManifestExcludedPath $relative){continue}
    if($relative -notin $manifestPaths){
        $report.Add([pscustomobject]@{RelativePath=$relative;Finding='UnexpectedFile';Exists=$true;HashMatch=$false;SignatureStatus='NotEvaluated';SignerSubject=$null;SignatureAcceptable=$false;Pass=$false})
    }
}

New-Item -ItemType Directory -Path (Split-Path $ReportPath) -Force | Out-Null
$report|Export-Csv $ReportPath -NoTypeInformation -Encoding UTF8
$failed=@($report|Where-Object {-not $_.Pass})
if($failed.Count){$failed|Format-Table -AutoSize|Out-Host; throw "Payload verification failed for $($failed.Count) file(s)."}
Write-Host "Payload verification passed for $($report.Count) controlled files."
