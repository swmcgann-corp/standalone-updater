#requires -version 5.1
#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('PreReboot','PostReboot')]
    [string]$Stage,

    [string]$ToolkitRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$PlanPath = (Join-Path $PSScriptRoot 'PatchPlan.csv')
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ToolkitRoot=(Resolve-Path $ToolkitRoot).Path
$PlanPath=(Resolve-Path $PlanPath).Path
$logDir=Join-Path $ToolkitRoot '40-Logs'
$reportDir=Join-Path $ToolkitRoot '50-Reports'
New-Item -ItemType Directory -Path $logDir -Force|Out-Null
New-Item -ItemType Directory -Path $reportDir -Force|Out-Null
$runId=Get-Date -Format 'yyyyMMdd-HHmmss'
Start-Transcript -Path (Join-Path $logDir "Apply-$Stage-$runId.log") -Force|Out-Null
$results=New-Object System.Collections.Generic.List[object]
$rebootRequired=$false

function Invoke-ProcessChecked {
    param([string]$FilePath,[string]$Arguments,[int[]]$SuccessCodes=@(0,1641,3010))
    $p=Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -Wait
    if($p.ExitCode -notin $SuccessCodes){throw "Process failed: $FilePath $Arguments (exit $($p.ExitCode))"}
    return $p.ExitCode
}

try{
    $plan=Import-Csv $PlanPath |
        Where-Object {$_.Stage -eq $Stage -and $_.Enabled -match '^(?i:true|yes|1)$'} |
        Sort-Object {[int]$_.Sequence}

    if(-not $plan){throw "No enabled PatchPlan.csv rows were found for stage '$Stage'."}

    foreach($item in $plan){
        $path=Join-Path $ToolkitRoot $item.RelativePath
        if(-not(Test-Path $path -PathType Leaf)){throw "Planned file missing: $path"}
        $start=Get-Date; $exit=0; $status='Success'
        try{
            if($PSCmdlet.ShouldProcess($path,"Apply $($item.Component) [$Stage]")){
                switch($item.Component){
                    'DefenderSecurityIntelligence' { $exit=Invoke-ProcessChecked $path '/quiet' }
                    'WindowsPackage' {
                        $args="/Online /Add-Package /PackagePath:`"$path`" /Quiet /NoRestart"
                        $exit=Invoke-ProcessChecked "$env:SystemRoot\System32\dism.exe" $args @(0,3010)
                    }
                    'DefenderPlatform' { $exit=Invoke-ProcessChecked $path '/quiet /norestart' }
                    'OfficeODT' {
                        $xml=Join-Path $ToolkitRoot $item.Arguments
                        if(-not(Test-Path $xml)){throw "Office XML missing: $xml"}
                        $exit=Invoke-ProcessChecked $path "/configure `"$xml`"" @(0)
                    }
                    'EdgeMSI' {
                        $edgeLog=Join-Path $logDir "Edge-$runId.log"
                        $args="/i `"$path`" /qn /norestart /L*v `"$edgeLog`""
                        $exit=Invoke-ProcessChecked "$env:SystemRoot\System32\msiexec.exe" $args @(0,1641,3010)
                    }
                    default { throw "Unknown component type: $($item.Component)" }
                }
                if($exit -in @(1641,3010)){$rebootRequired=$true}
            }
        }catch{
            $status='Failed'
            $results.Add([pscustomobject]@{Stage=$Stage;Sequence=$item.Sequence;Component=$item.Component;File=$item.RelativePath;Status=$status;ExitCode=$exit;Started=$start;Finished=Get-Date;Message=$_.Exception.Message})
            throw
        }
        $results.Add([pscustomobject]@{Stage=$Stage;Sequence=$item.Sequence;Component=$item.Component;File=$item.RelativePath;Status=$status;ExitCode=$exit;Started=$start;Finished=Get-Date;Message=''})
    }
}finally{
    $resultPath=Join-Path $reportDir "ApplyResults-$Stage-$runId.csv"
    $results|Export-Csv $resultPath -NoTypeInformation -Encoding UTF8
    @(
        "Stage=$Stage"
        "RebootRequired=$rebootRequired"
        "Completed=$(Get-Date -Format o)"
    )|Set-Content (Join-Path $reportDir "ApplyStatus-$Stage-$runId.txt")
    Stop-Transcript|Out-Null
}
Write-Host "Patch stage '$Stage' completed. Reboot required: $rebootRequired"
if($Stage -eq 'PreReboot'){
    Write-Host 'Restart the computer and verify Windows health before running the PostReboot stage.'
}
