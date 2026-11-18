# Runs install-shadownet.ps1 against a stub docker and asserts what docker was asked to do.
# Run it under each host you care about (powershell.exe = 5.1, pwsh = 7).
param(
    [Parameter(Mandatory)][string]$Script,
    [Parameter(Mandatory)][string]$StubDir
)
$ErrorActionPreference = 'Stop'
$hostExe = (Get-Process -Id $PID).Path
$log = Join-Path $StubDir 'calls.log'
$sep = [IO.Path]::PathSeparator
$env:PATH = "$StubDir$sep$env:PATH"
$env:STUB_LOG = $log
$failures = 0

function Invoke-Script([string[]]$ScriptArgs, [hashtable]$Env = @{}) {
    if (Test-Path $log) { Remove-Item $log }
    foreach ($k in 'LEVOAI_AUTH_KEY', 'LEVOAI_ORG_ID', 'LEVOAI_GROUP', 'LEVOAI_BASE_URL', 'LEVOAI_WORKSPACE_ID') { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
    foreach ($k in $Env.Keys) { Set-Item "Env:$k" $Env[$k] }
    $out = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $Script @ScriptArgs 2>&1 | Out-String
    $text = if (Test-Path $log) { Get-Content -Raw $log } else { '' }
    return @{ Code = $LASTEXITCODE; Out = $out; Log = $text }
}

function Assert-That([bool]$Cond, [string]$Name, [string]$Detail = '') {
    if ($Cond) { Write-Host "  ok   $Name" } else { Write-Host "  FAIL $Name $Detail"; $script:failures++ }
}

Write-Host "host: $($PSVersionTable.PSVersion) ($hostExe)"
Write-Host "script: $Script"

Write-Host '== install: group with a space, scheduled, india, workspace'
$r = Invoke-Script @('-Org', 'org-1', '-Group', 'QA Team', '-Scheduled', '-Region', 'india', '-Workspace', 'ws-1', '-NoPull') @{ LEVOAI_AUTH_KEY = 'SECRETKEY123' }
Assert-That ($r.Code -eq 0) 'exit code 0' "got $($r.Code): $($r.Out)"
$args1 = ($r.Log -split "`n" | Where-Object { $_ -like 'ARG:*' } | ForEach-Object { $_.Substring(4).TrimEnd("`r") })
Assert-That ($r.Log -match "ARG:LEVOAI_GROUP=QA Team") 'group with a space is ONE argument'
Assert-That ($r.Log -match "ARG:levoai-shadownet-QA-Team-scheduled") 'container name slug'
Assert-That ($r.Log -match "ARG:SHADOWNET_SCHEDULED=true") 'scheduled flag'
Assert-That ($r.Log -match "ARG:LEVOAI_WORKSPACE_ID=ws-1") 'workspace'
Assert-That ($r.Log -match "ARG:--stop-signal\s+ARG:SIGINT") 'stop signal SIGINT'
Assert-That ($r.Log -match "ARG:--shm-size=1g") 'shm size'
Assert-That ($args1[-2] -eq 'levoai/levoai-shadownet:stable' -or $args1 -contains 'levoai/levoai-shadownet:stable') 'image'
Assert-That ($r.Log -match "ARG:worker") 'worker command'
Assert-That (-not ($r.Log -match 'SECRETKEY123')) 'auth key is NOT on any docker command line'
Assert-That ($r.Log -match 'ENVKEY:set') 'auth key reaches docker through the environment'
Assert-That ($r.Out -match "api.india-1.levo.ai") 'india API URL printed'
Assert-That ($r.Out -match "stop -Group 'QA Team' -Scheduled") 'stop hint quotes the group' $r.Out

Write-Host '== install: key and org from environment, defaults'
$r = Invoke-Script @('-NoPull', '-NoWait') @{ LEVOAI_AUTH_KEY = 'k'; LEVOAI_ORG_ID = 'org-env' }
Assert-That ($r.Code -eq 0) 'exit code 0' $r.Out
Assert-That ($r.Log -match 'ARG:levoai-shadownet\s') 'default container name'
Assert-That (-not ($r.Log -match 'LEVOAI_GROUP')) 'no group variable when no group'

Write-Host '== missing key'
$r = Invoke-Script @('-Org', 'o', '-NoPull') @{}
Assert-That ($r.Code -ne 0) 'non-zero exit' "got $($r.Code)"
Assert-That ($r.Out -match 'LEVOAI_AUTH_KEY') 'message names LEVOAI_AUTH_KEY' $r.Out
Assert-That (-not ($r.Log -match 'ARG:run')) 'docker run was not called'

Write-Host '== missing org'
$r = Invoke-Script @('-NoPull') @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -ne 0) 'non-zero exit' "got $($r.Code)"
Assert-That ($r.Out -match 'Organization ID') 'message names organization' $r.Out

Write-Host '== bad region'
$r = Invoke-Script @('-Org', 'o', '-Region', 'mars') @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -ne 0) 'non-zero exit' "got $($r.Code)"

Write-Host '== stop'
$r = Invoke-Script @('stop', '-Group', 'QA Team') @{}
Assert-That ($r.Code -eq 0) 'exit code 0' $r.Out
Assert-That ($r.Out -match "No container named 'levoai-shadownet-QA-Team'") 'looks for the right container' $r.Out

if ($failures -gt 0) { Write-Host "`n$failures check(s) FAILED"; exit 1 }
Write-Host "`nall checks passed"
