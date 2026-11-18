# Runs install-all-helm.ps1 against stub helm/kubectl and asserts what they were asked to do.
param(
    [Parameter(Mandatory)][string]$Script,
    [Parameter(Mandatory)][string]$StubDir
)
$ErrorActionPreference = 'Stop'
$hostExe = (Get-Process -Id $PID).Path
$log = Join-Path $StubDir 'calls.log'
$env:PATH = "$StubDir$([IO.Path]::PathSeparator)$env:PATH"
$env:STUB_LOG = $log
$failures = 0

function Invoke-It([string[]]$ScriptArgs, [hashtable]$Env = @{}) {
    $ErrorActionPreference = 'Continue'
    if (Test-Path $log) { Remove-Item $log }
    foreach ($k in 'LEVOAI_AUTH_KEY', 'LEVOAI_ORG_ID', 'LEVOAI_BASE_URL', 'LEVOAI_WORKSPACE_ID', 'STUB_INSTALLED') { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
    foreach ($k in $Env.Keys) { Set-Item "Env:$k" $Env[$k] }
    if ($PSVersionTable.PSVersion.Major -lt 7) { $ScriptArgs = @($ScriptArgs | ForEach-Object { $_ -replace '"', '\"' }) }
    $out = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $Script @ScriptArgs 2>&1 | Out-String
    $text = if (Test-Path $log) { Get-Content -Raw $log } else { '' }
    return @{ Code = $LASTEXITCODE; Out = $out; Log = $text }
}
function Assert-That([bool]$Cond, [string]$Name, [string]$Detail = '') {
    if ($Cond) { Write-Host "  ok   $Name" } else { Write-Host "  FAIL $Name $Detail"; $script:failures++ }
}
function Has-Line([string]$Log, [string]$Line) { return (@($Log -split "`n" | ForEach-Object { $_.TrimEnd("`r") }) -contains $Line) }

Write-Host "host: $($PSVersionTable.PSVersion)"
$common = @('-Context', 'ctx-1', '-Namespace', 'ns-1', '-Yes')

Write-Host '== install (dry run): every release, tricky group'
$r = Invoke-It (@('-Dast', '2', '-Scheduled', '1', '-Testrunner', '1', '-Group', 'QA,Team "x"', '-Org', 'org-1', '-Workspace', 'ws-1', '-Region', 'india', '-DryRun') + $common) @{ LEVOAI_AUTH_KEY = 'SECRETKEY123' }
Assert-That ($r.Code -eq 0) 'exit code 0' "got $($r.Code): $($r.Out)"
foreach ($rel in 'levoai-shadownet', 'levoai-shadownet-scheduled', 'testrunner') {
    Assert-That (Has-Line $r.Log "ARG:$rel") "release $rel is installed"
}
Assert-That (Has-Line $r.Log 'ARG:--repo') 'uses --repo'
Assert-That (Has-Line $r.Log 'ARG:https://charts.levo.ai') 'chart repo URL'
Assert-That (Has-Line $r.Log 'ARG:--kube-context') 'passes --kube-context'
Assert-That (Has-Line $r.Log 'ARG:replicaCount=2') 'dast replicaCount=2'
Assert-That (Has-Line $r.Log 'ARG:scheduled=true') 'scheduled=true on the scheduled release'
Assert-That (Has-Line $r.Log 'ARG:--dry-run') '--dry-run is passed'
Assert-That (-not ($r.Log -match 'ARG:--wait')) 'no --wait on a dry run'
Assert-That ($r.Log -match 'key: "SECRETKEY123"') 'key reaches helm on stdin'
Assert-That (-not (@($r.Log -split "`n" | Where-Object { $_ -like 'ARG:*' }) -match 'SECRETKEY123')) 'key is NOT on any command line'
Assert-That ($r.Log.Contains('group: "QA,Team \"x\""')) 'group with comma and quotes is escaped in the YAML' (($r.Log -split "`n" | Where-Object { $_ -like '*group:*' }) -join ' | ')
Assert-That (-not (@($r.Log -split "`n" | Where-Object { $_ -like 'ARG:*' }) -match 'QA,Team')) 'group is NOT on any command line'
Assert-That ($r.Log.Contains('LEVOAI_WORKSPACE_ID: "ws-1"')) 'dast workspace via extraEnv'
Assert-That ($r.Log.Contains('workspace: "ws-1"')) 'test runner workspace'
Assert-That ($r.Log.Contains('levoBaseUrl: "https://api.india-1.levo.ai"')) 'india URL'

Write-Host '== install (real): waits'
$r = Invoke-It (@('-Org', 'org-1') + $common) @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -eq 0) 'exit code 0' $r.Out
Assert-That (Has-Line $r.Log 'ARG:--wait') '--wait'
Assert-That (@($r.Log -split "`n" | Where-Object { $_.TrimEnd("`r") -eq 'ARG:upgrade' }).Count -eq 2) 'only dast and testrunner are installed (scheduled skipped at 0)'

Write-Host '== validation'
$r = Invoke-It (@('-Dast', '99', '-Org', 'o') + $common) @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -ne 0 -and $r.Out -match 'above the limit') 'hard cap rejects 99' $r.Out
$r = Invoke-It (@('-Org', 'o') + $common) @{}
Assert-That ($r.Code -ne 0 -and $r.Out -match 'LEVOAI_AUTH_KEY') 'missing key is reported' $r.Out
$r = Invoke-It @('-Org', 'o', '-Context', 'ctx-1') @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -ne 0 -and $r.Out -match 'Yes') 'without -Yes and no terminal, it refuses' $r.Out
Assert-That (-not (Has-Line $r.Log 'ARG:upgrade')) 'nothing installed when not confirmed'

Write-Host '== scale uses kubectl scale on installed releases only'
$r = Invoke-It (@('scale', '-Dast', '3', '-Testrunner', '0', '-Scheduled', '2') + $common) @{ STUB_INSTALLED = 'levoai-shadownet,testrunner' }
Assert-That ($r.Code -eq 0) 'exit code 0' $r.Out
Assert-That (Has-Line $r.Log 'ARG:deployment/levoai-shadownet') 'scales the dast deployment'
Assert-That (Has-Line $r.Log 'ARG:--replicas=3') 'replicas=3'
Assert-That (Has-Line $r.Log 'ARG:--replicas=0') 'testrunner replicas=0'
Assert-That (-not (Has-Line $r.Log 'ARG:deployment/levoai-shadownet-scheduled')) 'not-installed scheduled release is not scaled'

Write-Host '== uninstall'
$r = Invoke-It (@('uninstall') + $common) @{ STUB_INSTALLED = 'levoai-shadownet,testrunner' }
Assert-That ($r.Code -eq 0) 'exit code 0' $r.Out
Assert-That ((Has-Line $r.Log 'ARG:uninstall') -and (Has-Line $r.Log 'ARG:testrunner')) 'uninstalls installed releases'

if ($failures -gt 0) { Write-Host "`n$failures check(s) FAILED"; exit 1 }
Write-Host "`nall checks passed"
