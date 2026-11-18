# Runs install-all.ps1 against a stub docker and asserts what docker was asked to do.
param(
    [Parameter(Mandatory)][string]$Dir,
    [Parameter(Mandatory)][string]$StubDir,
    [string]$RawBase = '',
    [string]$Ref = 'main'
)
$ErrorActionPreference = 'Stop'
$hostExe = (Get-Process -Id $PID).Path
$log = Join-Path $StubDir 'calls.log'
$env:PATH = "$StubDir$([IO.Path]::PathSeparator)$env:PATH"
$env:STUB_LOG = $log
$failures = 0
$scriptPath = Join-Path $Dir 'install-all.ps1'
function New-Fresh { $d = Join-Path $StubDir ('f-' + [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory $d | Out-Null; Copy-Item (Join-Path $Dir 'docker-compose.yml'), $scriptPath $d; return $d }
$scale = $null

function Invoke-It([string]$Script, [string[]]$ScriptArgs, [hashtable]$Env = @{}) {
    $ErrorActionPreference = 'Continue'
    if (Test-Path $log) { Remove-Item $log }
    foreach ($k in 'LEVOAI_AUTH_KEY', 'LEVOAI_ORG_ID', 'LEVOAI_BASE_URL', 'LEVOAI_WORKSPACE_ID', 'DAST_GROUP', 'TESTRUNNER_GROUP', 'LEVO_DOWNLOADS_BASE') { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
    foreach ($k in $Env.Keys) { Set-Item "Env:$k" $Env[$k] }
    $out = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $Script @ScriptArgs 2>&1 | Out-String
    $text = if (Test-Path $log) { Get-Content -Raw $log } else { '' }
    return @{ Code = $LASTEXITCODE; Out = $out; Log = $text }
}
function Assert-That([bool]$Cond, [string]$Name, [string]$Detail = '') {
    if ($Cond) { Write-Host "  ok   $Name" } else { Write-Host "  FAIL $Name $Detail"; $script:failures++ }
}
function Has-Seq([string]$Log, [string[]]$Items) {
    $lines = @($Log -split "`n" | ForEach-Object { $_.TrimEnd("`r") })
    for ($i = 0; $i -le $lines.Count - $Items.Count; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $Items.Count; $j++) { if ($lines[$i + $j] -ne $Items[$j]) { $ok = $false; break } }
        if ($ok) { return $true }
    }
    return $false
}

Write-Host "host: $($PSVersionTable.PSVersion)  dir: $Dir"

Write-Host '== install'
$fresh = New-Fresh
Push-Location $fresh
$scale = Join-Path $fresh 'install-all.ps1'
$r = Invoke-It $scale @('install', '-Dast', '2', '-Testrunner', '1', '-Scheduled', '0', '-Group', 'QA Team', '-Org', 'org-1', '-BaseUrl', 'http://x.example', '-NoWait') @{ LEVOAI_AUTH_KEY = 'SECRETKEY123' }
Assert-That ($r.Code -eq 0) 'exit code 0' "got $($r.Code): $($r.Out)"
Assert-That ($r.Log -match 'ARG:compose') 'uses docker compose'
Assert-That (Has-Seq $r.Log @('ARG:--scale', 'ARG:dast-worker=2')) 'dast-worker=2'
Assert-That (Has-Seq $r.Log @('ARG:--scale', 'ARG:dast-worker-scheduled=0')) 'scheduled=0'
Assert-That (Has-Seq $r.Log @('ARG:--scale', 'ARG:testrunner=1')) 'testrunner=1'
Assert-That ($r.Log -match 'ENVGROUP:QA Team') 'group reaches compose through the environment, with its space'
Assert-That (-not ($r.Log -match 'SECRETKEY123')) 'auth key is NOT on any docker command line'
Assert-That ($r.Log -match 'ENVKEY:set') 'auth key reaches docker through the environment'
Assert-That (-not ($r.Log -match 'ARG:--no-recreate')) 'up converges (no --no-recreate)'

Write-Host '== scale keeps others, uses --no-recreate'
$r = Invoke-It $scale @('scale', '-Dast', '3', '-Org', 'o', '-NoWait') @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -eq 0) 'exit code 0' $r.Out
Assert-That ($r.Log -match 'ARG:--no-recreate') '--no-recreate'
Assert-That (Has-Seq $r.Log @('ARG:--scale', 'ARG:dast-worker=3')) 'dast-worker=3'

Write-Host '== scheduled test runner and certificates'
Pop-Location
$fresh = New-Fresh; Push-Location $fresh; $scale = Join-Path $fresh 'install-all.ps1'
$certDir = Join-Path $StubDir ('certs-' + [guid]::NewGuid().ToString('N').Substring(0, 6)); New-Item -ItemType Directory $certDir | Out-Null
'ca' | Set-Content (Join-Path $certDir 'ca.pem')
$r = Invoke-It $scale @('install', '-Dast', '1', '-Testrunner', '0', '-TestrunnerScheduled', '2', '-Org', 'o', '-CaCert', (Join-Path $certDir 'ca.pem'), '-NoWait') @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -eq 0) 'exit code 0' "got $($r.Code): $($r.Out)"
Assert-That (Has-Seq $r.Log @('ARG:--scale', 'ARG:testrunner-scheduled=2')) 'testrunner-scheduled=2'
Assert-That (Test-Path (Join-Path $fresh 'certs/ca.pem')) 'CA copied to .\certs'
Assert-That ((Get-Content -Raw (Join-Path $fresh '.env')) -match 'LEVOAI_CA_CERT=/etc/shadownet/certs/ca.pem') '.env points LEVOAI_CA_CERT at the mounted file'
Assert-That ($r.Log -match 'ARG:api-testing-scheduled') 'all four profiles are passed'
$r = Invoke-It $scale @('install', '-Org', 'o', '-ClientCert', (Join-Path $certDir 'ca.pem'), '-NoWait') @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -ne 0 -and $r.Out -match 'together') 'client cert without key is refused' $r.Out
$r = Invoke-It $scale @('scale', '-CaCert', (Join-Path $certDir 'ca.pem'), '-Org', 'o', '-NoWait') @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -ne 0 -and $r.Out -match 'install only') 'scale refuses certificate options' $r.Out

Write-Host '== limits and validation'
Pop-Location
$fresh = New-Fresh; Push-Location $fresh; $scale = Join-Path $fresh 'install-all.ps1'
$r = Invoke-It $scale @('install', '-Dast', '99', '-Org', 'o') @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -ne 0 -and $r.Out -match 'above the limit') 'hard cap rejects 99' $r.Out
Assert-That (-not ($r.Log -match 'ARG:up')) 'compose up not called'
$r = Invoke-It $scale @('install', '-Org', 'o') @{}
Assert-That ($r.Code -ne 0 -and $r.Out -match 'LEVOAI_AUTH_KEY') 'missing key is reported' $r.Out
$r = Invoke-It $scale @('install') @{ LEVOAI_AUTH_KEY = 'k' }
Assert-That ($r.Code -ne 0 -and $r.Out -match 'Organization ID') 'missing org is reported' $r.Out

Write-Host '== down and status work without credentials'
Pop-Location
$fresh = New-Fresh; Push-Location $fresh; $scale = Join-Path $fresh 'install-all.ps1'
$r = Invoke-It $scale @('down') @{}
Assert-That ($r.Code -eq 0 -and $r.Log -match 'ARG:down') 'down' $r.Out
$r = Invoke-It $scale @('status') @{}
Assert-That ($r.Code -eq 0 -and $r.Log -match 'ARG:ps') 'status' $r.Out
Pop-Location

Write-Host '== install (download mode)'
$work = Join-Path $StubDir ('work-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory $work | Out-Null
$alone = Join-Path $work 'alone'; New-Item -ItemType Directory $alone | Out-Null
Copy-Item $scriptPath $alone
Push-Location $work
$envs = @{ LEVOAI_AUTH_KEY = 'SECRETKEY123' }
if ($RawBase) { $envs.LEVO_DOWNLOADS_BASE = $RawBase }
$r = Invoke-It (Join-Path $alone 'install-all.ps1') @('-Org', 'org-9', '-Group', 'QA Team', '-Dast', '2', '-Testrunner', '1', '-Region', 'india', '-Ref', $Ref, '-NoWait') $envs
Assert-That ($r.Code -eq 0) 'exit code 0' "got $($r.Code): $($r.Out)"
$inst = Join-Path $work 'levo-dast-testrunner'
Assert-That (Test-Path (Join-Path $inst 'docker-compose.yml')) 'compose file downloaded'
Assert-That (Test-Path (Join-Path $inst 'install-all.ps1')) 'script copied next to the compose file'
$envText = if (Test-Path (Join-Path $inst '.env')) { Get-Content -Raw (Join-Path $inst '.env') } else { '' }
Assert-That ($envText -match 'LEVOAI_ORG_ID=org-9') '.env has the org'
Assert-That ($envText -match 'LEVOAI_BASE_URL=https://api.india-1.levo.ai') '.env has the india URL'
Assert-That ($envText -match 'DAST_GROUP=QA Team') '.env has the group'
Assert-That (-not ($envText -match 'SECRETKEY123')) 'key is NOT written to .env'
Assert-That (Has-Seq $r.Log @('ARG:--scale', 'ARG:dast-worker=2')) 'compose up with dast-worker=2'
Assert-That (-not ($r.Log -match 'SECRETKEY123')) 'key not on any docker command line'
Pop-Location

if ($failures -gt 0) { Write-Host "`n$failures check(s) FAILED"; exit 1 }
Write-Host "`nall checks passed"
