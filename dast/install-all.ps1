<#
.SYNOPSIS
Installs, resizes and removes the Levo DAST workers and the API test runner with Docker Compose.

.DESCRIPTION
Windows twin of install-all.sh. One scan, or one test run, runs per container, so the
number of containers is the number of things that run in parallel.

Run it from a folder that already holds docker-compose.yml, or anywhere else: install
downloads that file into -Dir first.

The auth key is taken from LEVOAI_AUTH_KEY, from .env, or prompted for. It is never written
to disk; the .env this script writes holds settings only.
Works in Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Command
install (default), scale, status, logs or down.
  install Install, or converge to, the requested workers and test runner.
  scale   Change the number of running containers without restarting the others.
  status  Show what is running.
  logs    Follow logs. Optional second argument: dast, scheduled or testrunner.
  down    Stop and remove everything this script started.

.PARAMETER Dast
DAST workers for on-demand scans.

.PARAMETER Scheduled
DAST workers for scheduled scans.

.PARAMETER Testrunner
API test runners.

An omitted count is left as it is (scale), or taken from DAST_REPLICAS /
DAST_SCHEDULED_REPLICAS / TESTRUNNER_REPLICAS / TESTRUNNER_SCHEDULED_REPLICAS in the environment or .env, else 1 / 0 / 1 / 0 (install).

.PARAMETER TestrunnerScheduled
API test runners for scheduled test runs.

.PARAMETER CaCert
CA the DAST workers trust for Levo, Temporal and the browser (internal CA, TLS-inspecting proxy). Copied into .\certs.

.PARAMETER TargetCaCert
CA for the target application only.

.PARAMETER ClientCert
Client certificate (mutual TLS) presented to the target. Needs -ClientKey.

.PARAMETER ClientKey
Private key for -ClientCert.

.PARAMETER Org
Organization ID. Defaults to LEVOAI_ORG_ID.

.PARAMETER Group
Group for DAST workers and test runners.

.PARAMETER Region
us or india. Picks the API URL.

.PARAMETER BaseUrl
A specific API URL. Overrides -Region.

.PARAMETER ImageTag
Image tag for both images. Default: stable

.PARAMETER Dir
Install folder when docker-compose.yml is downloaded. Default: .\levo-dast-testrunner

.PARAMETER Ref
Branch or tag of levoai/downloads to download from. Default: main

.PARAMETER Force
Allow more DAST workers than the memory check suggests.

.PARAMETER NoWait
Do not wait for the DAST workers to report healthy.

.EXAMPLE
.\install-all.ps1 -Dast 2 -Testrunner 1

.EXAMPLE
.\install-all.ps1 scale -Dast 4
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'up', 'scale', 'status', 'logs', 'down')]
    [string]$Command = 'install',
    [Parameter(Position = 1)]
    [ValidateSet('', 'dast', 'scheduled', 'testrunner', 'testrunner-scheduled')]
    [string]$LogTarget = '',
    [int]$Dast = -1,
    [int]$Scheduled = -1,
    [int]$Testrunner = -1,
    [int]$TestrunnerScheduled = -1,
    [string]$CaCert,
    [string]$TargetCaCert,
    [string]$ClientCert,
    [string]$ClientKey,
    [string]$Org = $env:LEVOAI_ORG_ID,
    [string]$Group = $env:RUNNER_GROUP,
    [ValidateSet('us', 'india')]
    [string]$Region,
    [string]$BaseUrl = $env:LEVOAI_BASE_URL,
    [string]$ImageTag,
    [string]$Dir,
    [string]$Ref = 'main',
    [switch]$Force,
    [switch]$NoWait
)

$ErrorActionPreference = 'Stop'
if ($Command -eq 'up') { $Command = 'install' }
$ScriptDir = $PSScriptRoot
$DefaultDir = 'levo-dast-testrunner'
$RawBase = if ($env:LEVO_DOWNLOADS_BASE) { $env:LEVO_DOWNLOADS_BASE } else { 'https://raw.githubusercontent.com/levoai/downloads' }

# The memory cap is derived from the host (see Get-MaxDast); the hard caps protect Levo's
# shared pollers when a typo asks for 500 containers.
$HardMaxDast = 20
$HardMaxTestrunner = 20
$HealthWaitSeconds = 180
$ServiceDast = 'dast-worker'
$ServiceScheduled = 'dast-worker-scheduled'
$ServiceTestrunner = 'testrunner'
$ServiceTestrunnerScheduled = 'testrunner-scheduled'
$CertDirInContainer = '/etc/shadownet/certs'
$DefaultBaseUrl = 'https://api.levo.ai'
$IndiaBaseUrl = 'https://api.india-1.levo.ai'

function Stop-WithError([string]$Message) {
    [Console]::Error.WriteLine("Error: $Message")
    exit 1
}

function Get-RemoteFile([string]$Url, [string]$Destination) {
    $lastError = $null
    foreach ($attempt in 1..3) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination
            return
        } catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Seconds 2
        }
    }
    throw $lastError
}

# The folder holding docker-compose.yml and .env: next to this script if it has the compose file,
# else -Dir. Only install may download the file; the other commands need an existing install.
function Enter-InstallDir {
    $target = $script:Dir
    if (-not $target -and (Test-Path -LiteralPath (Join-Path $ScriptDir 'docker-compose.yml'))) {
        $target = $ScriptDir
    } else {
        if (-not $target) { $target = $DefaultDir }
        if (-not (Test-Path -LiteralPath (Join-Path $target 'docker-compose.yml'))) {
            if ($Command -ne 'install') { Stop-WithError "No install found in $target. Run this from the install folder, or pass -Dir." }
            # Windows PowerShell 5.1 can default to TLS versions raw.githubusercontent.com no longer accepts.
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { Write-Verbose 'Could not enable TLS 1.2' }
            New-Item -ItemType Directory -Force -Path $target | Out-Null
            $full = (Resolve-Path -LiteralPath $target).Path
            Write-Host "Downloading docker-compose.yml (ref: $Ref) into $full ..."
            $part = Join-Path $full 'docker-compose.yml.part'
            try { Get-RemoteFile "$RawBase/$Ref/dast/docker-compose.yml" $part }
            catch { Stop-WithError "Could not download docker-compose.yml. Check your network and that ref '$Ref' exists. ($_)" }
            if ((Get-Item -LiteralPath $part).Length -eq 0) { Stop-WithError 'Downloaded docker-compose.yml is empty.' }
            if (-not (Select-String -LiteralPath $part -Pattern '^name: levo-dast-testrunner' -Quiet)) { Stop-WithError 'Downloaded docker-compose.yml is not the expected file.' }
            Move-Item -Force -LiteralPath $part -Destination (Join-Path $full 'docker-compose.yml')
        }
    }
    $script:InstallDir = (Resolve-Path -LiteralPath $target).Path
    # Keep a copy beside docker-compose.yml, so "Manage it from <folder>" works whatever folder the
    # script was first run from.
    $copy = Join-Path $script:InstallDir 'install-all.ps1'
    if ($Command -eq 'install' -and -not (Test-Path -LiteralPath $copy) -and $PSCommandPath) {
        Copy-Item -LiteralPath $PSCommandPath -Destination $copy
    }
    Set-Location -LiteralPath $script:InstallDir
}

# Settings only, no secrets: later runs read them, so the org, group and URL need not be typed
# again. An existing .env is never overwritten.
function Write-EnvFile([int]$DastCount, [int]$ScheduledCount, [int]$TestrunnerCount, [int]$TestrunnerScheduledCount) {
    $envFile = Join-Path $script:InstallDir '.env'
    if (Test-Path -LiteralPath $envFile) {
        Write-Host "Keeping the existing $envFile. Options given now apply to this run only; edit .env to make them permanent."
        return
    }
    $baseUrl = if ($env:LEVOAI_BASE_URL) { $env:LEVOAI_BASE_URL } else { $DefaultBaseUrl }
    $lines = @(
        '# Written by install-all.ps1. Settings only: the auth key is never stored here.',
        "LEVOAI_ORG_ID=$env:LEVOAI_ORG_ID",
        "LEVOAI_BASE_URL=$baseUrl",
        "DAST_REPLICAS=$DastCount",
        "DAST_SCHEDULED_REPLICAS=$ScheduledCount",
        "TESTRUNNER_REPLICAS=$TestrunnerCount",
        "TESTRUNNER_SCHEDULED_REPLICAS=$TestrunnerScheduledCount"
    )
    if ($Group) { $lines += "RUNNER_GROUP=$Group" }
    if ($ImageTag) { $lines += @("DAST_IMAGE_TAG=$ImageTag", "TESTRUNNER_IMAGE_TAG=$ImageTag") }
    foreach ($name in 'LEVOAI_CA_CERT', 'CA_CERT_PATH', 'CLIENT_CERT_PATH', 'CLIENT_KEY_PATH') {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { $lines += "$name=$value" }
    }
    [IO.File]::WriteAllText($envFile, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
}

function Assert-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Stop-WithError 'docker was not found. Install Docker Desktop (https://docs.docker.com/desktop/install/windows-install/) and try again.'
    }
    docker info 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-WithError 'Docker is installed but not running. Start Docker Desktop and try again.' }
    docker compose version 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Docker Compose v2 was not found ('docker compose'). Update Docker Desktop." }
    Enter-InstallDir
}

# Environment first, then .env, so a value set in either place is honoured.
function Get-EnvValue([string]$Name) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if (-not $value -and (Test-Path -LiteralPath '.env')) {
        $line = Get-Content -LiteralPath '.env' | Where-Object { $_ -match "^$Name=" } | Select-Object -Last 1
        if ($line) { $value = ($line -replace "^$Name=", '').TrimEnd("`r") }
    }
    return $value
}

function Invoke-Compose {
    # Windows PowerShell 5.1 turns native stderr into a terminating error under 'Stop' when it is redirected.
    $ErrorActionPreference = 'Continue'
    docker compose --profile dast --profile scheduled --profile api-testing --profile api-testing-scheduled @args
}

function Get-RunningCount([string]$Service) {
    $ErrorActionPreference = 'Continue'
    $ids = @(Invoke-Compose ps -q --status running $Service 2>$null | Where-Object { $_ })
    return $ids.Count
}

function ConvertTo-Mib([string]$Limit) {
    if ($Limit -match '^(\d+)[gG]$') { return [int]$Matches[1] * 1024 }
    if ($Limit -match '^(\d+)[mM]$') { return [int]$Matches[1] }
    return 2048
}

# Memory is what limits DAST workers: each is a headless Chromium. 1 GiB is left for the
# test runner and the host.
function Get-MaxDast {
    $ErrorActionPreference = 'Continue'
    $memBytes = 0
    $raw = docker info --format '{{.MemTotal}}' 2>$null
    if ($raw) { [void][long]::TryParse("$raw".Trim(), [ref]$memBytes) }
    $memMib = [math]::Floor($memBytes / 1MB)
    $perMib = ConvertTo-Mib (Get-EnvValue 'DAST_MEMORY_LIMIT')
    if ($perMib -le 0) { $perMib = 2048 }
    $fits = [math]::Floor(($memMib - 1024) / $perMib)
    if ($fits -lt 1) { $fits = 1 }
    return [int]$fits
}

function Read-Secret([string]$Label) {
    if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) { return $null }
    $secure = Read-Host -Prompt $Label -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

# down, status and logs never use the key, but compose still insists the variables exist.
function Set-PlaceholderCredentials {
    if (-not $env:LEVOAI_AUTH_KEY) { $env:LEVOAI_AUTH_KEY = 'unused' }
    if (-not $env:LEVOAI_ORG_ID) { $env:LEVOAI_ORG_ID = 'unused' }
}

function Set-Settings {
    $key = Get-EnvValue 'LEVOAI_AUTH_KEY'
    if (-not $key) {
        $key = Read-Secret 'Levo auth key (input hidden)'
        if (-not $key) { Stop-WithError 'LEVOAI_AUTH_KEY is not set. Set it, put it in .env, or run this from a terminal.' }
    }
    $env:LEVOAI_AUTH_KEY = $key

    $orgId = $script:Org
    if (-not $orgId) { $orgId = Get-EnvValue 'LEVOAI_ORG_ID' }
    if (-not $orgId) { Stop-WithError 'Organization ID is not set. Use -Org, set LEVOAI_ORG_ID, or put it in .env.' }
    $env:LEVOAI_ORG_ID = $orgId

    $url = $script:BaseUrl
    if ($script:Region -and -not $url) {
        $url = if ($script:Region -eq 'india') { $IndiaBaseUrl } else { $DefaultBaseUrl }
    }
    if ($url) { $env:LEVOAI_BASE_URL = $url }
    if ($script:Group) {
        $env:RUNNER_GROUP = $script:Group
    }
    if ($script:ImageTag) {
        $env:DAST_IMAGE_TAG = $script:ImageTag
        $env:TESTRUNNER_IMAGE_TAG = $script:ImageTag
    }
}

# Copies a certificate file into .\certs and sets the variable that points the workers at it.
function Copy-Cert([string]$Variable, [string]$Source) {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { Stop-WithError "Certificate file not found: $Source" }
    $name = Split-Path -Leaf $Source
    New-Item -ItemType Directory -Force -Path 'certs' | Out-Null
    Copy-Item -Force -LiteralPath $Source -Destination (Join-Path 'certs' $name)
    [Environment]::SetEnvironmentVariable($Variable, "$CertDirInContainer/$name")
}

function Copy-Certs {
    if (($script:ClientCert -or $script:ClientKey) -and -not ($script:ClientCert -and $script:ClientKey)) {
        Stop-WithError '-ClientCert and -ClientKey must be given together.'
    }
    if ($script:CaCert) { Copy-Cert 'LEVOAI_CA_CERT' $script:CaCert }
    if ($script:TargetCaCert) { Copy-Cert 'CA_CERT_PATH' $script:TargetCaCert }
    if ($script:ClientCert) { Copy-Cert 'CLIENT_CERT_PATH' $script:ClientCert }
    if ($script:ClientKey) { Copy-Cert 'CLIENT_KEY_PATH' $script:ClientKey }
}

function Resolve-Count([int]$Explicit, [string]$Service, [string]$EnvName, [int]$Fallback) {
    if ($Explicit -ge 0) { return $Explicit }
    if ($script:Command -eq 'scale') { return (Get-RunningCount $Service) }
    $value = Get-EnvValue $EnvName
    if ($value) {
        if ($value -notmatch '^\d+$') { Stop-WithError "$EnvName must be a whole number, got '$value'" }
        return [int]$value
    }
    return $Fallback
}

function Test-Caps([int]$DastCount, [int]$ScheduledCount, [int]$TestrunnerCount, [int]$TestrunnerScheduledCount) {
    if ($DastCount -gt $HardMaxDast) { Stop-WithError "-Dast $DastCount is above the limit of $HardMaxDast per host. Run another host instead." }
    if ($ScheduledCount -gt $HardMaxDast) { Stop-WithError "-Scheduled $ScheduledCount is above the limit of $HardMaxDast per host. Run another host instead." }
    if ($TestrunnerCount -gt $HardMaxTestrunner) { Stop-WithError "-Testrunner $TestrunnerCount is above the limit of $HardMaxTestrunner per host. Run another host instead." }
    if ($TestrunnerScheduledCount -gt $HardMaxTestrunner) { Stop-WithError "-TestrunnerScheduled $TestrunnerScheduledCount is above the limit of $HardMaxTestrunner per host. Run another host instead." }
    $fits = Get-MaxDast
    $total = $DastCount + $ScheduledCount
    if ($total -gt $fits -and -not $Force) {
        $needGiB = [math]::Ceiling($total * (ConvertTo-Mib (Get-EnvValue 'DAST_MEMORY_LIMIT')) / 1024)
        Stop-WithError "$total DAST workers need about $needGiB GiB, but Docker has memory for $fits. Lower the count, give Docker more memory, or add -Force."
    }
}

function Wait-Healthy {
    $ErrorActionPreference = 'Continue'
    $waited = 0
    $pending = 0
    Write-Host -NoNewline 'Waiting for DAST workers to become healthy'
    while ($waited -lt $HealthWaitSeconds) {
        $ids = @(Invoke-Compose ps -q $ServiceDast $ServiceScheduled 2>$null | Where-Object { $_ })
        $pending = 0
        foreach ($id in $ids) {
            $state = docker inspect --format '{{if eq .State.Status "running"}}{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}{{else}}{{.State.Status}}{{end}}' $id 2>$null
            $state = "$state".Trim()
            if (-not $state) { $state = 'missing' }
            if ($state -in @('exited', 'dead', 'restarting', 'missing')) {
                Write-Host ''
                Stop-WithError "A DAST worker keeps stopping. Run '.\install-all.ps1 logs dast' to see why (a 401 means the auth key or organization ID is wrong)."
            }
            if ($state -ne 'healthy') { $pending++ }
        }
        if ($pending -eq 0) { break }
        Write-Host -NoNewline '.'
        Start-Sleep -Seconds 3
        $waited += 3
    }
    Write-Host ''
    if ($pending -gt 0) {
        [Console]::Error.WriteLine("Some DAST workers are still starting after ${HealthWaitSeconds}s. Check '.\install-all.ps1 status'.")
    }
}

function Invoke-Apply {
    # .env is read by Docker Compose, which treats these characters specially.
    if ("$Group$ImageTag" -match '[$#"''\\]') {
        Stop-WithError '-Group and -ImageTag cannot contain $ # quotes or backslashes.'
    }
    if ($Command -eq 'scale' -and ($CaCert -or $TargetCaCert -or $ClientCert -or $ClientKey)) {
        Stop-WithError 'Certificate options apply to install only. Edit .env and run install again to change them.'
    }
    # The script changes into the install folder later, so certificate paths must not stay relative.
    foreach ($name in 'CaCert', 'TargetCaCert', 'ClientCert', 'ClientKey') {
        $path = (Get-Variable -Name $name -Scope Script).Value
        if ($path -and -not [IO.Path]::IsPathRooted($path)) { Set-Variable -Name $name -Scope Script -Value (Join-Path (Get-Location).Path $path) }
    }
    Assert-Docker
    Set-Settings
    if ($Command -eq 'install') { Copy-Certs }
    docker container inspect levoai-shadownet-worker 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { [Console]::Error.WriteLine('Note: a worker started by install-dast-proxy.sh (levoai-shadownet-worker) is also running on this host.') }

    $dastCount = Resolve-Count $Dast $ServiceDast 'DAST_REPLICAS' 1
    $scheduledCount = Resolve-Count $Scheduled $ServiceScheduled 'DAST_SCHEDULED_REPLICAS' 0
    $testrunnerCount = Resolve-Count $Testrunner $ServiceTestrunner 'TESTRUNNER_REPLICAS' 1
    $testrunnerScheduledCount = Resolve-Count $TestrunnerScheduled $ServiceTestrunnerScheduled 'TESTRUNNER_SCHEDULED_REPLICAS' 0
    Test-Caps $dastCount $scheduledCount $testrunnerCount $testrunnerScheduledCount
    if ($Command -eq 'install') { Write-EnvFile $dastCount $scheduledCount $testrunnerCount $testrunnerScheduledCount }

    if ($Command -eq 'scale') {
        Write-Host "Scaling: DAST $(Get-RunningCount $ServiceDast) -> $dastCount, scheduled $(Get-RunningCount $ServiceScheduled) -> $scheduledCount, test runners $(Get-RunningCount $ServiceTestrunner) -> $testrunnerCount, scheduled test runners $(Get-RunningCount $ServiceTestrunnerScheduled) -> $testrunnerScheduledCount"
        Write-Host 'Removing a worker that is mid-scan lets it finish first (up to 5 minutes).'
    } else {
        Write-Host "Starting: DAST $dastCount, scheduled $scheduledCount, test runners $testrunnerCount, scheduled test runners $testrunnerScheduledCount"
    }

    $upArgs = @('up', '-d')
    if ($Command -eq 'scale') { $upArgs += '--no-recreate' }
    $upArgs += @('--scale', "$ServiceDast=$dastCount", '--scale', "$ServiceScheduled=$scheduledCount", '--scale', "$ServiceTestrunner=$testrunnerCount", '--scale', "$ServiceTestrunnerScheduled=$testrunnerScheduledCount")
    Invoke-Compose @upArgs
    if ($LASTEXITCODE -ne 0) { Stop-WithError 'docker compose up failed. See the message above.' }

    if (-not $NoWait -and ($dastCount + $scheduledCount) -gt 0) { Wait-Healthy }

    Write-Host ''
    Write-Host 'Running now:'
    Write-Host "  DAST workers (on-demand): $(Get-RunningCount $ServiceDast)"
    Write-Host "  DAST workers (scheduled): $(Get-RunningCount $ServiceScheduled)"
    Write-Host "  API test runners:         $(Get-RunningCount $ServiceTestrunner)"
    Write-Host "  API test runners (sched.): $(Get-RunningCount $ServiceTestrunnerScheduled)"
    if ($Command -eq 'install') {
        Write-Host ''
        Write-Host "Manage it from ${script:InstallDir}:"
        Write-Host '  .\install-all.ps1 status'
        Write-Host '  .\install-all.ps1 scale -Dast 4 -Testrunner 2'
        Write-Host '  .\install-all.ps1 logs dast'
        Write-Host '  .\install-all.ps1 down'
    }
}

switch ($Command) {
    { $_ -in 'install', 'scale' } { Invoke-Apply }
    'status' {
        Assert-Docker
        Set-PlaceholderCredentials
        Invoke-Compose ps
    }
    'logs' {
        Assert-Docker
        Set-PlaceholderCredentials
        $service = switch ($LogTarget) {
            'dast' { $ServiceDast }
            'scheduled' { $ServiceScheduled }
            'testrunner' { $ServiceTestrunner }
            'testrunner-scheduled' { $ServiceTestrunnerScheduled }
            default { $null }
        }
        if ($service) { Invoke-Compose logs -f --tail 100 $service } else { Invoke-Compose logs -f --tail 100 }
    }
    'down' {
        Assert-Docker
        Set-PlaceholderCredentials
        Write-Host 'Stopping everything (a worker mid-scan is allowed up to 5 minutes to finish) ...'
        Invoke-Compose down
    }
}
