<#
.SYNOPSIS
Runs and resizes the Levo DAST workers and the API test runner with Docker Compose.

.DESCRIPTION
Windows twin of scale.sh. Uses docker-compose.yml next to this script. One scan, or
one test run, runs per container, so the number of containers is the number of things
that run in parallel.

The auth key is taken from LEVOAI_AUTH_KEY, from .env, or prompted for.
Works in Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Command
up (default), scale, status, logs or down.
  up      Start (or converge) the workers and test runner.
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
DAST_SCHEDULED_REPLICAS / TESTRUNNER_REPLICAS in the environment or .env, else 1 / 0 / 0 (up).

.PARAMETER Org
Organization ID. Defaults to LEVOAI_ORG_ID.

.PARAMETER Group
Group for DAST workers and test runners.

.PARAMETER Region
us or india. Picks the API URL.

.PARAMETER BaseUrl
A specific API URL. Overrides -Region.

.PARAMETER Workspace
Workspace ID for the DAST health heartbeat.

.PARAMETER ImageTag
Image tag for both images. Default: stable

.PARAMETER Force
Allow more DAST workers than the memory check suggests.

.PARAMETER NoWait
Do not wait for the DAST workers to report healthy.

.EXAMPLE
.\scale.ps1 up -Dast 2 -Testrunner 1

.EXAMPLE
.\scale.ps1 scale -Dast 4
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('up', 'scale', 'status', 'logs', 'down')]
    [string]$Command = 'up',
    [Parameter(Position = 1)]
    [ValidateSet('', 'dast', 'scheduled', 'testrunner')]
    [string]$LogTarget = '',
    [int]$Dast = -1,
    [int]$Scheduled = -1,
    [int]$Testrunner = -1,
    [string]$Org = $env:LEVOAI_ORG_ID,
    [string]$Group,
    [ValidateSet('us', 'india')]
    [string]$Region,
    [string]$BaseUrl = $env:LEVOAI_BASE_URL,
    [string]$Workspace = $env:LEVOAI_WORKSPACE_ID,
    [string]$ImageTag,
    [switch]$Force,
    [switch]$NoWait
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

# The memory cap is derived from the host (see Get-MaxDast); the hard caps protect Levo's
# shared pollers when a typo asks for 500 containers.
$HardMaxDast = 20
$HardMaxTestrunner = 20
$HealthWaitSeconds = 180
$ServiceDast = 'dast-worker'
$ServiceScheduled = 'dast-worker-scheduled'
$ServiceTestrunner = 'testrunner'
$DefaultBaseUrl = 'https://api.levo.ai'
$IndiaBaseUrl = 'https://api.india-1.levo.ai'

function Stop-WithError([string]$Message) {
    [Console]::Error.WriteLine("Error: $Message")
    exit 1
}

function Assert-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Stop-WithError 'docker was not found. Install Docker Desktop (https://docs.docker.com/desktop/install/windows-install/) and try again.'
    }
    docker info 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-WithError 'Docker is installed but not running. Start Docker Desktop and try again.' }
    docker compose version 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Docker Compose v2 was not found ('docker compose'). Update Docker Desktop." }
    if (-not (Test-Path -LiteralPath 'docker-compose.yml')) { Stop-WithError 'docker-compose.yml was not found next to this script.' }
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
    docker compose --profile dast --profile scheduled --profile api-testing @args
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
    if ($script:Workspace) { $env:LEVOAI_WORKSPACE_ID = $script:Workspace }
    if ($script:Group) {
        $env:DAST_GROUP = $script:Group
        $env:TESTRUNNER_GROUP = $script:Group
    }
    if ($script:ImageTag) {
        $env:DAST_IMAGE_TAG = $script:ImageTag
        $env:TESTRUNNER_IMAGE_TAG = $script:ImageTag
    }
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

function Test-Caps([int]$DastCount, [int]$ScheduledCount, [int]$TestrunnerCount) {
    if ($DastCount -gt $HardMaxDast) { Stop-WithError "-Dast $DastCount is above the limit of $HardMaxDast per host. Run another host instead." }
    if ($ScheduledCount -gt $HardMaxDast) { Stop-WithError "-Scheduled $ScheduledCount is above the limit of $HardMaxDast per host. Run another host instead." }
    if ($TestrunnerCount -gt $HardMaxTestrunner) { Stop-WithError "-Testrunner $TestrunnerCount is above the limit of $HardMaxTestrunner per host. Run another host instead." }
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
            $state = docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $id 2>$null
            $state = "$state".Trim()
            if (-not $state) { $state = 'missing' }
            if ($state -in @('exited', 'dead', 'missing')) {
                Write-Host ''
                Stop-WithError "A DAST worker stopped right after starting. Run '.\scale.ps1 logs dast' to see why."
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
        [Console]::Error.WriteLine("Some DAST workers are still starting after ${HealthWaitSeconds}s. Check '.\scale.ps1 status'.")
    }
}

function Invoke-Apply {
    Assert-Docker
    Set-Settings

    $dastCount = Resolve-Count $Dast $ServiceDast 'DAST_REPLICAS' 1
    $scheduledCount = Resolve-Count $Scheduled $ServiceScheduled 'DAST_SCHEDULED_REPLICAS' 0
    $testrunnerCount = Resolve-Count $Testrunner $ServiceTestrunner 'TESTRUNNER_REPLICAS' 0
    Test-Caps $dastCount $scheduledCount $testrunnerCount

    if ($Command -eq 'scale') {
        Write-Host "Scaling: DAST $(Get-RunningCount $ServiceDast) -> $dastCount, scheduled $(Get-RunningCount $ServiceScheduled) -> $scheduledCount, test runners $(Get-RunningCount $ServiceTestrunner) -> $testrunnerCount"
        Write-Host 'Removing a worker that is mid-scan lets it finish first (up to 5 minutes).'
    } else {
        Write-Host "Starting: DAST $dastCount, scheduled $scheduledCount, test runners $testrunnerCount"
    }

    $upArgs = @('up', '-d')
    if ($Command -eq 'scale') { $upArgs += '--no-recreate' }
    $upArgs += @('--scale', "$ServiceDast=$dastCount", '--scale', "$ServiceScheduled=$scheduledCount", '--scale', "$ServiceTestrunner=$testrunnerCount")
    Invoke-Compose @upArgs
    if ($LASTEXITCODE -ne 0) { Stop-WithError 'docker compose up failed. See the message above.' }

    if (-not $NoWait -and ($dastCount + $scheduledCount) -gt 0) { Wait-Healthy }

    Write-Host ''
    Write-Host 'Running now:'
    Write-Host "  DAST workers (on-demand): $(Get-RunningCount $ServiceDast)"
    Write-Host "  DAST workers (scheduled): $(Get-RunningCount $ServiceScheduled)"
    Write-Host "  API test runners:         $(Get-RunningCount $ServiceTestrunner)"
}

switch ($Command) {
    { $_ -in 'up', 'scale' } { Invoke-Apply }
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
