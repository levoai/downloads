<#
.SYNOPSIS
Installs the Levo DAST worker(s) AND the API test runner on one Docker host (Windows).

.DESCRIPTION
Windows twin of install-all.sh. An on-prem DAST scan hands its post-crawl API tests to
the test runner, so on-prem customers need both.

Run it from a folder that already holds docker-compose.yml and scale.ps1, or anywhere
else: it downloads those two files into -Dir first.

The auth key is taken from LEVOAI_AUTH_KEY or prompted for. It is never written to disk;
the .env this script writes holds settings only.
Works in Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Dast
DAST workers for on-demand scans. Default: 1

.PARAMETER Scheduled
DAST workers for scheduled scans. Default: 0

.PARAMETER Testrunner
API test runners. Default: 1

.PARAMETER Org
Organization ID. Defaults to LEVOAI_ORG_ID.

.PARAMETER Group
Group for DAST workers and test runners. Default: none.

.PARAMETER Region
us or india. Picks the API URL.

.PARAMETER BaseUrl
A specific API URL. Overrides -Region. Defaults to LEVOAI_BASE_URL.

.PARAMETER Workspace
Workspace ID for the DAST health heartbeat. Defaults to LEVOAI_WORKSPACE_ID.

.PARAMETER ImageTag
Image tag for both images. Default: stable

.PARAMETER Dir
Install folder when the files are downloaded. Default: .\levo-dast-testrunner

.PARAMETER Ref
Branch or tag of levoai/downloads to download from. Default: main

.PARAMETER NoWait
Do not wait for the DAST workers to report healthy.

.EXAMPLE
.\install-all.ps1 -Group qa_team -Dast 2
#>
[CmdletBinding()]
param(
    [int]$Dast = 1,
    [int]$Scheduled = 0,
    [int]$Testrunner = 1,
    [string]$Org = $env:LEVOAI_ORG_ID,
    [string]$Group,
    [ValidateSet('us', 'india')]
    [string]$Region,
    [string]$BaseUrl = $env:LEVOAI_BASE_URL,
    [string]$Workspace = $env:LEVOAI_WORKSPACE_ID,
    [string]$ImageTag,
    [string]$Dir,
    [string]$Ref = 'main',
    [switch]$NoWait
)

$ErrorActionPreference = 'Stop'

$ScriptDir = $PSScriptRoot
$DefaultBaseUrl = 'https://api.levo.ai'
$IndiaBaseUrl = 'https://api.india-1.levo.ai'
$DefaultDir = 'levo-dast-testrunner'
$RawBase = if ($env:LEVO_DOWNLOADS_BASE) { $env:LEVO_DOWNLOADS_BASE } else { 'https://raw.githubusercontent.com/levoai/downloads' }

function Stop-WithError([string]$Message) {
    [Console]::Error.WriteLine("Error: $Message")
    exit 1
}

if ($Dast -lt 0 -or $Scheduled -lt 0 -or $Testrunner -lt 0) { Stop-WithError '-Dast, -Scheduled and -Testrunner must be zero or more.' }

# .env is read by Docker Compose, which treats these characters specially.
if ("$Group$Workspace$ImageTag" -match '[$#"''\\]') {
    Stop-WithError '-Group, -Workspace and -ImageTag cannot contain $ # quotes or backslashes.'
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Stop-WithError 'docker was not found. Install Docker Desktop (https://docs.docker.com/desktop/install/windows-install/) and try again.'
}
docker info 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Stop-WithError 'Docker is installed but not running. Start Docker Desktop and try again.' }
docker compose version 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Stop-WithError "Docker Compose v2 was not found ('docker compose'). Update Docker Desktop." }

# Windows PowerShell 5.1 can default to TLS versions raw.githubusercontent.com no longer accepts.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { Write-Verbose 'Could not enable TLS 1.2' }

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

if (-not $Dir -and (Test-Path -LiteralPath (Join-Path $ScriptDir 'docker-compose.yml')) -and (Test-Path -LiteralPath (Join-Path $ScriptDir 'scale.ps1'))) {
    $InstallDir = $ScriptDir
    Write-Host "Using the files in $InstallDir"
} else {
    if (-not $Dir) { $Dir = $DefaultDir }
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $InstallDir = (Resolve-Path -LiteralPath $Dir).Path
    Write-Host "Downloading install files (ref: $Ref) into $InstallDir ..."
    foreach ($file in @('docker-compose.yml', 'scale.ps1')) {
        $part = Join-Path $InstallDir "$file.part"
        try { Get-RemoteFile "$RawBase/$Ref/dast-and-testrunner/$file" $part }
        catch { Stop-WithError "Could not download $file. Check your network and that ref '$Ref' exists. ($_)" }
        if ((Get-Item -LiteralPath $part).Length -eq 0) { Stop-WithError "Downloaded $file is empty." }
        Move-Item -Force -LiteralPath $part -Destination (Join-Path $InstallDir $file)
    }
    if (-not (Select-String -LiteralPath (Join-Path $InstallDir 'docker-compose.yml') -Pattern '^name: levo-dast-testrunner' -Quiet)) {
        Stop-WithError 'Downloaded docker-compose.yml is not the expected file.'
    }
}

if (-not $Org) {
    if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) {
        Stop-WithError 'Organization ID is not set. Use -Org or set LEVOAI_ORG_ID.'
    }
    $Org = Read-Host -Prompt 'Levo organization ID'
    if (-not $Org) { Stop-WithError 'Organization ID cannot be empty.' }
}

if ($Region -and -not $BaseUrl) {
    $BaseUrl = if ($Region -eq 'india') { $IndiaBaseUrl } else { $DefaultBaseUrl }
}
if (-not $BaseUrl) { $BaseUrl = $DefaultBaseUrl }

# Settings only, no secrets: later .\scale.ps1 runs read them, so the org, group and URL need not
# be typed again. An existing .env is never overwritten.
$envFile = Join-Path $InstallDir '.env'
if (Test-Path -LiteralPath $envFile) {
    Write-Host "Keeping the existing $envFile. Options given now apply to this run only; edit .env to make them permanent."
} else {
    $lines = @(
        '# Written by install-all.ps1. Settings only: the auth key is never stored here.',
        "LEVOAI_ORG_ID=$Org",
        "LEVOAI_BASE_URL=$BaseUrl",
        "DAST_REPLICAS=$Dast",
        "DAST_SCHEDULED_REPLICAS=$Scheduled",
        "TESTRUNNER_REPLICAS=$Testrunner"
    )
    if ($Group) { $lines += @("DAST_GROUP=$Group", "TESTRUNNER_GROUP=$Group") }
    if ($Workspace) { $lines += "LEVOAI_WORKSPACE_ID=$Workspace" }
    if ($ImageTag) { $lines += @("DAST_IMAGE_TAG=$ImageTag", "TESTRUNNER_IMAGE_TAG=$ImageTag") }
    [IO.File]::WriteAllText($envFile, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
}

$scaleArgs = @{
    Dast = $Dast
    Scheduled = $Scheduled
    Testrunner = $Testrunner
    Org = $Org
    BaseUrl = $BaseUrl
}
if ($Group) { $scaleArgs.Group = $Group }
if ($Workspace) { $scaleArgs.Workspace = $Workspace }
if ($ImageTag) { $scaleArgs.ImageTag = $ImageTag }
if ($NoWait) { $scaleArgs.NoWait = $true }

& (Join-Path $InstallDir 'scale.ps1') up @scaleArgs

Write-Host ''
Write-Host "Done. Manage it from ${InstallDir}:"
Write-Host '  .\scale.ps1 status'
Write-Host '  .\scale.ps1 scale -Dast 4 -Testrunner 2'
Write-Host '  .\scale.ps1 logs dast'
Write-Host '  .\scale.ps1 down'
