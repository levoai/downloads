<#
.SYNOPSIS
Starts ONE Levo DAST worker (levoai/levoai-shadownet) in Docker on Windows.

.DESCRIPTION
Windows twin of install-shadownet.sh. To run several workers, or the API test
runner next to it, use docker-compose.yml in this folder.

The auth key is taken from LEVOAI_AUTH_KEY or prompted for, and is handed to
Docker by name, so it never appears on a command line or in a file.
Works in Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Command
install (default), status, logs or stop.

.PARAMETER Org
Organization ID. Defaults to LEVOAI_ORG_ID.

.PARAMETER Group
Join a worker group. Used exactly as typed (case-sensitive).

.PARAMETER Scheduled
Take scheduled scans only (default: on-demand scans).

.PARAMETER Region
us or india. Picks the API URL.

.PARAMETER BaseUrl
A specific API URL. Overrides -Region. Defaults to LEVOAI_BASE_URL.

.PARAMETER Workspace
Workspace ID for the health heartbeat. Defaults to LEVOAI_WORKSPACE_ID.

.PARAMETER ImageTag
Image tag. Default: stable

.PARAMETER Name
Container name. Default: levoai-shadownet[-GROUP][-scheduled]

.PARAMETER NoPull
Use the local image instead of pulling.

.PARAMETER NoWait
Do not wait for the worker to report healthy.

.EXAMPLE
.\install-shadownet.ps1 -Group qa_team

.EXAMPLE
.\install-shadownet.ps1 stop -Group qa_team
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'status', 'logs', 'stop')]
    [string]$Command = 'install',
    [string]$Org = $env:LEVOAI_ORG_ID,
    [string]$Group = $env:LEVOAI_GROUP,
    [switch]$Scheduled,
    [ValidateSet('us', 'india')]
    [string]$Region,
    [string]$BaseUrl = $env:LEVOAI_BASE_URL,
    [string]$Workspace = $env:LEVOAI_WORKSPACE_ID,
    [string]$ImageTag = 'stable',
    [string]$Name,
    [switch]$NoPull,
    [switch]$NoWait
)

$ErrorActionPreference = 'Stop'

$ImageRepo = 'levoai/levoai-shadownet'
$DefaultBaseUrl = 'https://api.levo.ai'
$IndiaBaseUrl = 'https://api.india-1.levo.ai'
# install-dast-proxy.sh names its container this; warn rather than run two workers by accident.
$ProxyScriptContainer = 'levoai-shadownet-worker'
$HealthWaitSeconds = 120

function Stop-WithError([string]$Message) {
    [Console]::Error.WriteLine("Error: $Message")
    exit 1
}

# Container names allow letters, digits, "_", "." and "-"; anything else in a group becomes "-".
function ConvertTo-Slug([string]$Value) {
    return ($Value -replace '[^A-Za-z0-9_.-]', '-')
}

function Assert-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Stop-WithError 'docker was not found. Install Docker Desktop (https://docs.docker.com/desktop/install/windows-install/) and try again.'
    }
    docker info 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError 'Docker is installed but not running. Start Docker Desktop and try again.'
    }
}

function Test-ContainerExists([string]$ContainerName) {
    $names = docker ps -a --filter "name=^/$ContainerName`$" --format '{{.Names}}'
    return [bool]($names | Where-Object { $_ -eq $ContainerName })
}

function Get-ContainerHealth([string]$ContainerName) {
    $state = docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $ContainerName 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $state) { return 'missing' }
    return "$state".Trim()
}

function Read-Secret([string]$Label) {
    if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) {
        return $null
    }
    $secure = Read-Host -Prompt $Label -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

$NameGiven = [bool]$Name
if (-not $Name) {
    $Name = 'levoai-shadownet'
    if ($Group) { $Name = "$Name-$(ConvertTo-Slug $Group)" }
    if ($Scheduled) { $Name = "$Name-scheduled" }
}

if ($Region -and -not $BaseUrl) {
    $BaseUrl = if ($Region -eq 'india') { $IndiaBaseUrl } else { $DefaultBaseUrl }
}
if (-not $BaseUrl) { $BaseUrl = $DefaultBaseUrl }

function Invoke-Install {
    Assert-Docker

    if (-not $env:LEVOAI_AUTH_KEY) {
        $key = Read-Secret 'Levo auth key (input hidden)'
        if (-not $key) { Stop-WithError 'LEVOAI_AUTH_KEY is not set. Set it and run again.' }
        $env:LEVOAI_AUTH_KEY = $key
    }
    if (-not $Org) {
        Stop-WithError 'Organization ID is not set. Use -Org or set LEVOAI_ORG_ID.'
    }

    if (Test-ContainerExists $Name) {
        Stop-WithError "A container named '$Name' already exists. Run '.\install-shadownet.ps1 stop -Name $Name' first, or pick another with -Name."
    }
    if ($Name -ne $ProxyScriptContainer -and (Test-ContainerExists $ProxyScriptContainer)) {
        [Console]::Error.WriteLine("Note: '$ProxyScriptContainer' (from install-dast-proxy.sh) is already running. This starts a second, separate worker.")
    }

    $image = "${ImageRepo}:${ImageTag}"
    if (-not $NoPull) {
        Write-Host "Pulling $image ..."
        docker pull $image | Out-Null
        if ($LASTEXITCODE -ne 0) { Stop-WithError "Could not pull $image." }
    }

    # Values reach the container through the environment, by name, so the key stays off the command line.
    $env:LEVOAI_ORG_ID = $Org
    $env:LEVOAI_BASE_URL = $BaseUrl

    # Registration-sensitive settings (group, workspace) are kept together in this block.
    $identityArgs = @()
    if ($Group) { $identityArgs += @('-e', "LEVOAI_GROUP=$Group") }
    if ($Workspace) { $identityArgs += @('-e', "LEVOAI_WORKSPACE_ID=$Workspace") }
    $modeArgs = @()
    if ($Scheduled) { $modeArgs += @('-e', 'SHADOWNET_SCHEDULED=true') }

    $groupText = if ($Group) { $Group } else { '(none)' }
    $scanText = if ($Scheduled) { 'scheduled' } else { 'on-demand' }
    Write-Host "Starting $Name ..."
    Write-Host "  Image:    $image"
    Write-Host "  Org:      $Org"
    Write-Host "  API URL:  $BaseUrl"
    Write-Host "  Group:    $groupText"
    Write-Host "  Scans:    $scanText"

    $runArgs = @(
        'run', '-d',
        '--name', $Name,
        '--restart', 'unless-stopped',
        '--shm-size=1g',
        '--stop-timeout', '300',
        '--stop-signal', 'SIGINT',
        '--security-opt', 'no-new-privileges:true',
        '-e', 'LEVOAI_AUTH_KEY',
        '-e', 'LEVOAI_ORG_ID',
        '-e', 'LEVOAI_BASE_URL'
    ) + $identityArgs + $modeArgs + @($image, 'worker')
    docker @runArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-WithError 'docker run failed. See the message above.' }

    if (-not $NoWait) {
        Write-Host -NoNewline 'Waiting for the worker to become healthy'
        $waited = 0
        $state = ''
        while ($waited -lt $HealthWaitSeconds) {
            $state = Get-ContainerHealth $Name
            if ($state -eq 'healthy') { break }
            if ($state -in @('exited', 'dead', 'missing')) {
                Write-Host ''
                docker logs --tail 20 $Name
                Stop-WithError 'The worker stopped right after starting. See the log lines above.'
            }
            Write-Host -NoNewline '.'
            Start-Sleep -Seconds 3
            $waited += 3
        }
        Write-Host ''
        $state = Get-ContainerHealth $Name
        if ($state -ne 'healthy') {
            [Console]::Error.WriteLine("The worker is '$state' after ${HealthWaitSeconds}s. It may still be starting; check the logs below.")
        }
    }

    if ($NameGiven) {
        $stopHint = ".\install-shadownet.ps1 stop -Name $Name"
    } else {
        $stopHint = '.\install-shadownet.ps1 stop'
        if ($Group) { $stopHint += " -Group '$Group'" }
        if ($Scheduled) { $stopHint += ' -Scheduled' }
    }
    Write-Host "'$Name' started."
    Write-Host "  Check it:  docker ps --filter name=$Name"
    Write-Host "  Logs:      docker logs -f $Name"
    Write-Host "  Stop it:   $stopHint"
}

function Invoke-Status {
    Assert-Docker
    if (-not (Test-ContainerExists $Name)) { Stop-WithError "No container named '$Name'." }
    docker ps -a --filter "name=^/$Name`$" --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
}

function Invoke-Logs {
    Assert-Docker
    if (-not (Test-ContainerExists $Name)) { Stop-WithError "No container named '$Name'." }
    docker logs -f $Name
}

function Invoke-Stop {
    Assert-Docker
    if (Test-ContainerExists $Name) {
        Write-Host "Stopping $Name (a running scan is allowed up to 5 minutes to finish) ..."
        docker stop $Name | Out-Null
        docker rm $Name | Out-Null
        Write-Host "'$Name' stopped and removed."
    } else {
        Write-Host "No container named '$Name'."
    }
}

switch ($Command) {
    'install' { Invoke-Install }
    'status' { Invoke-Status }
    'logs' { Invoke-Logs }
    'stop' { Invoke-Stop }
}
