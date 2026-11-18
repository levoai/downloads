<#
.SYNOPSIS
Installs the Levo DAST workers AND the API test runner on a Kubernetes cluster with Helm.

.DESCRIPTION
Windows twin of install-all-helm.sh (Kubernetes twin of install-all). An on-prem DAST scan hands its post-crawl API tests to
the test runner, so on-prem customers need both.

Charts come from https://charts.levo.ai. The script passes --repo to Helm, so your local
`helm repo` list is not changed.

The auth key is taken from LEVOAI_AUTH_KEY or prompted for, and is handed to Helm on stdin, so
it never appears on a command line. (The charts themselves pass the key to the container as an
argument, so anyone who can read the Deployment can read it. Restrict access to the namespace.)
Works in Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Command
install (default), scale, status or uninstall.

.PARAMETER Dast
DAST workers for on-demand scans. Default: 1

.PARAMETER Scheduled
DAST workers for scheduled scans. Default: 0

.PARAMETER Testrunner
API test runners. Default: 1. A count of 0 installs nothing for that release (scale: 0 pods).

.PARAMETER TestrunnerScheduled
API test runners for scheduled test runs. Default: 0

.PARAMETER CaCert
CA the DAST workers trust for Levo, Temporal and the browser (internal CA, TLS-inspecting proxy). Stored in the Secret levo-dast-certs.

.PARAMETER TargetCaCert
CA for the target application only.

.PARAMETER ClientCert
Client certificate (mutual TLS) presented to the target. Needs -ClientKey.

.PARAMETER ClientKey
Private key for -ClientCert.

.PARAMETER Namespace
Namespace. Default: levoai. Use one namespace per group.

.PARAMETER Context
kubectl/Helm context to use. Default: the current context.

.PARAMETER Org
Organization ID. Defaults to LEVOAI_ORG_ID.

.PARAMETER Group
Group for DAST workers and test runners. Default: none.

.PARAMETER Region
us or india. Picks the API URL.

.PARAMETER BaseUrl
A specific API URL. Overrides -Region. Defaults to LEVOAI_BASE_URL.

.PARAMETER Workspace
Workspace ID (DAST health heartbeat; test runner registration). Defaults to LEVOAI_WORKSPACE_ID.

.PARAMETER ImageTag
DAST worker image tag. Default: the chart's.

.PARAMETER TestrunnerImageTag
Test runner image tag. Default: the chart's.

.PARAMETER DastChartVersion
Pin the DAST chart version.

.PARAMETER TestrunnerChartVersion
Pin the test runner chart version.

.PARAMETER DryRun
Ask Helm to validate everything without installing.

.PARAMETER NoWait
Do not wait for the pods to start.

.PARAMETER Yes
Do not ask to confirm the cluster.

.EXAMPLE
.\install-all-helm.ps1 -Group qa_team -Namespace levoai-qa

.EXAMPLE
.\install-all-helm.ps1 scale -Dast 4 -Testrunner 2
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'scale', 'status', 'uninstall')]
    [string]$Command = 'install',
    [int]$Dast = -1,
    [int]$Scheduled = -1,
    [int]$Testrunner = -1,
    [int]$TestrunnerScheduled = -1,
    [string]$CaCert,
    [string]$TargetCaCert,
    [string]$ClientCert,
    [string]$ClientKey,
    [string]$Namespace = 'levoai',
    [string]$Context,
    [string]$Org = $env:LEVOAI_ORG_ID,
    [string]$Group,
    [ValidateSet('us', 'india')]
    [string]$Region,
    [string]$BaseUrl = $env:LEVOAI_BASE_URL,
    [string]$Workspace = $env:LEVOAI_WORKSPACE_ID,
    [string]$ImageTag,
    [string]$TestrunnerImageTag,
    [string]$DastChartVersion,
    [string]$TestrunnerChartVersion,
    [switch]$DryRun,
    [switch]$NoWait,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

$ChartRepo = 'https://charts.levo.ai'
$DefaultBaseUrl = 'https://api.levo.ai'
$IndiaBaseUrl = 'https://api.india-1.levo.ai'
$HardMax = 20
$WaitTimeout = '5m'

# Helm release and chart names. Each release owns one Deployment of the same name, so two groups
# in one namespace would collide: use one namespace per group.
$ReleaseDast = 'levoai-shadownet'
$ReleaseScheduled = 'levoai-shadownet-scheduled'
$ReleaseTestrunner = 'testrunner'
$ReleaseTestrunnerScheduled = 'testrunner-scheduled'
$CertSecret = 'levo-dast-certs'
$CertMountPath = '/etc/shadownet/certs'
$script:CertFiles = @{}
$ChartDast = 'levoai-shadownet'
$ChartTestrunner = 'testrunner'

function Stop-WithError([string]$Message) {
    [Console]::Error.WriteLine("Error: $Message")
    exit 1
}

if (-not (Get-Command helm -ErrorAction SilentlyContinue)) {
    Stop-WithError 'helm was not found. Install Helm 3 (https://helm.sh/docs/intro/install/) and try again.'
}
if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Stop-WithError 'kubectl was not found. Install it (https://kubernetes.io/docs/tasks/tools/) and try again.'
}

$KubeArgs = @()
$KubectlArgs = @()
if ($Context) {
    $KubeArgs = @('--kube-context', $Context)
    $KubectlArgs = @('--context', $Context)
}

# Native commands write progress to stderr; keep that from becoming a terminating error in 5.1.
function Invoke-Helm {
    $ErrorActionPreference = 'Continue'
    helm @KubeArgs @args
}

# Pipeline input is not forwarded to a native command inside a function, so stdin is passed explicitly.
function Invoke-HelmStdin([string]$Stdin) {
    $ErrorActionPreference = 'Continue'
    $Stdin | helm @KubeArgs @args
}

function Invoke-Kubectl {
    $ErrorActionPreference = 'Continue'
    kubectl @KubectlArgs @args
}

$ActiveContext = $Context
if (-not $ActiveContext) {
    $ActiveContext = "$(kubectl config current-context 2>$null)".Trim()
}
if (-not $ActiveContext) { Stop-WithError 'No Kubernetes context is set. Point kubectl at your cluster, or pass -Context.' }
Invoke-Kubectl cluster-info 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Stop-WithError "Cannot reach the cluster for context '$ActiveContext'. Check your kubeconfig and network." }

function Confirm-Cluster {
    Write-Host "Cluster: $ActiveContext   Namespace: $Namespace"
    if ($Yes) { return }
    if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) {
        Stop-WithError 'Not a terminal, so I cannot ask. Re-run with -Yes to confirm the cluster above.'
    }
    $answer = Read-Host -Prompt 'Continue on this cluster? [y/N]'
    if ($answer -notmatch '^(y|yes)$') { Stop-WithError 'Cancelled.' }
}

function Test-Count([string]$Name, [int]$Value) {
    if ($Value -gt $HardMax) { Stop-WithError "$Name $Value is above the limit of $HardMax. Use another cluster or namespace." }
}

function Test-ReleaseExists([string]$Release) {
    Invoke-Helm status $Release --namespace $Namespace 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Read-Secret([string]$Label) {
    if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) { return $null }
    $secure = Read-Host -Prompt $Label -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

# Quotes a value as a YAML double-quoted scalar, so no character in it can change the YAML.
function ConvertTo-YamlQuoted([string]$Value) {
    return '"' + ($Value.Replace('\', '\\').Replace('"', '\"')) + '"'
}

# Every string value goes to Helm as YAML on stdin: the key stays off the command line, and group
# names with commas or spaces need no --set escaping.
# Registration-sensitive settings (group, workspace) are kept together in this block.
function Get-ValuesYaml([string]$Kind) {
    $lines = @(
        "key: $(ConvertTo-YamlQuoted $env:LEVOAI_AUTH_KEY)",
        "orgId: $(ConvertTo-YamlQuoted $script:Org)",
        "levoBaseUrl: $(ConvertTo-YamlQuoted $script:BaseUrl)"
    )
    if ($script:Group) { $lines += "group: $(ConvertTo-YamlQuoted $script:Group)" }
    if ($Kind -eq 'dast') {
        $envLines = @()
        if ($script:Workspace) { $envLines += "  LEVOAI_WORKSPACE_ID: $(ConvertTo-YamlQuoted $script:Workspace)" }
        foreach ($pair in @(@('LEVOAI_CA_CERT', 'ca'), @('CA_CERT_PATH', 'target'), @('CLIENT_CERT_PATH', 'cert'), @('CLIENT_KEY_PATH', 'key'))) {
            if ($script:CertFiles.ContainsKey($pair[1])) { $envLines += "  $($pair[0]): $(ConvertTo-YamlQuoted "$CertMountPath/$($script:CertFiles[$pair[1]])")" }
        }
        if ($envLines.Count -gt 0) { $lines += @('extraEnv:') + $envLines }
        if ($script:CertFiles.Count -gt 0) {
            $lines += @('secretMounts:', "  - name: $CertSecret", "    secretName: $CertSecret", "    mountPath: $CertMountPath", '    defaultMode: 292')
        }
        if ($script:ImageTag) { $lines += @('image:', "  tagOverride: $(ConvertTo-YamlQuoted $script:ImageTag)") }
    } else {
        if ($script:Workspace) { $lines += "workspace: $(ConvertTo-YamlQuoted $script:Workspace)" }
        if ($script:TestrunnerImageTag) { $lines += @('image:', "  tag: $(ConvertTo-YamlQuoted $script:TestrunnerImageTag)") }
    }
    return (($lines -join "`n") + "`n")
}

# One Secret holds every certificate file; the DAST pods mount it read-only. Only DAST workers
# get it: the test runner has no custom-CA setting.
function New-CertSecret {
    $ErrorActionPreference = 'Continue'
    if (($ClientCert -or $ClientKey) -and -not ($ClientCert -and $ClientKey)) { Stop-WithError '-ClientCert and -ClientKey must be given together.' }
    $files = [ordered]@{ ca = $CaCert; target = $TargetCaCert; cert = $ClientCert; key = $ClientKey }
    $fromArgs = @()
    foreach ($kind in $files.Keys) {
        $path = $files[$kind]
        if (-not $path) { continue }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Stop-WithError "Certificate file not found: $path" }
        $name = Split-Path -Leaf $path
        $script:CertFiles[$kind] = $name
        $fromArgs += "--from-file=$name=$((Resolve-Path -LiteralPath $path).Path)"
    }
    if ($script:CertFiles.Count -eq 0 -or $DryRun) { return }
    Write-Host "Storing the certificates in Secret $CertSecret ..."
    Invoke-Kubectl get namespace $Namespace 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Invoke-Kubectl create namespace $Namespace | Out-Null }
    $yaml = Invoke-Kubectl create secret generic $CertSecret --namespace $Namespace @fromArgs --dry-run=client -o yaml | Out-String
    $yaml | & kubectl @KubectlArgs apply --server-side --namespace $Namespace -f - | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-WithError 'Could not store the certificates.' }
}

function Install-Release([string]$Release, [string]$Chart, [int]$Count, [string]$ChartVersion, [string]$Kind, [string[]]$ExtraArgs) {
    $helmArgs = @('upgrade', '--install', $Release, $Chart, '--repo', $ChartRepo, '--namespace', $Namespace, '--create-namespace', '-f', '-')
    if ($ChartVersion) { $helmArgs += @('--version', $ChartVersion) }
    $helmArgs += $ExtraArgs
    if ($DryRun) { $helmArgs += '--dry-run' }
    elseif (-not $NoWait) { $helmArgs += @('--wait', '--timeout', $WaitTimeout) }

    Write-Host "Installing $Release ($Count pod(s)) ..."
    # Helm reads UTF-8 on stdin; Windows PowerShell 5.1 would otherwise send ASCII and mangle a non-ASCII group.
    $previousEncoding = $OutputEncoding
    $OutputEncoding = New-Object Text.UTF8Encoding $false
    try {
        # The rendered manifest contains the key, so Helm's output is discarded.
        $global:LASTEXITCODE = 0
        Invoke-HelmStdin (Get-ValuesYaml $Kind) @helmArgs | Out-Null
        $code = $LASTEXITCODE
    } finally {
        $OutputEncoding = $previousEncoding
    }
    if ($code -ne 0) { Stop-WithError "helm failed for $Release. Run the command again with -DryRun to see the problem." }
    if ($DryRun) { Write-Host "  ${Release}: dry run passed" }
}

function Show-Status {
    Write-Host ''
    Write-Host "Releases in namespace $Namespace (cluster ${ActiveContext}):"
    $found = $false
    foreach ($release in @($ReleaseDast, $ReleaseScheduled, $ReleaseTestrunner, $ReleaseTestrunnerScheduled)) {
        if (Test-ReleaseExists $release) {
            $found = $true
            $json = Invoke-Helm status $release --namespace $Namespace -o json 2>$null | Out-String
            $state = if ($json -match '"status"\s*:\s*"([a-z-]+)"') { $Matches[1] } else { 'unknown' }
            Write-Host "  ${release}: $state"
        }
    }
    if (-not $found) { Write-Host '  (none)'; return }
    Write-Host ''
    Invoke-Kubectl get pods --namespace $Namespace -l 'app in (levoai-shadownet,levoai-shadownet-scheduled,testrunner,testrunner-scheduled)' 2>$null
}

function Invoke-Install {
    $dastCount = if ($Dast -ge 0) { $Dast } else { 1 }
    $scheduledCount = if ($Scheduled -ge 0) { $Scheduled } else { 0 }
    $testrunnerCount = if ($Testrunner -ge 0) { $Testrunner } else { 1 }
    $testrunnerScheduledCount = if ($TestrunnerScheduled -ge 0) { $TestrunnerScheduled } else { 0 }
    Test-Count '-TestrunnerScheduled' $testrunnerScheduledCount
    Test-Count '-Dast' $dastCount
    Test-Count '-Scheduled' $scheduledCount
    Test-Count '-Testrunner' $testrunnerCount

    if (-not $script:Org) {
        if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) {
            Stop-WithError 'Organization ID is not set. Use -Org or set LEVOAI_ORG_ID.'
        }
        $script:Org = Read-Host -Prompt 'Levo organization ID'
        if (-not $script:Org) { Stop-WithError 'Organization ID cannot be empty.' }
    }
    if ($script:Region -and -not $script:BaseUrl) {
        $script:BaseUrl = if ($script:Region -eq 'india') { $IndiaBaseUrl } else { $DefaultBaseUrl }
    }
    if (-not $script:BaseUrl) { $script:BaseUrl = $DefaultBaseUrl }
    if (-not $env:LEVOAI_AUTH_KEY) {
        $key = Read-Secret 'Levo auth key (input hidden)'
        if (-not $key) { Stop-WithError 'LEVOAI_AUTH_KEY is not set. Set it and run again.' }
        $env:LEVOAI_AUTH_KEY = $key
    }
    Confirm-Cluster
    New-CertSecret

    if ($dastCount -gt 0) {
        Install-Release $ReleaseDast $ChartDast $dastCount $DastChartVersion 'dast' @('--set', "replicaCount=$dastCount")
    }
    if ($scheduledCount -gt 0) {
        Install-Release $ReleaseScheduled $ChartDast $scheduledCount $DastChartVersion 'dast' @('--set', "replicaCount=$scheduledCount", '--set', 'scheduled=true')
    }
    if ($testrunnerCount -gt 0) {
        Install-Release $ReleaseTestrunner $ChartTestrunner $testrunnerCount $TestrunnerChartVersion 'runner' @('--set', "replicaCount=$testrunnerCount")
    }

    if ($testrunnerScheduledCount -gt 0) {
        Install-Release $ReleaseTestrunnerScheduled $ChartTestrunner $testrunnerScheduledCount $TestrunnerChartVersion 'runner' @('--set', "replicaCount=$testrunnerScheduledCount", '--set', 'scheduled=true')
    }

    if (-not $DryRun) { Show-Status }
    Write-Host ''
    Write-Host 'Manage it with this script:'
    Write-Host "  .\install-all-helm.ps1 status -Namespace $Namespace"
    Write-Host "  .\install-all-helm.ps1 scale -Dast 4 -Testrunner 2 -Namespace $Namespace"
    Write-Host "  .\install-all-helm.ps1 uninstall -Namespace $Namespace"
}

# Each release owns one Deployment named like the release. kubectl scale leaves every other setting
# alone, so no chart version or key is needed. Re-running install sets the count in Helm again.
function Set-ReleaseScale([string]$Release, [int]$Count) {
    if (-not (Test-ReleaseExists $Release)) {
        if ($Count -ne 0) { Write-Host "  $Release is not installed; run '.\install-all-helm.ps1 install' to add it." }
        return
    }
    Write-Host "Scaling $Release to $Count pod(s) ..."
    Invoke-Kubectl scale "deployment/$Release" --namespace $Namespace "--replicas=$Count" | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Could not scale $Release." }
}

function Invoke-Scale {
    if ($Dast -lt 0 -and $Scheduled -lt 0 -and $Testrunner -lt 0 -and $TestrunnerScheduled -lt 0) { Stop-WithError 'Give at least one of -Dast, -Scheduled, -Testrunner, -TestrunnerScheduled.' }
    if ($CaCert -or $TargetCaCert -or $ClientCert -or $ClientKey) { Stop-WithError 'Certificate options apply to install only. Run install again to change them.' }
    if ($TestrunnerScheduled -ge 0) { Test-Count '-TestrunnerScheduled' $TestrunnerScheduled }
    if ($Dast -ge 0) { Test-Count '-Dast' $Dast }
    if ($Scheduled -ge 0) { Test-Count '-Scheduled' $Scheduled }
    if ($Testrunner -ge 0) { Test-Count '-Testrunner' $Testrunner }
    Confirm-Cluster
    Write-Host 'A pod that is mid-scan is stopped when the count is lowered.'
    if ($Dast -ge 0) { Set-ReleaseScale $ReleaseDast $Dast }
    if ($Scheduled -ge 0) { Set-ReleaseScale $ReleaseScheduled $Scheduled }
    if ($Testrunner -ge 0) { Set-ReleaseScale $ReleaseTestrunner $Testrunner }
    if ($TestrunnerScheduled -ge 0) { Set-ReleaseScale $ReleaseTestrunnerScheduled $TestrunnerScheduled }
    Show-Status
}

function Invoke-Uninstall {
    Confirm-Cluster
    foreach ($release in @($ReleaseDast, $ReleaseScheduled, $ReleaseTestrunner, $ReleaseTestrunnerScheduled)) {
        if (Test-ReleaseExists $release) {
            Write-Host "Removing $release ..."
            Invoke-Helm uninstall $release --namespace $Namespace | Out-Null
        }
    }
    Write-Host "Done. The namespace '$Namespace' was left in place."
}

switch ($Command) {
    'install' { Invoke-Install }
    'scale' { Invoke-Scale }
    'status' { Show-Status }
    'uninstall' { Invoke-Uninstall }
}
