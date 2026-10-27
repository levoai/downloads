<#
.SYNOPSIS
    ShadowNet DAST Runner for Windows - PowerShell Version

.DESCRIPTION
    Installs Levo's ShadowNet DAST scanner from Levo's private PyPI (Google
    Artifact Registry) into a local virtual environment, installs the Playwright
    Chromium browser it drives, and runs scans. Scans run in HEADED mode by
    default so you can watch the browser while the scanner works. Handles:
    - Python 3.12+ detection and validation (uses existing installation)
    - Virtual environment creation/reuse (.shadownet-venv)
    - ShadowNet installation from Google Artifact Registry
    - Playwright Chromium installation
    - Scan / crawl execution via `shadownet scan` / `shadownet crawl`

    Windows port of shadownet-runner.sh, modelled on bitbucket/levo-cli-runner.ps1.

    Secret handling: no secret (Levo auth key, GAR/PyPI credentials) is ever passed
    as a command-line argument. Secrets travel through the environment or temp
    files instead. ShadowNet itself reads LEVOAI_AUTH_KEY / LEVOAI_ORG_ID from the
    environment, so no login shim is needed.

    Dependency-confusion guard: pip does not prefer --index-url over
    --extra-index-url, so the `shadownet` requirement is only ever resolved
    against the private index (`pip download --no-deps`), and the downloaded
    wheel file is then installed with its dependencies coming from public PyPI.

.PARAMETER Command
    The command to execute: install, scan, crawl, login, version, help

.PARAMETER TargetUrl
    Target URL to scan (required unless -ConfigFile is given)

.PARAMETER ConfigFile
    Path to a levo-dast.yml (may supply target.url)

.PARAMETER Headless
    Run the browser headless. Default is headed (browser window visible).

.PARAMETER WithDeps
    Accepted for parity with the bash runner; a no-op on Windows (Playwright's
    Chromium needs no extra OS packages there).

.PARAMETER VenvDir
    Virtual environment directory (default: .shadownet-venv)

.PARAMETER WorkDir
    Working directory (default: current directory)

.PARAMETER ShadownetArgs
    Everything after the named options is passed to shadownet verbatim.

.EXAMPLE
    .\shadownet-runner.ps1 install
    .\shadownet-runner.ps1 scan -TargetUrl https://app.example.com
    .\shadownet-runner.ps1 scan -TargetUrl https://app.example.com -Headless
    .\shadownet-runner.ps1 scan -ConfigFile levo-dast.yml
    .\shadownet-runner.ps1 scan -TargetUrl https://app.example.com --max-pages 50 --fail-on high
    .\shadownet-runner.ps1 crawl -TargetUrl https://app.example.com
    .\shadownet-runner.ps1 login
    .\shadownet-runner.ps1 version

.NOTES
    Version: 1.0.0

    Required Environment Variables (scan only):
        LEVOAI_AUTH_KEY      - Levo Auth key for authentication
        LEVOAI_ORG_ID        - Levo organization ID
        (or an existing session from `shadownet login` / this script's `login`)

    Artifact Registry auth (pick ONE of the following):
        LEVOAI_GAR_SA_KEY_B64 - Base64-encoded Google service account JSON key.
                                Recommended. Uses keyrings.google-artifactregistry-auth,
                                which auto-refreshes OAuth tokens. No gcloud required.
        PYPI_USERNAME + PYPI_PASSWORD
                              - Legacy path. PYPI_USERNAME is typically
                                'oauth2accesstoken' and PYPI_PASSWORD is a short-lived
                                gcloud access token (ya29.*). Token expires in ~60 min.

    Optional Environment Variables:
        SHADOWNET_VERSION   - Specific ShadowNet version (default: latest)
        LEVOAI_BASE_URL     - Custom Levo API URL
        PYPI_INDEX_URL      - Override default GAR index URL
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'scan', 'crawl', 'login', 'version', 'help')]
    [string]$Command = 'help',

    [string]$TargetUrl = '',
    [string]$ConfigFile = '',
    [switch]$Headless,
    [switch]$WithDeps,
    [string]$VenvDir = '.shadownet-venv',
    [string]$WorkDir = $PWD,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ShadownetArgs = @()
)

$ScriptVersion = "1.0.0"
$ScriptName = Split-Path -Leaf $MyInvocation.MyCommand.Path

# Levo's private PyPI repository in Google Artifact Registry (shared with the
# levo CLI; shadownet is a separate package inside it).
$GarRepoName = 'pypi-levo'

$Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Cyan'
}

$Config = @{
    PypiIndexUrl = if ($env:PYPI_INDEX_URL) { $env:PYPI_INDEX_URL } else { "https://us-python.pkg.dev/levoai/$GarRepoName/simple/" }
    VenvPath     = Join-Path $WorkDir $VenvDir
    PipLogFile   = Join-Path $WorkDir 'shadownet-pip-install.log'
}

# Populated by Find-Python
$script:PythonCmd = $null

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'Info'
    )

    $color = switch ($Level) {
        'Error'   { $Colors.Red }
        'Success' { $Colors.Green }
        'Warning' { $Colors.Yellow }
        'Info'    { $Colors.Blue }
        default   { 'White' }
    }

    $prefix = switch ($Level) {
        'Error'   { '[-]' }
        'Success' { '[+]' }
        'Warning' { '[!]' }
        'Info'    { '[*]' }
        default   { '   ' }
    }

    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Write-Banner {
    param([string]$Message)

    $border = '=' * 50
    Write-Host ""
    Write-Host $border -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host $border -ForegroundColor Cyan
    Write-Host ""
}

function Get-UrlHost {
    # Returns the host[:port] portion of a URL, without any user:pass@ prefix.
    param([string]$Url)
    $rest = $Url -replace '^[a-zA-Z][a-zA-Z0-9+.-]*://', ''
    $rest = $rest.Split('/')[0]
    if ($rest.Contains('@')) { $rest = $rest.Substring($rest.LastIndexOf('@') + 1) }
    return $rest
}

# ============================================================================
# Python Detection
# ============================================================================

function Find-Python {
    Write-Log "Detecting Python 3.12+..."

    # Try py launcher first (most reliable on Windows)
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        foreach ($ver in @('3.12', '3.13', '3.14')) {
            try {
                $output = & py "-$ver" --version 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $script:PythonCmd = @('py', "-$ver")
                    Write-Log "Found: $output (via py -$ver)" -Level Success
                    return $true
                }
            } catch {}
        }
    }

    foreach ($cmd in @('python3.12', 'python3.13', 'python3', 'python')) {
        $pythonExe = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($pythonExe) {
            try {
                $output = & $cmd --version 2>&1
                if ($LASTEXITCODE -eq 0 -and "$output" -match 'Python (\d+)\.(\d+)') {
                    $major = [int]$Matches[1]
                    $minor = [int]$Matches[2]
                    if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 12)) {
                        $script:PythonCmd = @($cmd)
                        Write-Log "Found: $output (via $cmd)" -Level Success
                        return $true
                    } else {
                        Write-Log "Found Python $major.$minor but need 3.12+" -Level Warning
                    }
                }
            } catch {}
        }
    }

    Write-Log "Python 3.12 or higher is required but not found." -Level Error
    Write-Host ""
    Write-Host "Please install Python 3.12+ from https://www.python.org/downloads/"
    Write-Host "Or ensure it's in your PATH."
    Write-Host ""
    return $false
}

# ============================================================================
# Virtual Environment Management
# ============================================================================

function Get-VenvBinDir {
    # Windows venvs use Scripts\, POSIX venvs use bin\ (lets the script also run
    # under pwsh on macOS/Linux).
    $scripts = Join-Path $Config.VenvPath 'Scripts'
    if (Test-Path $scripts) { return $scripts }
    return (Join-Path $Config.VenvPath 'bin')
}

function Get-VenvPython {
    $bin = Get-VenvBinDir
    foreach ($name in @('python.exe', 'python')) {
        $p = Join-Path $bin $name
        if (Test-Path $p) { return $p }
    }
    return (Join-Path $bin 'python.exe')
}

function Initialize-Venv {
    $venvPython = Get-VenvPython
    if (Test-Path $venvPython) {
        Write-Log "Virtual environment exists: $($Config.VenvPath)"
        try {
            $venvVersion = & $venvPython --version 2>&1
            if ("$venvVersion" -match 'Python (\d+)\.(\d+)') {
                $major = [int]$Matches[1]
                $minor = [int]$Matches[2]
                if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 12)) {
                    Write-Log "Virtual environment has Python 3.12+" -Level Success
                    return $true
                }
                Write-Log "Virtual environment has Python $major.$minor but need 3.12+, recreating..." -Level Warning
            } else {
                Write-Log "Could not check venv Python version, recreating..." -Level Warning
            }
        } catch {
            Write-Log "Could not check venv Python version, recreating..." -Level Warning
        }
        Remove-Item -Path $Config.VenvPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Log "Creating virtual environment: $($Config.VenvPath)"
    $exe = $script:PythonCmd[0]
    $extra = @()
    if ($script:PythonCmd.Count -gt 1) { $extra = $script:PythonCmd[1..($script:PythonCmd.Count - 1)] }
    & $exe @extra -m venv $Config.VenvPath | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Failed to create virtual environment" -Level Error
        return $false
    }

    Write-Log "Virtual environment created" -Level Success
    return $true
}

function Enter-Venv {
    $venvPython = Get-VenvPython
    if (-not (Test-Path $venvPython)) {
        Write-Log "Virtual environment not found: $venvPython" -Level Error
        return $false
    }

    Write-Log "Activating virtual environment..."
    $env:VIRTUAL_ENV = $Config.VenvPath
    $env:PATH = "$(Get-VenvBinDir)$([System.IO.Path]::PathSeparator)$env:PATH"

    & $venvPython -m pip install --upgrade pip setuptools wheel -q 2>&1 | Out-Null

    Write-Log "Virtual environment activated" -Level Success
    return $true
}

# ============================================================================
# ShadowNet Installation
# ============================================================================

function Install-Shadownet {
    Write-Log "Installing ShadowNet..."

    $python = Get-VenvPython
    $indexUrl = $Config.PypiIndexUrl
    $indexHost = Get-UrlHost $indexUrl
    $saKeyPath = $null
    $pipConfigPath = $null
    $wheelDir = $null
    $usedGarKey = $false
    $previousGac = [Environment]::GetEnvironmentVariable('GOOGLE_APPLICATION_CREDENTIALS', 'Process')
    $previousPipConfig = [Environment]::GetEnvironmentVariable('PIP_CONFIG_FILE', 'Process')

    try {
        # Auth mode priority:
        #   1. LEVOAI_GAR_SA_KEY_B64 -> keyring helper (auto-refresh, no gcloud).
        #   2. PYPI_USERNAME/PYPI_PASSWORD -> credentials in a private pip.ini (no argv leak).
        if ($env:LEVOAI_GAR_SA_KEY_B64) {
            $usedGarKey = $true
            $saKeyPath = Join-Path ([System.IO.Path]::GetTempPath()) ("gar-sa-key-{0}.json" -f ([System.Guid]::NewGuid().ToString('N')))
            try {
                $keyBytes = [Convert]::FromBase64String($env:LEVOAI_GAR_SA_KEY_B64.Trim())
                [System.IO.File]::WriteAllBytes($saKeyPath, $keyBytes)
            } catch {
                Write-Log "Failed to decode LEVOAI_GAR_SA_KEY_B64: $_" -Level Error
                return $false
            }
            [Environment]::SetEnvironmentVariable('GOOGLE_APPLICATION_CREDENTIALS', $saKeyPath, 'Process')

            Write-Log "Installing keyrings.google-artifactregistry-auth..."
            $keyringOutput = & $python -m pip install --no-cache-dir keyrings.google-artifactregistry-auth 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Log "Failed to install keyring helper" -Level Error
                Write-Host $keyringOutput -ForegroundColor Red
                return $false
            }
            Write-Log "Using GAR service account key via keyring helper" -Level Success
        } elseif ($env:PYPI_USERNAME) {
            if (-not $env:PYPI_PASSWORD) {
                Write-Log "PYPI_PASSWORD is required when PYPI_USERNAME is set" -Level Error
                return $false
            }
            # Do NOT embed the token in --index-url on the command line (visible to
            # other processes). Write it to a private pip config referenced via
            # PIP_CONFIG_FILE. No public extra index: the shadownet requirement must
            # only ever resolve against the private index.
            $pipConfigPath = Join-Path ([System.IO.Path]::GetTempPath()) ("shadownet-pip-{0}.ini" -f ([System.Guid]::NewGuid().ToString('N')))
            $scheme = $indexUrl.Split('://')[0]
            $rest = $indexUrl.Substring($indexUrl.IndexOf('://') + 3)
            $authedUrl = "{0}://{1}:{2}@{3}" -f $scheme, $env:PYPI_USERNAME, $env:PYPI_PASSWORD, $rest
            $ini = "[global]`r`nindex-url = $authedUrl`r`n"
            [System.IO.File]::WriteAllText($pipConfigPath, $ini)
            [Environment]::SetEnvironmentVariable('PIP_CONFIG_FILE', $pipConfigPath, 'Process')
            Write-Log "Using authenticated repository (credentials in a private pip config, not argv)"
        } else {
            Write-Log "No Artifact Registry credentials configured." -Level Error
            Write-Log "Set ONE of the following before running install/scan:" -Level Error
            Write-Log '  $env:LEVOAI_GAR_SA_KEY_B64 = "<base64 SA key>"   (recommended)' -Level Error
            Write-Log '  -- or --' -Level Error
            Write-Log '  $env:PYPI_USERNAME = "oauth2accesstoken"; $env:PYPI_PASSWORD = "<ya29 token>"' -Level Error
            return $false
        }

        $packageSpec = 'shadownet'
        if ($env:SHADOWNET_VERSION) {
            $packageSpec = "shadownet==$($env:SHADOWNET_VERSION)"
            Write-Log "Installing version: $($env:SHADOWNET_VERSION)"
        } else {
            Write-Log "Installing latest version"
        }

        # Step 1: fetch just the shadownet wheel from the private index.
        $wheelDir = Join-Path ([System.IO.Path]::GetTempPath()) ("shadownet-wheel-{0}" -f ([System.Guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $wheelDir -Force | Out-Null

        Write-Log "Fetching $packageSpec from the private index (this can take a moment)..."
        $downloadArgs = @('-m', 'pip', 'download', '--no-cache-dir', $packageSpec, '--no-deps', '-d', $wheelDir, '--trusted-host', $indexHost)
        if ($usedGarKey) { $downloadArgs += @('--index-url', $indexUrl) }
        $output = & $python @downloadArgs 2>&1
        $output | Out-File -FilePath $Config.PipLogFile -Encoding UTF8
        if ($LASTEXITCODE -ne 0) {
            Write-Log "pip download failed. See $($Config.PipLogFile) for details" -Level Error
            Write-Host $output -ForegroundColor Red
            return $false
        }

        $wheel = Get-ChildItem -Path $wheelDir -Filter 'shadownet-*.whl' | Select-Object -First 1
        if (-not $wheel) {
            Write-Log "No shadownet wheel was downloaded to $wheelDir" -Level Error
            return $false
        }

        # Step 2: install that explicit file; dependencies resolve from public PyPI.
        # Drop the private pip config first so no private credentials are involved.
        [Environment]::SetEnvironmentVariable('PIP_CONFIG_FILE', $previousPipConfig, 'Process')
        # Two passes: force-reinstall the wheel itself (a re-published dev build
        # keeps its version number, so a plain install would say "already
        # satisfied"), then a normal install to pull in any new dependencies.
        Write-Log "Installing $($wheel.Name) and its dependencies (this can take a few minutes)..."
        $output = & $python -m pip install --no-cache-dir --force-reinstall --no-deps $wheel.FullName 2>&1
        $output | Out-File -FilePath $Config.PipLogFile -Encoding UTF8 -Append
        if ($LASTEXITCODE -eq 0) {
            $output = & $python -m pip install --no-cache-dir $wheel.FullName 2>&1
            $output | Out-File -FilePath $Config.PipLogFile -Encoding UTF8 -Append
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Log "pip install failed. See $($Config.PipLogFile) for details" -Level Error
            Write-Host $output -ForegroundColor Red
            return $false
        }

        Write-Log "ShadowNet installed" -Level Success
        return $true
    } finally {
        [Environment]::SetEnvironmentVariable('GOOGLE_APPLICATION_CREDENTIALS', $previousGac, 'Process')
        [Environment]::SetEnvironmentVariable('PIP_CONFIG_FILE', $previousPipConfig, 'Process')
        foreach ($p in @($saKeyPath, $pipConfigPath)) {
            if ($p -and (Test-Path -LiteralPath $p)) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
        }
        if ($wheelDir -and (Test-Path -LiteralPath $wheelDir)) {
            Remove-Item -LiteralPath $wheelDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Install-Browser {
    # ShadowNet drives Chromium through Playwright. The browser is not bundled in
    # the wheel, so fetch it into Playwright's per-user cache (idempotent).
    Write-Log "Installing Playwright Chromium browser..."
    $python = Get-VenvPython
    $pwArgs = @('-m', 'playwright', 'install', 'chromium')
    if ($WithDeps -and -not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
        $pwArgs = @('-m', 'playwright', 'install', '--with-deps', 'chromium')
    }
    & $python @pwArgs | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Playwright browser installation failed" -Level Error
        return $false
    }
    Write-Log "Chromium installed" -Level Success
    return $true
}

function Test-ShadownetInstallation {
    Write-Log "Verifying installation..."
    $python = Get-VenvPython
    & $python -m pip show shadownet 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Log "shadownet package not found" -Level Error
        return $false
    }
    Write-Log "Installation verified" -Level Success
    return $true
}

function Test-ShadownetInstalled {
    $python = Get-VenvPython
    & $python -m pip show shadownet 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Get-ShadownetCommand {
    # Returns @(exe, args...) for the shadownet entry point. Callers must wrap the
    # result in @(): PowerShell unrolls a single-element array on return.
    $bin = Get-VenvBinDir
    foreach ($name in @('shadownet.exe', 'shadownet')) {
        $p = Join-Path $bin $name
        if (Test-Path $p) { return @($p) }
    }
    return @((Get-VenvPython), '-m', 'shadownet.cli.main')
}

function Invoke-Shadownet {
    param([string[]]$Arguments)
    $cmd = @(Get-ShadownetCommand)
    $exe = $cmd[0]
    $pre = @()
    if ($cmd.Count -gt 1) { $pre = $cmd[1..($cmd.Count - 1)] }
    $global:LASTEXITCODE = 0
    # Out-Host streams shadownet's live progress UI to the console instead of
    # capturing it into this function's return value.
    & $exe @pre @Arguments | Out-Host
    if ($null -eq $LASTEXITCODE) { return 1 }
    return $LASTEXITCODE
}

function Ensure-Installed {
    if (-not (Find-Python)) { return $false }
    if (-not (Initialize-Venv)) { return $false }
    if (-not (Enter-Venv)) { return $false }
    if (Test-ShadownetInstalled) {
        Write-Log "ShadowNet already installed"
    } else {
        Write-Log "ShadowNet not found, installing..."
        if (-not (Install-Shadownet)) { return $false }
        if (-not (Test-ShadownetInstallation)) { return $false }
        if (-not (Install-Browser)) { return $false }
    }
    return $true
}

# ============================================================================
# Scan / crawl
# ============================================================================

function Test-LevoCredentials {
    # `shadownet scan` needs a Levo session: either LEVOAI_AUTH_KEY + LEVOAI_ORG_ID in
    # the environment (it logs in on its own), or a saved session from `shadownet login`.
    if ($env:LEVOAI_AUTH_KEY -and $env:LEVOAI_ORG_ID) { return $true }
    $userHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $env:HOME }
    $session = Join-Path $userHome '.config/configstore/levo.json'
    if (Test-Path $session) {
        Write-Log "Using saved Levo session ($session)"
        return $true
    }
    Write-Log "Levo credentials are required for a scan." -Level Error
    Write-Log "Set LEVOAI_AUTH_KEY and LEVOAI_ORG_ID in the environment, or run: .\$ScriptName login" -Level Error
    return $false
}

function Test-TargetRequirements {
    if (-not $TargetUrl -and -not $ConfigFile) {
        Write-Log "Either -TargetUrl or -ConfigFile <levo-dast.yml> is required" -Level Error
        return $false
    }
    if ($TargetUrl -and $TargetUrl -notmatch '^https?://') {
        Write-Log "-TargetUrl must start with http:// or https://" -Level Error
        return $false
    }
    if ($ConfigFile -and -not (Test-Path $ConfigFile)) {
        Write-Log "-ConfigFile not found: $ConfigFile" -Level Error
        return $false
    }
    return $true
}

function Get-ShadownetArgs {
    param([string]$Subcommand)
    $snArgs = @($Subcommand)
    if ($TargetUrl) { $snArgs += $TargetUrl }
    if ($ConfigFile) { $snArgs += @('--config', $ConfigFile) }
    if ($Subcommand -eq 'crawl') {
        # The AI crawler needs an LLM key; the standard crawler is what headed
        # customers want to watch.
        $snArgs += @('--crawler-type', 'standard')
    }
    if ($Headless) { $snArgs += '--headless' } else { $snArgs += '--no-headless' }
    if ($ShadownetArgs.Count -gt 0) { $snArgs += $ShadownetArgs }
    return $snArgs
}

function Show-RunConfig {
    $mode = if ($Headless) { 'headless' } else { 'headed (browser window visible)' }
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Cyan
    if ($TargetUrl)  { Write-Host "  Target URL:   $TargetUrl" }
    if ($ConfigFile) { Write-Host "  Config file:  $ConfigFile" }
    Write-Host "  Browser:      $mode"
    Write-Host "  Venv:         $($Config.VenvPath)"
    if ($ShadownetArgs.Count -gt 0) { Write-Host "  Extra args:   $($ShadownetArgs -join ' ')" }
    Write-Host ""
}

function Invoke-Run {
    param([string]$Subcommand)
    $snArgs = Get-ShadownetArgs $Subcommand
    Write-Log "Running: shadownet $($snArgs -join ' ')"
    Write-Host ""
    # Foreground, inheriting the console: shadownet renders a live progress UI
    # and, in headed mode, opens the browser window.
    return (Invoke-Shadownet -Arguments $snArgs)
}

# ============================================================================
# Commands
# ============================================================================

function Invoke-Help {
    Write-Banner "ShadowNet DAST Runner v$ScriptVersion"
    Write-Host @"
Usage: .\$ScriptName <command> [options] [<extra shadownet args>]

Commands:
  install   Install or upgrade ShadowNet + Chromium in a virtual environment
  scan      Run a DAST security scan (auto-installs if needed)
  crawl     Discovery-only crawl, no security testing (auto-installs if needed)
  login     Log in to the Levo platform interactively (saves a session)
  version   Show installed ShadowNet version
  help      Show this help message

Options:
  -TargetUrl <url>       Target URL to scan (required unless -ConfigFile is given)
  -ConfigFile <path>     Path to a levo-dast.yml (may supply target.url)
  -Headless              Run the browser headless (default: headed, window visible)
  -VenvDir <string>      Virtual environment directory (default: .shadownet-venv)
  -WorkDir <string>      Working directory (default: current directory)
  Any remaining arguments are passed to shadownet verbatim.

Examples:
  .\$ScriptName install
  .\$ScriptName scan -TargetUrl https://app.example.com
  .\$ScriptName scan -TargetUrl https://app.example.com -Headless
  .\$ScriptName scan -ConfigFile levo-dast.yml
  .\$ScriptName scan -TargetUrl https://app.example.com --max-pages 50 --fail-on high
  .\$ScriptName crawl -TargetUrl https://app.example.com
  .\$ScriptName login

Required environment variables (scan):
  LEVOAI_AUTH_KEY      Levo Auth Key      (or run '.\$ScriptName login' once)
  LEVOAI_ORG_ID        Levo organization ID

Artifact Registry auth (pick ONE):
  LEVOAI_GAR_SA_KEY_B64            Base64 Google SA JSON key (recommended)
  PYPI_USERNAME + PYPI_PASSWORD    Legacy ya29.* token path

Optional environment variables:
  SHADOWNET_VERSION    Specific ShadowNet version (default: latest)
  LEVOAI_BASE_URL      Custom Levo API URL
  PYPI_INDEX_URL       Override default GAR index URL
"@
    return 0
}

function Invoke-Install {
    Write-Banner "Installing ShadowNet"
    if (-not (Find-Python)) { return 1 }
    if (-not (Initialize-Venv)) { return 1 }
    if (-not (Enter-Venv)) { return 1 }
    if (-not (Install-Shadownet)) { return 1 }
    if (-not (Test-ShadownetInstallation)) { return 1 }
    if (-not (Install-Browser)) { return 1 }
    Write-Banner "ShadowNet installed successfully!"
    Write-Log "Next: set LEVOAI_AUTH_KEY / LEVOAI_ORG_ID, then run: .\$ScriptName scan -TargetUrl <url>"
    return 0
}

function Invoke-Version {
    if (-not (Find-Python)) { return 1 }
    if (-not (Initialize-Venv)) { return 1 }
    if (-not (Enter-Venv)) { return 1 }

    Write-Host ""
    Write-Host "ShadowNet Version:" -ForegroundColor Cyan

    $versionText = ''
    try {
        $cmd = @(Get-ShadownetCommand)
        $exe = $cmd[0]
        $pre = @()
        if ($cmd.Count -gt 1) { $pre = $cmd[1..($cmd.Count - 1)] }
        $versionText = (& $exe @pre --version 2>$null | Select-Object -First 1)
    } catch {}

    if (-not $versionText) {
        $show = & (Get-VenvPython) -m pip show shadownet 2>$null
        $line = $show | Where-Object { $_ -match '^Version:\s*(.+)$' } | Select-Object -First 1
        if ($line -match '^Version:\s*(.+)$') { $versionText = $Matches[1] }
    }

    if ($versionText) {
        Write-Host "  $versionText"
        return 0
    }
    Write-Log "Could not determine ShadowNet version" -Level Error
    return 1
}

function Invoke-Login {
    Write-Banner "Levo Login"
    if (-not (Ensure-Installed)) { return 1 }
    return (Invoke-Shadownet -Arguments @('login'))
}

function Invoke-Scan {
    Write-Banner "ShadowNet DAST Scan"
    if (-not (Test-TargetRequirements)) { return 1 }
    if (-not (Test-LevoCredentials)) { return 1 }
    if (-not (Ensure-Installed)) { return 1 }
    Show-RunConfig
    $rc = Invoke-Run 'scan'
    if ($rc -eq 0) { Write-Log "Scan completed" -Level Success } else { Write-Log "Scan exited with code $rc" -Level Warning }
    return $rc
}

function Invoke-Crawl {
    Write-Banner "ShadowNet Crawl (discovery only)"
    if (-not (Test-TargetRequirements)) { return 1 }
    if (-not (Ensure-Installed)) { return 1 }
    Show-RunConfig
    $rc = Invoke-Run 'crawl'
    if ($rc -eq 0) { Write-Log "Crawl completed" -Level Success } else { Write-Log "Crawl exited with code $rc" -Level Warning }
    return $rc
}

# ============================================================================
# Main Entry Point
# ============================================================================

if (-not (Test-Path $WorkDir)) {
    try { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
    catch { Write-Log "-WorkDir '$WorkDir' does not exist and could not be created" -Level Error; exit 2 }
}

$exitCode = switch ($Command) {
    'help'    { Invoke-Help }
    'install' { Invoke-Install }
    'version' { Invoke-Version }
    'login'   { Invoke-Login }
    'scan'    { Invoke-Scan }
    'crawl'   { Invoke-Crawl }
    default   { Invoke-Help }
}

exit $exitCode
