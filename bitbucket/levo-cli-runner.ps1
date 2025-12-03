<#
.SYNOPSIS
    Levo CLI Runner for Windows - PowerShell Version

.DESCRIPTION
    This script handles:
    - Python 3.12+ detection and validation (uses existing installation)
    - Virtual environment creation/reuse
    - Levo CLI installation from Google Artifact Registry
    - Security test execution

.PARAMETER Command
    The command to execute: install, test, audit, version, help

.EXAMPLE
    .\levo-cli-runner.ps1 install
    .\levo-cli-runner.ps1 test
    .\levo-cli-runner.ps1 audit
    .\levo-cli-runner.ps1 -Command test -Environment production

.NOTES
    Version: 1.0.0
    
    Required Environment Variables:
        LEVOAI_AUTH_KEY      - Levo Auth key for authentication
        LEVOAI_ORG_ID       - Levo organization ID
        PYPI_USERNAME     - PyPI username (oauth2accesstoken for GAR)
        PYPI_PASSWORD     - PyPI password (gcloud access token)
    
    Optional Environment Variables:
        LEVOAI_CLI_VERSION  - Specific CLI version (default: latest)
        LEVOAI_BASE_URL     - Custom Levo API URL
        APP_NAME          - Application name
        ENVIRONMENT       - Target environment (default: staging)
        TEST_METHODS      - HTTP methods (default: GET,POST)
        FAIL_SCOPE        - new|any|none (default: new)
        FAIL_SEVERITY     - critical|high|medium|low|none (default: high)
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'test', 'audit', 'version', 'help')]
    [string]$Command = 'help',
    
    [string]$AppName = $env:APP_NAME,
    [string]$Environment = $env:ENVIRONMENT,
    [string]$TestMethods = $env:TEST_METHODS,
    [string]$FailScope = $env:FAIL_SCOPE,
    [string]$FailSeverity = $env:FAIL_SEVERITY,
    [string]$VenvDir = '.levo-venv',
    [string]$WorkDir = $PWD
)

# Script version
$ScriptVersion = "1.0.0"

# Colors
$Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Cyan'
}

# Default configuration
$Config = @{
    PypiIndexUrl = if ($env:PYPI_INDEX_URL) { $env:PYPI_INDEX_URL } else { 'https://us-python.pkg.dev/levoai/pypi-levo/simple/' }
    MinPythonVersion = [version]'3.12'
    VenvPath = Join-Path $WorkDir $VenvDir
    LogFile = Join-Path $WorkDir 'levo-test-output.log'
    PipLogFile = Join-Path $WorkDir 'pip-install.log'
}

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

# ============================================================================
# Python Detection
# ============================================================================

function Find-Python {
    <#
    .SYNOPSIS
        Finds Python 3.12+ on the system
    #>
    
    Write-Log "Detecting Python 3.12+..."
    
    # Try py launcher first (most reliable on Windows)
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        # Try specific versions
        foreach ($ver in @('3.12', '3.13', '3.14')) {
            try {
                $output = & py "-$ver" --version 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $script:PythonCmd = "py -$ver"
                    $script:PythonVersion = $output
                    Write-Log "Found: $output (via py -$ver)" -Level Success
                    return $true
                }
            } catch {}
        }
    }
    
    # Try pythonX.XX variants
    foreach ($cmd in @('python3.12', 'python3.13', 'python')) {
        $pythonExe = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($pythonExe) {
            try {
                $output = & $cmd --version 2>&1
                if ($LASTEXITCODE -eq 0 -and $output -match 'Python (\d+)\.(\d+)') {
                    $major = [int]$Matches[1]
                    $minor = [int]$Matches[2]
                    
                    if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 12)) {
                        $script:PythonCmd = $cmd
                        $script:PythonVersion = $output
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

function Initialize-Venv {
    <#
    .SYNOPSIS
        Creates virtual environment if it doesn't exist or has wrong Python version
    #>
    
    if (Test-Path (Join-Path $Config.VenvPath 'Scripts\activate.bat')) {
        Write-Log "Virtual environment exists: $($Config.VenvPath)"
        
        # Check if venv has correct Python version
        $venvPython = Join-Path $Config.VenvPath 'Scripts\python.exe'
        if (Test-Path $venvPython) {
            try {
                $venvVersion = & $venvPython --version 2>&1
                if ($venvVersion -match 'Python (\d+)\.(\d+)') {
                    $major = [int]$Matches[1]
                    $minor = [int]$Matches[2]
                    
                    if ($major -eq 3 -and $minor -ge 12) {
                        Write-Log "Virtual environment has Python 3.12+" -Level Success
                        return $true
                    } else {
                        Write-Log "Virtual environment has Python $major.$minor but need 3.12+, recreating..." -Level Warning
                        Remove-Item -Path $Config.VenvPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch {
                Write-Log "Could not check venv Python version, recreating..." -Level Warning
                Remove-Item -Path $Config.VenvPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        } else {
            Write-Log "Virtual environment exists but python.exe not found, recreating..." -Level Warning
            Remove-Item -Path $Config.VenvPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Log "Creating virtual environment: $($Config.VenvPath)"
    
    $result = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $PythonCmd -m venv `"$($Config.VenvPath)`"" -Wait -NoNewWindow -PassThru
    
    if ($result.ExitCode -ne 0) {
        Write-Log "Failed to create virtual environment" -Level Error
        return $false
    }
    
    Write-Log "Virtual environment created" -Level Success
    return $true
}

function Enter-Venv {
    <#
    .SYNOPSIS
        Activates the virtual environment for the current session
    #>
    
    $activateScript = Join-Path $Config.VenvPath 'Scripts\Activate.ps1'
    
    if (-not (Test-Path $activateScript)) {
        Write-Log "Virtual environment not found: $activateScript" -Level Error
        return $false
    }
    
    Write-Log "Activating virtual environment..."
    
    # Add venv to PATH
    $env:VIRTUAL_ENV = $Config.VenvPath
    $env:PATH = "$(Join-Path $Config.VenvPath 'Scripts');$env:PATH"
    
    # Upgrade pip silently
    & python -m pip install --upgrade pip setuptools wheel -q 2>&1 | Out-Null
    
    Write-Log "Virtual environment activated" -Level Success
    return $true
}

# ============================================================================
# Levo CLI Installation
# ============================================================================

function Install-LevoCli {
    <#
    .SYNOPSIS
        Installs Levo CLI from the configured repository
    #>
    
    Write-Log "Installing Levo CLI..."
    
    # Build index URL
    $indexUrl = $Config.PypiIndexUrl
    
    if ($env:PYPI_USERNAME) {
        if (-not $env:PYPI_PASSWORD) {
            Write-Log "PYPI_PASSWORD is required when PYPI_USERNAME is set" -Level Error
            return $false
        }
        
        # Construct authenticated URL
        $indexUrl = "https://$($env:PYPI_USERNAME):$($env:PYPI_PASSWORD)@us-python.pkg.dev/levoai/pypi-levo/simple/"
        Write-Log "Using authenticated repository"
    } else {
        Write-Log "Using repository: $indexUrl"
    }
    
    # Build package spec
    $packageSpec = 'levo'
    if ($env:LEVOAI_CLI_VERSION) {
        $packageSpec = "levo==$($env:LEVOAI_CLI_VERSION)"
        Write-Log "Installing version: $($env:LEVOAI_CLI_VERSION)"
    } else {
        Write-Log "Installing latest version"
    }
    
    # Run pip install
    Write-Log "Running pip install..."
    
    $pipArgs = @(
        '-m', 'pip', 'install', '--no-cache-dir',
        $packageSpec,
        '--index-url', $indexUrl,
        '--extra-index-url', 'https://pypi.org/simple/',
        '--trusted-host', 'us-python.pkg.dev'
    )
    
    $output = & python @pipArgs 2>&1
    $output | Out-File -FilePath $Config.PipLogFile -Encoding UTF8
    
    if ($LASTEXITCODE -ne 0) {
        Write-Log "pip install failed. See $($Config.PipLogFile) for details" -Level Error
        Write-Host $output -ForegroundColor Red
        return $false
    }
    
    # Reinstall packages with C extensions to fix Windows compilation issues
    Write-Log "Reinstalling packages with C extensions to ensure proper compilation..."
    
    # Reinstall packages that may have C extension compilation issues on Windows
    # Note: cryptography version must respect levo's constraints (<43.0.0,>=42.0.0)
    $cExtensionPackages = @(
        'grpcio',
        'orjson',
        'cryptography>=42.0.0,<43.0.0',  # Respect levo's version constraint
        'protobuf'
    )
    foreach ($pkg in $cExtensionPackages) {
        Write-Log "Reinstalling $pkg..."
        $pkgOutput = & python -m pip install --force-reinstall --no-cache-dir $pkg --extra-index-url 'https://pypi.org/simple/' 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Warning: $pkg reinstall had issues, but continuing..." -Level Warning
        }
    }
    
    Write-Log "Levo CLI installed" -Level Success
    return $true
}

function Test-LevoInstallation {
    <#
    .SYNOPSIS
        Verifies Levo CLI is properly installed
    #>
    
    Write-Log "Verifying installation..."
    
    $pipShow = & python -m pip show levo 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "levo package not found" -Level Error
        return $false
    }
    
    Write-Log "Installation verified" -Level Success
    return $true
}

function Get-LevoExecutable {
    <#
    .SYNOPSIS
        Returns the path to the Levo executable
    #>
    
    $exePath = Join-Path $Config.VenvPath 'Scripts\levo.exe'
    if (Test-Path $exePath) {
        return $exePath
    }
    
    $batPath = Join-Path $Config.VenvPath 'Scripts\levo.bat'
    if (Test-Path $batPath) {
        return $batPath
    }
    
    # Fall back to module
    return 'python -m levo'
}

# ============================================================================
# Security Testing
# ============================================================================

function Test-Requirements {
    <#
    .SYNOPSIS
        Validates required environment variables
    #>
    
    $failed = $false
    
    if (-not $env:LEVOAI_AUTH_KEY) {
        Write-Log "LEVOAI_AUTH_KEY is required but not set" -Level Error
        $failed = $true
    }
    
    if (-not $env:LEVOAI_ORG_ID) {
        Write-Log "LEVOAI_ORG_ID is required but not set" -Level Error
        $failed = $true
    }
    
    if ($failed) {
        Write-Host ""
        Write-Host "Please set the required environment variables:"
        Write-Host '  $env:LEVOAI_AUTH_KEY = "your-auth-key"'
        Write-Host '  $env:LEVOAI_ORG_ID = "your-org-id"'
        Write-Host ""
    }
    
    return -not $failed
}

function Set-TestDefaults {
    <#
    .SYNOPSIS
        Sets default values for test parameters
    #>
    
    # App name detection
    if (-not $script:AppName) {
        $script:AppName = $env:APP_NAME
    }
    if (-not $script:AppName -and $env:BITBUCKET_REPO_SLUG) {
        $script:AppName = $env:BITBUCKET_REPO_SLUG
    }
    if (-not $script:AppName -and $env:GITHUB_REPOSITORY) {
        $script:AppName = Split-Path $env:GITHUB_REPOSITORY -Leaf
    }
    if (-not $script:AppName) {
        try {
            $gitRoot = & git rev-parse --show-toplevel 2>$null
            if ($gitRoot) {
                $script:AppName = Split-Path $gitRoot -Leaf
            }
        } catch {}
    }
    if (-not $script:AppName) {
        $script:AppName = 'default-app'
    }
    
    # Other defaults
    if (-not $script:Environment) { $script:Environment = 'staging' }
    if (-not $script:TestMethods) { $script:TestMethods = 'GET,POST' }
    if (-not $script:FailScope) { $script:FailScope = 'new' }
    if (-not $script:FailSeverity) { $script:FailSeverity = 'high' }
}

function Show-TestConfig {
    <#
    .SYNOPSIS
        Displays test configuration
    #>
    
    Write-Host ""
    Write-Host "Test Configuration:" -ForegroundColor Cyan
    Write-Host "  App Name:         $script:AppName"
    Write-Host "  Environment:      $script:Environment"
    Write-Host "  HTTP Methods:     $script:TestMethods"
    Write-Host "  Fail Scope:       $script:FailScope"
    Write-Host "  Fail Severity:    $script:FailSeverity"
    $apiUrl = if ($env:LEVOAI_BASE_URL) { $env:LEVOAI_BASE_URL } else { 'https://api.levo.ai' }
    Write-Host "  API URL:          $apiUrl"
    Write-Host ""
}

function Invoke-SecurityTest {
    <#
    .SYNOPSIS
        Executes the security test
    #>
    
    Write-Log "Running security tests..."
    Write-Log "Output will be saved to: $($Config.LogFile)"
    
    # Ensure LEVOAI_BASE_URL is available
    if (-not $env:LEVOAI_BASE_URL) {
        $env:LEVOAI_BASE_URL = 'https://api.levo.ai'
    }
    
    $levoExe = Get-LevoExecutable
    
    # Build command arguments as a flat array
    $processArgs = @(
        'remote-test-run'
        '--key'
        $env:LEVOAI_AUTH_KEY
        '--organization'
        $env:LEVOAI_ORG_ID
        '--app-name'
        $script:AppName
        '--env'
        $script:Environment
        '--methods'
        $script:TestMethods
        '--fail-scope'
        $script:FailScope
        '--fail-severity'
        $script:FailSeverity
        '--verbosity'
        'INFO'
    )
    
    # Execute and capture output
    # Use call operator with array splatting (@) to prevent wildcard expansion
    # Use New-TemporaryFile to guarantee unique filenames (avoids collision risk with Get-Random)
    $tempOutFile = New-TemporaryFile
    $tempOut = $tempOutFile.FullName
    $tempOutFile.Delete()
    
    $tempErrFile = New-TemporaryFile
    $tempErr = $tempErrFile.FullName
    $tempErrFile.Delete()
    
    try {
        if ($levoExe -eq 'python -m levo') {
            $process = Start-Process -FilePath 'python' `
                -ArgumentList @('-m', 'levo') + $processArgs `
                -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput $tempOut `
                -RedirectStandardError $tempErr
        } else {
            $process = Start-Process -FilePath $levoExe `
                -ArgumentList $processArgs `
                -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput $tempOut `
                -RedirectStandardError $tempErr
        }
        
        $output = Get-Content $tempOut -Raw -ErrorAction SilentlyContinue
        $errorOutput = Get-Content $tempErr -Raw -ErrorAction SilentlyContinue
        # Explicitly handle all cases: both outputs, only error, or only standard output
        $output = if ($output -and $errorOutput) { "$output`n$errorOutput" } elseif ($errorOutput) { $errorOutput } else { $output }
        $exitCode = $process.ExitCode
    } finally {
        if (Test-Path $tempOut) { Remove-Item $tempOut -ErrorAction SilentlyContinue }
        if (Test-Path $tempErr) { Remove-Item $tempErr -ErrorAction SilentlyContinue }
    }
    
    # Save output
    $output | Out-File -FilePath $Config.LogFile -Encoding UTF8
    
    # Display output
    Write-Host ""
    Write-Host ('=' * 40) -ForegroundColor Cyan
    Write-Host "Test Output:" -ForegroundColor Cyan
    Write-Host ('=' * 40) -ForegroundColor Cyan
    Write-Host $output
    Write-Host ('=' * 40) -ForegroundColor Cyan
    Write-Host ""
    
    return $exitCode
}

# ============================================================================
# Command Handlers
# ============================================================================

function Invoke-Help {
    Write-Banner "Levo CLI Runner v$ScriptVersion"
    
    Write-Host "Usage: $([System.IO.Path]::GetFileName($PSCommandPath)) <command>"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  install   Install Levo CLI into virtual environment"
    Write-Host "  test      Run security tests (auto-installs if needed)"
    Write-Host "  audit     Run comprehensive audit (never fails build)"
    Write-Host "  version   Show installed Levo CLI version"
    Write-Host "  help      Show this help message"
    Write-Host ""
    Write-Host "Required Environment Variables:"
    Write-Host '  $env:LEVOAI_AUTH_KEY      Levo Auth Key'
    Write-Host '  $env:LEVOAI_ORG_ID       Levo organization ID'
    Write-Host '  $env:PYPI_USERNAME     PyPI username (oauth2accesstoken for GAR)'
    Write-Host '  $env:PYPI_PASSWORD     PyPI password (gcloud access token)'
    Write-Host ""
    
    return 0
}

function Invoke-Install {
    Write-Banner "Installing Levo CLI"
    
    if (-not (Find-Python)) { return 1 }
    if (-not (Initialize-Venv)) { return 1 }
    if (-not (Enter-Venv)) { return 1 }
    if (-not (Install-LevoCli)) { return 1 }
    if (-not (Test-LevoInstallation)) { return 1 }
    
    Write-Banner "Levo CLI installed successfully!"
    return 0
}

function Invoke-Version {
    if (-not (Find-Python)) { return 1 }
    if (-not (Initialize-Venv)) { return 1 }
    if (-not (Enter-Venv)) { return 1 }
    
    Write-Host ""
    Write-Host "Levo CLI Version:" -ForegroundColor Cyan
    
    $levoExe = Get-LevoExecutable
    if ($levoExe -eq 'python -m levo') {
        & python -m levo --version
    } else {
        & $levoExe --version
    }
    
    return $LASTEXITCODE
}

function Invoke-Test {
    Write-Banner "Levo Security Test"
    
    if (-not (Test-Requirements)) { return 1 }
    
    # Ensure installed
    if (-not (Find-Python)) { return 1 }
    if (-not (Initialize-Venv)) { return 1 }
    if (-not (Enter-Venv)) { return 1 }
    
    # Check if levo is installed
    $installed = & python -m pip show levo 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Levo CLI not found, installing..."
        if (-not (Install-LevoCli)) { return 1 }
        if (-not (Test-LevoInstallation)) { return 1 }
    } else {
        Write-Log "Levo CLI already installed"
    }
    
    Set-TestDefaults
    Show-TestConfig
    
    $exitCode = Invoke-SecurityTest
    
    Write-Host ""
    if ($exitCode -eq 0) {
        Write-Banner "Security tests PASSED"
    } else {
        Write-Host ('=' * 50) -ForegroundColor Red
        Write-Host "  Security tests FAILED (exit code: $exitCode)" -ForegroundColor Red
        Write-Host ('=' * 50) -ForegroundColor Red
    }
    
    return $exitCode
}

function Invoke-Audit {
    Write-Banner "Levo Security Audit"
    
    if (-not (Test-Requirements)) { return 1 }
    
    # Ensure installed
    if (-not (Find-Python)) { return 1 }
    if (-not (Initialize-Venv)) { return 1 }
    if (-not (Enter-Venv)) { return 1 }
    
    # Check if levo is installed
    $installed = & python -m pip show levo 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Levo CLI not found, installing..."
        if (-not (Install-LevoCli)) { return 1 }
    }
    
    # Set audit defaults
    Set-TestDefaults
    $script:FailScope = 'none'
    $script:FailSeverity = 'none'
    $script:TestMethods = 'GET,POST,PUT,DELETE,PATCH'
    
    Show-TestConfig
    Write-Host "  Mode: AUDIT (will not fail build)" -ForegroundColor Yellow
    
    $exitCode = Invoke-SecurityTest
    
    Write-Banner "Audit completed (exit code ignored: $exitCode)"
    
    # Always return success for audit
    return 0
}

# ============================================================================
# Main Entry Point
# ============================================================================

$exitCode = switch ($Command) {
    'help'    { Invoke-Help }
    'install' { Invoke-Install }
    'version' { Invoke-Version }
    'test'    { Invoke-Test }
    'audit'   { Invoke-Audit }
    default   { Invoke-Help }
}

exit $exitCode
