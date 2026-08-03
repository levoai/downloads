#!/usr/bin/env bash
#
# Levo CLI Runner for Linux/macOS - Bash Version
#
# Native (Docker-less) port of levo-cli-runner.ps1. Handles:
#   - Python 3.12+ detection and validation (uses existing installation)
#   - Virtual environment creation/reuse (.levo-venv/bin, POSIX layout)
#   - Levo CLI installation from Google Artifact Registry
#   - Security test execution via `levo remote-test-run`
#
# Runs on an Ubuntu Bitbucket shell runner (no Docker) and on macOS for
# local/dev use. Written to be bash 3.2 compatible (macOS default bash).
#
# Commands: install | test | audit | version | help
#
# Secret handling: no secret (Levo auth key, GAR/PyPI credentials) is ever passed
# as a command-line argument, because argv is world-readable on Unix hosts via
# `ps` / /proc/<pid>/cmdline. Secrets travel through the environment or 0600 temp
# files instead; see LEVO_LOGIN_SHIM and install_levo_cli below.
#
# Required environment variables:
#   LEVOAI_AUTH_KEY   Levo Auth key for authentication
#   LEVOAI_ORG_ID     Levo organization ID
#
# Artifact Registry auth (pick ONE):
#   LEVOAI_GAR_SA_KEY_B64   Base64-encoded Google service account JSON key.
#                           Recommended. Uses keyrings.google-artifactregistry-auth,
#                           which auto-refreshes OAuth tokens. No gcloud required.
#   PYPI_USERNAME + PYPI_PASSWORD
#                           Legacy path. PYPI_USERNAME is typically
#                           'oauth2accesstoken' and PYPI_PASSWORD is a short-lived
#                           gcloud access token (ya29.*). Token expires in ~60 min.
#
# Optional environment variables:
#   LEVOAI_CLI_VERSION   Specific CLI version (default: latest)
#   LEVOAI_BASE_URL      Custom Levo API URL
#   PYPI_INDEX_URL       Override default GAR index URL
#
# Examples:
#   ./levo-cli-runner.sh install
#   ./levo-cli-runner.sh test --target-url https://api.example.com
#   ./levo-cli-runner.sh test --app-name myapp --environment production --target-url https://api.example.com
#   ./levo-cli-runner.sh test --environment production --data-source Traces --run-on cloud --target-url https://api.example.com
#   ./levo-cli-runner.sh test --data-source TestUserData --test-users 'Victim1,Victim2' --target-url https://api.example.com
#   ./levo-cli-runner.sh audit --target-url https://api.example.com

set -uo pipefail

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"
DEFAULT_LEVOAI_BASE_URL="https://api.levo.ai"

# ============================================================================
# Defaults (mirror the .ps1 param block)
# ============================================================================
COMMAND="help"
APP_NAME=""
ENVIRONMENT="staging"
TEST_METHODS=""
FAIL_SCOPE="new"
FAIL_SEVERITY="high"
DATA_SOURCE="TestUserData"
RUN_ON="cloud"
TARGET_URL=""
TEST_USERS=""
EXCLUDE_METHODS=""
ENDPOINT_PATTERN=""
EXCLUDE_ENDPOINT_PATTERN=""
CATEGORIES=""
FAIL_THRESHOLD=0
HEADERS=()
PROXY_HOST=""
PROXY_PORT=0
MAX_RUN_TIME_MINUTES=0
SUITE_EXECUTION_DELAY=0
CASE_EXECUTION_DELAY=0
IGNORE_SSL_VERIFY=false
IGNORE_HEALTH_CHECK=false
REQUEST_TIMEOUT=0
GENERATE_JUNIT_REPORT=false
ENDPOINT_TAGS=""
SKIP_CATEGORIES_RUN_WITHIN_MINUTES=0
USE_TARGET_URL_FROM_TRACES=false
RUN_TESTS_SEQUENTIALLY=false
ADD_TRAILING_SLASH=false
TESTRUNNER_GROUP_NAME=""
USE_AUTH_FROM_TRACES=false
TRACE_RECEIVED_TIME_IN_MINUTES=0
VENV_DIR=".levo-venv"
WORK_DIR="$PWD"

# Populated after arg parse
PYPI_INDEX_URL_DEFAULT="${PYPI_INDEX_URL:-https://us-python.pkg.dev/levoai/pypi-levo/simple/}"
PYTHON_CMD=""
VENV_PATH=""
LOG_FILE=""
PIP_LOG_FILE=""
SA_KEY_PATH=""          # temp GAR service-account key (keyring auth)
PIP_CONFIG_PATH=""      # temp 0600 pip.conf holding legacy index creds
CONFIG_CLEAN_PATH=""    # temp 0600 levo session config we created

# ============================================================================
# Cleanup / colors
# ============================================================================
# shellcheck disable=SC2329  # invoked indirectly via `trap cleanup EXIT`
cleanup() {
    # Remove any secret-bearing temp files we created.
    local f
    for f in "$SA_KEY_PATH" "$PIP_CONFIG_PATH" "$CONFIG_CLEAN_PATH"; do
        if [ -n "$f" ] && [ -f "$f" ]; then
            rm -f "$f" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT

if [ -t 1 ]; then
    C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'
    C_CYAN='\033[0;36m'; C_RESET='\033[0m'
else
    C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_RESET=''
fi

log() {
    # log <message> [level]
    local message="$1"
    local level="${2:-Info}"
    local color prefix
    case "$level" in
        Error)   color="$C_RED";    prefix="[-]" ;;
        Success) color="$C_GREEN";  prefix="[+]" ;;
        Warning) color="$C_YELLOW"; prefix="[!]" ;;
        Info)    color="$C_CYAN";   prefix="[*]" ;;
        *)       color="";          prefix="   " ;;
    esac
    printf "%b%s %s%b\n" "$color" "$prefix" "$message" "$C_RESET"
}

banner() {
    local border
    border="$(printf '=%.0s' $(seq 1 50))"
    printf "\n%b%s%b\n" "$C_CYAN" "$border" "$C_RESET"
    printf "%b  %s%b\n" "$C_CYAN" "$1" "$C_RESET"
    printf "%b%s%b\n\n" "$C_CYAN" "$border" "$C_RESET"
}

is_int() {
    # Accepts an optional leading '-' followed by one or more digits.
    # Rejects embedded hyphens (e.g. '1-2'), empty string, and non-digits.
    case "$1" in
        ''|-) return 1 ;;
        -*) case "${1#-}" in *[!0-9]*) return 1 ;; esac ;;
        *[!0-9]*) return 1 ;;
    esac
    return 0
}

# ============================================================================
# Python detection
# ============================================================================
py_version_ok() {
    # py_version_ok <python-cmd>  -> 0 if reports Python >= 3.12
    local cmd="$1" out major minor
    out="$("$cmd" --version 2>&1)" || return 1
    case "$out" in
        Python\ *) ;;
        *) return 1 ;;
    esac
    out="${out#Python }"
    major="${out%%.*}"
    out="${out#*.}"
    minor="${out%%.*}"
    is_int "$major" || return 1
    is_int "$minor" || return 1
    if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 12 ]; }; then
        return 0
    fi
    return 1
}

find_python() {
    log "Detecting Python 3.12+..."
    local cmd ver
    for cmd in python3.12 python3.13 python3.14 python3 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            if py_version_ok "$cmd"; then
                PYTHON_CMD="$cmd"
                ver="$("$cmd" --version 2>&1)"
                log "Found: $ver (via $cmd)" Success
                return 0
            else
                ver="$("$cmd" --version 2>&1 || true)"
                if [ -n "$ver" ]; then
                    log "Found $ver but need 3.12+" Warning
                fi
            fi
        fi
    done

    log "Python 3.12 or higher is required but not found." Error
    printf "\n"
    printf "Please install Python 3.12+ (e.g. from your package manager or https://www.python.org/downloads/)\n"
    printf "Or ensure it's on your PATH.\n\n"
    return 1
}

# ============================================================================
# Virtual environment management
# ============================================================================
init_venv() {
    local venv_python="$VENV_PATH/bin/python"
    if [ -f "$VENV_PATH/bin/activate" ]; then
        log "Virtual environment exists: $VENV_PATH"
        if [ -x "$venv_python" ]; then
            if py_version_ok "$venv_python"; then
                log "Virtual environment has Python 3.12+" Success
                return 0
            else
                log "Virtual environment has an unsupported Python (<3.12), recreating..." Warning
                rm -rf "$VENV_PATH" 2>/dev/null || true
            fi
        else
            log "Virtual environment exists but python not found, recreating..." Warning
            rm -rf "$VENV_PATH" 2>/dev/null || true
        fi
    fi

    log "Creating virtual environment: $VENV_PATH"
    if ! "$PYTHON_CMD" -m venv "$VENV_PATH"; then
        log "Failed to create virtual environment" Error
        return 1
    fi
    log "Virtual environment created" Success
    return 0
}

enter_venv() {
    local activate="$VENV_PATH/bin/activate"
    if [ ! -f "$activate" ]; then
        log "Virtual environment not found: $activate" Error
        return 1
    fi
    log "Activating virtual environment..."
    # Mirror the .ps1: manually put the venv on PATH rather than sourcing activate.
    export VIRTUAL_ENV="$VENV_PATH"
    export PATH="$VENV_PATH/bin:$PATH"
    # Upgrade pip tooling quietly (best-effort).
    python -m pip install --upgrade pip setuptools wheel -q >/dev/null 2>&1 || true
    log "Virtual environment activated" Success
    return 0
}

# ============================================================================
# Levo CLI installation
# ============================================================================
install_levo_cli() {
    log "Installing Levo CLI..."

    # Auth mode priority:
    #   1. LEVOAI_GAR_SA_KEY_B64 -> keyring helper (auto-refresh, no gcloud).
    #   2. PYPI_USERNAME/PYPI_PASSWORD -> credentials in a 0600 pip.conf (no argv leak).
    local index_url="$PYPI_INDEX_URL_DEFAULT"
    local used_gar_key=false
    local used_pip_config=false

    if [ -n "${LEVOAI_GAR_SA_KEY_B64:-}" ]; then
        used_gar_key=true
        SA_KEY_PATH="$(mktemp "${TMPDIR:-/tmp}/gar-sa-key-XXXXXX.json")" || {
            log "Failed to create temp file for GAR key" Error
            return 1
        }
        chmod 600 "$SA_KEY_PATH" 2>/dev/null || true
        # Decode via python (guaranteed present) to avoid base64 flag differences
        # between GNU (Linux) and BSD (macOS).
        if ! printf '%s' "${LEVOAI_GAR_SA_KEY_B64}" | \
            python -c 'import sys,base64; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read().strip()))' \
            > "$SA_KEY_PATH" 2>/dev/null; then
            log "Failed to decode LEVOAI_GAR_SA_KEY_B64" Error
            return 1
        fi
        if [ ! -s "$SA_KEY_PATH" ]; then
            log "Failed to decode LEVOAI_GAR_SA_KEY_B64 (empty result)" Error
            return 1
        fi

        log "Installing keyrings.google-artifactregistry-auth..."
        if ! python -m pip install --no-cache-dir keyrings.google-artifactregistry-auth; then
            log "Failed to install keyring helper" Error
            return 1
        fi
        log "Using GAR service account key via keyring helper" Success
    elif [ -n "${PYPI_USERNAME:-}" ]; then
        if [ -z "${PYPI_PASSWORD:-}" ]; then
            log "PYPI_PASSWORD is required when PYPI_USERNAME is set" Error
            return 1
        fi
        # Do NOT embed the token in --index-url (it would leak via process argv on a
        # shared Unix runner). Write it to a 0600 pip.conf and reference it via
        # PIP_CONFIG_FILE so no secret ever appears on the command line.
        used_pip_config=true
        local old_umask_pc
        old_umask_pc="$(umask)"
        umask 077
        PIP_CONFIG_PATH="$(mktemp "${TMPDIR:-/tmp}/levo-pip-XXXXXX.conf")" || {
            umask "$old_umask_pc"
            log "Failed to create temp pip config" Error
            return 1
        }
        {
            printf '[global]\n'
            printf 'index-url = https://%s:%s@us-python.pkg.dev/levoai/pypi-levo/simple/\n' \
                "${PYPI_USERNAME}" "${PYPI_PASSWORD}"
            printf 'extra-index-url = https://pypi.org/simple/\n'
        } > "$PIP_CONFIG_PATH"
        umask "$old_umask_pc"
        log "Using authenticated repository (credentials in 0600 pip.conf, not argv)"
    else
        log "No Artifact Registry credentials configured." Error
        log "Set ONE of the following before running install/test:" Error
        log "  export LEVOAI_GAR_SA_KEY_B64='<base64 SA key>'   (recommended)" Error
        log "  -- or --" Error
        log "  export PYPI_USERNAME='oauth2accesstoken'; export PYPI_PASSWORD='<ya29 token>'" Error
        return 1
    fi

    # Package spec
    local package_spec="levo"
    if [ -n "${LEVOAI_CLI_VERSION:-}" ]; then
        package_spec="levo==${LEVOAI_CLI_VERSION}"
        log "Installing version: ${LEVOAI_CLI_VERSION}"
    else
        log "Installing latest version"
    fi

    log "Running pip install..."
    # trusted-host flags are not secret and stay on argv. Index URLs carrying secrets
    # never touch argv:
    #   - keyring path: GOOGLE_APPLICATION_CREDENTIALS scoped to this command; index-url
    #     is the credential-free GAR URL.
    #   - legacy path: index/extra-index come from the 0600 pip.conf via PIP_CONFIG_FILE.
    local rc
    if [ "$used_gar_key" = true ]; then
        GOOGLE_APPLICATION_CREDENTIALS="$SA_KEY_PATH" python -m pip install --no-cache-dir \
            "$package_spec" \
            --index-url "$index_url" \
            --extra-index-url "https://pypi.org/simple/" \
            --trusted-host us-python.pkg.dev \
            --trusted-host pypi.org \
            --trusted-host files.pythonhosted.org \
            >"$PIP_LOG_FILE" 2>&1
        rc=$?
    elif [ "$used_pip_config" = true ]; then
        PIP_CONFIG_FILE="$PIP_CONFIG_PATH" python -m pip install --no-cache-dir \
            "$package_spec" \
            --trusted-host us-python.pkg.dev \
            --trusted-host pypi.org \
            --trusted-host files.pythonhosted.org \
            >"$PIP_LOG_FILE" 2>&1
        rc=$?
    else
        python -m pip install --no-cache-dir \
            "$package_spec" \
            --index-url "$index_url" \
            --extra-index-url "https://pypi.org/simple/" \
            --trusted-host us-python.pkg.dev \
            --trusted-host pypi.org \
            --trusted-host files.pythonhosted.org \
            >"$PIP_LOG_FILE" 2>&1
        rc=$?
    fi

    if [ "$rc" -ne 0 ]; then
        log "pip install failed. See $PIP_LOG_FILE for details" Error
        cat "$PIP_LOG_FILE" >&2 || true
        return 1
    fi

    # NOTE: The Windows runner force-reinstalls grpcio/orjson/cryptography/protobuf to
    # work around C-extension compilation issues on Windows. That is unnecessary on
    # Linux/macOS, where prebuilt manylinux/macos wheels are used, so it is intentionally
    # omitted here.

    log "Levo CLI installed" Success
    return 0
}

verify_installation() {
    log "Verifying installation..."
    if ! python -m pip show levo >/dev/null 2>&1; then
        log "levo package not found" Error
        return 1
    fi
    log "Installation verified" Success
    return 0
}

# Sets LEVO_BIN array to the levo entrypoint.
set_levo_bin() {
    if [ -x "$VENV_PATH/bin/levo" ]; then
        LEVO_BIN=("$VENV_PATH/bin/levo")
    else
        LEVO_BIN=(python -m levo)
    fi
}

# ============================================================================
# Environment variable mapping
# ============================================================================
set_levo_env() {
    # levo package expects LEVO_BASE_URL; map from LEVOAI_BASE_URL (default if unset).
    export LEVO_BASE_URL="${LEVOAI_BASE_URL:-$DEFAULT_LEVOAI_BASE_URL}"
}

# Python shim used to run `levo login` without ever placing the auth key on a
# command line.
#
# argv is world-readable on Linux/macOS (`ps`, /proc/<pid>/cmdline), so any
# process on a shared or self-hosted runner can read a secret passed as `--key`.
# The environment block is not: /proc/<pid>/environ is readable only by the
# process owner (and root), which is the standard way to hand a secret to a
# child process.
#
# So the key is exported for this one invocation, and this shim appends it to
# the *interpreter-level* `sys.argv` before handing control to the levo console
# entry point. Assigning to `sys.argv` in Python rewrites only the in-process
# list; it does not touch the kernel's copy of the command line. The OS-visible
# command line therefore stays `python -c <shim source> login --organization X`,
# with the secret nowhere in it.
#
# The entry point is resolved from installed package metadata (version- and
# module-name agnostic), falling back to running the venv's `levo` console
# script and then the `levo` module under runpy — the same two targets
# set_levo_bin() picks between, so behaviour matches invoking `levo` directly.
LEVO_LOGIN_SHIM='
import os, runpy, sys

key = os.environ.pop("LEVOAI_RUNNER_LOGIN_KEY", "")
script = os.environ.pop("LEVOAI_RUNNER_LEVO_SCRIPT", "")

argv = list(sys.argv[1:])
if key:
    argv = argv + ["--key", key]
sys.argv = ["levo"] + argv
del key

fn = None
try:
    from importlib.metadata import entry_points
    try:
        eps = list(entry_points(group="console_scripts"))
    except TypeError:  # importlib.metadata < 3.10 selection API
        eps = list(entry_points().get("console_scripts", []))
    for ep in eps:
        if ep.name == "levo":
            fn = ep.load()
            break
except Exception:
    fn = None

if fn is not None:
    sys.exit(fn())
if script and os.path.isfile(script):
    runpy.run_path(script, run_name="__main__")
    sys.exit(0)
try:  # mirrors the "python -m levo" fallback in set_levo_bin
    runpy.run_module("levo", run_name="__main__", alter_sys=True)
    sys.exit(0)
except ImportError:
    pass
sys.stderr.write("levo entry point not found in this environment\n")
sys.exit(1)
'

# Authenticate once via `levo login`, which stores a session in LEVOAI_CONFIG_FILE.
# The subsequent `remote-test-run` reads that session and is invoked WITHOUT --key,
# so the long-lived auth key never appears in the long-running scan's process argv
# (readable via ps/proc on shared Unix runners). The session file is created 0600.
#
# The login itself also keeps the key off argv: it is passed through the
# environment and injected into sys.argv inside the interpreter by
# LEVO_LOGIN_SHIM (see above), so the key is not on any process command line at
# any point.
levo_login() {
    log "Authenticating with Levo (session -> $LEVOAI_CONFIG_FILE)..."
    local old_umask rc=0 levo_script=""
    [ -x "$VENV_PATH/bin/levo" ] && levo_script="$VENV_PATH/bin/levo"
    old_umask="$(umask)"
    umask 077
    LEVOAI_RUNNER_LOGIN_KEY="${LEVOAI_AUTH_KEY:-}" \
    LEVOAI_RUNNER_LEVO_SCRIPT="$levo_script" \
        python -c "$LEVO_LOGIN_SHIM" login --organization "${LEVOAI_ORG_ID:-}" \
        >"$WORK_DIR/levo-login.log" 2>&1 || rc=$?
    umask "$old_umask"
    if [ -f "$LEVOAI_CONFIG_FILE" ]; then
        chmod 600 "$LEVOAI_CONFIG_FILE" 2>/dev/null || true
    fi
    if [ "$rc" -ne 0 ]; then
        log "levo login failed (exit $rc). See $WORK_DIR/levo-login.log" Error
        log "Verify LEVOAI_AUTH_KEY / LEVOAI_ORG_ID." Error
        return 1
    fi
    log "Authenticated; auth key never placed on any process command line" Success
    return 0
}

# ============================================================================
# Security testing
# ============================================================================
test_requirements() {
    local failed=false

    if [ -z "${LEVOAI_AUTH_KEY:-}" ]; then
        log "LEVOAI_AUTH_KEY is required but not set" Error
        failed=true
    fi
    if [ -z "${LEVOAI_ORG_ID:-}" ]; then
        log "LEVOAI_ORG_ID is required but not set" Error
        failed=true
    fi
    if [ -z "$TARGET_URL" ] && [ "$USE_TARGET_URL_FROM_TRACES" != true ]; then
        log "--target-url is required unless --use-target-url-from-traces is set" Error
        failed=true
    fi
    case "$DATA_SOURCE" in
        TestUserData|"Test User Data"|Traces) ;;
        *) log "--data-source must be 'TestUserData' (or 'Test User Data') or 'Traces'" Error; failed=true ;;
    esac
    case "$RUN_ON" in
        cloud|on-prem) ;;
        *) log "--run-on must be 'cloud' or 'on-prem'" Error; failed=true ;;
    esac
    if [ -n "$TEST_METHODS" ] && [ -n "$EXCLUDE_METHODS" ]; then
        log "--test-methods and --exclude-methods cannot be used together" Error
        failed=true
    fi
    if [ "$PROXY_PORT" -lt 0 ] || [ "$PROXY_PORT" -gt 65535 ]; then
        log "--proxy-port must be between 1 and 65535 (0 = unset)" Error
        failed=true
    fi
    if [ "$MAX_RUN_TIME_MINUTES" -lt 0 ] || [ "$SUITE_EXECUTION_DELAY" -lt 0 ] || \
       [ "$CASE_EXECUTION_DELAY" -lt 0 ] || [ "$REQUEST_TIMEOUT" -lt 0 ] || \
       [ "$SKIP_CATEGORIES_RUN_WITHIN_MINUTES" -lt 0 ] || \
       [ "$TRACE_RECEIVED_TIME_IN_MINUTES" -lt 0 ] || \
       [ "$FAIL_THRESHOLD" -lt 0 ]; then
        log "Numeric remote test run options cannot be negative" Error
        failed=true
    fi

    if [ "$failed" = true ]; then
        printf "\n"
        printf "Please set the required environment variables and parameters:\n"
        printf "  export LEVOAI_AUTH_KEY='your-auth-key'\n"
        printf "  export LEVOAI_ORG_ID='your-org-id'\n"
        printf "  --target-url 'https://api.example.com'\n"
        printf "  or --use-target-url-from-traces\n\n"
        return 1
    fi
    return 0
}

resolve_app_name() {
    if [ -n "$APP_NAME" ]; then
        return 0
    fi
    if [ -n "${BITBUCKET_REPO_SLUG:-}" ]; then
        APP_NAME="$BITBUCKET_REPO_SLUG"
    elif [ -n "${GITHUB_REPOSITORY:-}" ]; then
        APP_NAME="$(basename "$GITHUB_REPOSITORY")"
    else
        local git_root
        git_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
        if [ -n "$git_root" ]; then
            APP_NAME="$(basename "$git_root")"
        fi
    fi
    if [ -z "$APP_NAME" ]; then
        APP_NAME="default-app"
    fi
}

show_test_config() {
    printf "\n%bTest Configuration:%b\n" "$C_CYAN" "$C_RESET"
    printf "  App Name:         %s\n" "$APP_NAME"
    printf "  Environment:      %s\n" "$ENVIRONMENT"
    printf "  Data Source:      %s\n" "$DATA_SOURCE"
    printf "  Run On:           %s\n" "$RUN_ON"
    if [ "$USE_TARGET_URL_FROM_TRACES" = true ]; then
        printf "  Target URL:       from traces\n"
    else
        printf "  Target URL:       %s\n" "$TARGET_URL"
    fi
    [ -n "$TEST_USERS" ] && printf "  Test Users:       %s\n" "$TEST_USERS"
    [ -n "$TEST_METHODS" ] && printf "  HTTP Methods:     %s\n" "$TEST_METHODS"
    [ -n "$EXCLUDE_METHODS" ] && printf "  Exclude Methods:  %s\n" "$EXCLUDE_METHODS"
    [ -n "$ENDPOINT_PATTERN" ] && printf "  Endpoint Pattern: %s\n" "$ENDPOINT_PATTERN"
    [ -n "$EXCLUDE_ENDPOINT_PATTERN" ] && printf "  Exclude Endpoint Pattern: %s\n" "$EXCLUDE_ENDPOINT_PATTERN"
    [ -n "$CATEGORIES" ] && printf "  Categories:       %s\n" "$CATEGORIES"
    printf "  Fail Scope:       %s\n" "$FAIL_SCOPE"
    printf "  Fail Severity:    %s\n" "$FAIL_SEVERITY"
    [ "$FAIL_THRESHOLD" -gt 0 ] && printf "  Fail Threshold:   %s\n" "$FAIL_THRESHOLD"
    [ -n "$ENDPOINT_TAGS" ] && printf "  Endpoint Tags:    %s\n" "$ENDPOINT_TAGS"
    [ -n "$TESTRUNNER_GROUP_NAME" ] && printf "  Testrunner Group: %s\n" "$TESTRUNNER_GROUP_NAME"
    [ "${#HEADERS[@]}" -gt 0 ] && printf "  Headers:          %s custom header(s)\n" "${#HEADERS[@]}"
    [ "$IGNORE_SSL_VERIFY" = true ] && printf "  Ignore SSL:       true\n"
    [ "$IGNORE_HEALTH_CHECK" = true ] && printf "  Ignore Health:    true\n"
    [ "$USE_AUTH_FROM_TRACES" = true ] && printf "  Auth From Traces: true\n"
    [ "$RUN_TESTS_SEQUENTIALLY" = true ] && printf "  Sequential Runs:  true\n"
    printf "  API URL:          %s\n\n" "${LEVO_BASE_URL:-$DEFAULT_LEVOAI_BASE_URL}"
}

invoke_security_test() {
    log "Running security tests..."
    log "Output will be saved to: $LOG_FILE"

    set_levo_env
    set_levo_bin

    # NOTE: --key/--organization are deliberately NOT passed here. Auth comes from the
    # session established by levo_login() (stored in LEVOAI_CONFIG_FILE), so the secret
    # never appears in this long-running process's argv.
    local args
    args=(
        remote-test-run
        --app-name "$APP_NAME"
        --env "$ENVIRONMENT"
        --data-source "$DATA_SOURCE"
        --run-on "$RUN_ON"
        --fail-scope "$FAIL_SCOPE"
        --fail-severity "$FAIL_SEVERITY"
    )

    if [ "$USE_TARGET_URL_FROM_TRACES" = true ]; then
        args+=(--use-target-url-from-traces)
    else
        args+=(--target-url "$TARGET_URL")
    fi

    # Methods vs exclude-methods (mutually exclusive); default GET,POST.
    if [ -n "$TEST_METHODS" ]; then
        args+=(--methods "$TEST_METHODS")
    elif [ -n "$EXCLUDE_METHODS" ]; then
        args+=(--exclude-methods "$EXCLUDE_METHODS")
    else
        args+=(--methods "GET,POST")
    fi

    [ -n "$ENDPOINT_PATTERN" ] && args+=(--endpoint-pattern "$ENDPOINT_PATTERN")
    [ -n "$EXCLUDE_ENDPOINT_PATTERN" ] && args+=(--exclude-endpoint-pattern "$EXCLUDE_ENDPOINT_PATTERN")
    [ -n "$CATEGORIES" ] && args+=(--categories "$CATEGORIES")
    [ "$FAIL_THRESHOLD" -gt 0 ] && args+=(--fail-threshold "$FAIL_THRESHOLD")

    if [ -n "$TEST_USERS" ]; then
        case "$DATA_SOURCE" in
            TestUserData|"Test User Data") args+=(--test-users "$TEST_USERS") ;;
        esac
    fi

    if [ "${#HEADERS[@]}" -gt 0 ]; then
        local h
        for h in "${HEADERS[@]}"; do
            [ -n "$h" ] && args+=(--header "$h")
        done
    fi

    [ -n "$PROXY_HOST" ] && args+=(--proxy-host "$PROXY_HOST")
    [ "$PROXY_PORT" -gt 0 ] && args+=(--proxy-port "$PROXY_PORT")
    [ "$MAX_RUN_TIME_MINUTES" -gt 0 ] && args+=(--max-run-time-minutes "$MAX_RUN_TIME_MINUTES")
    [ "$SUITE_EXECUTION_DELAY" -gt 0 ] && args+=(--suite-execution-delay "$SUITE_EXECUTION_DELAY")
    [ "$CASE_EXECUTION_DELAY" -gt 0 ] && args+=(--case-execution-delay "$CASE_EXECUTION_DELAY")
    [ "$IGNORE_SSL_VERIFY" = true ] && args+=(--ignore-ssl-verify)
    [ "$IGNORE_HEALTH_CHECK" = true ] && args+=(--ignore-health-check)
    [ "$REQUEST_TIMEOUT" -gt 0 ] && args+=(--request-timeout "$REQUEST_TIMEOUT")
    [ "$GENERATE_JUNIT_REPORT" = true ] && args+=(--generate-junit-report)
    [ -n "$ENDPOINT_TAGS" ] && args+=(--endpoint-tags "$ENDPOINT_TAGS")
    [ "$SKIP_CATEGORIES_RUN_WITHIN_MINUTES" -gt 0 ] && args+=(--skip-categories-run-within-minutes "$SKIP_CATEGORIES_RUN_WITHIN_MINUTES")
    [ "$RUN_TESTS_SEQUENTIALLY" = true ] && args+=(--run-tests-sequentially)
    [ "$ADD_TRAILING_SLASH" = true ] && args+=(--add-trailing-slash)
    [ -n "$TESTRUNNER_GROUP_NAME" ] && args+=(--testrunner-group-name "$TESTRUNNER_GROUP_NAME")
    [ "$USE_AUTH_FROM_TRACES" = true ] && args+=(--use-auth-from-traces)
    [ "$TRACE_RECEIVED_TIME_IN_MINUTES" -gt 0 ] && args+=(--trace-received-time-in-minutes "$TRACE_RECEIVED_TIME_IN_MINUTES")

    args+=(--verbosity INFO)

    # Execute; stream live and tee to the log file. PIPESTATUS[0] is the CLI's exit code.
    local exit_code
    printf "\n%b%s%b\n" "$C_CYAN" "$(printf '=%.0s' $(seq 1 40))" "$C_RESET"
    printf "%bTest Output:%b\n" "$C_CYAN" "$C_RESET"
    printf "%b%s%b\n" "$C_CYAN" "$(printf '=%.0s' $(seq 1 40))" "$C_RESET"

    "${LEVO_BIN[@]}" "${args[@]}" 2>&1 | tee "$LOG_FILE"
    exit_code=${PIPESTATUS[0]}

    printf "%b%s%b\n\n" "$C_CYAN" "$(printf '=%.0s' $(seq 1 40))" "$C_RESET"
    return "$exit_code"
}

# ============================================================================
# Command handlers
# ============================================================================
invoke_help() {
    banner "Levo CLI Runner v$SCRIPT_VERSION"
    cat <<EOF
Usage: $SCRIPT_NAME <command> [options]

Commands:
  install   Install Levo CLI into virtual environment
  test      Run security tests (auto-installs if needed)
  audit     Run comprehensive audit (never fails build)
  version   Show installed Levo CLI version
  help      Show this help message

Options:
  --app-name <string>            Application name (default: auto-detected)
  --environment <string>         Target environment (default: staging) [alias: --env]
  --data-source <string>         Data source: 'TestUserData' or 'Traces' (default: TestUserData)
  --run-on <string>              Where to run: 'cloud' or 'on-prem' (default: cloud)
  --target-url <string>          Target URL for the test run (required unless --use-target-url-from-traces)
  --test-users <string>          Comma-separated test user names (only for TestUserData)
  --test-methods <string>        HTTP methods to include, comma-separated (default: GET,POST; excl. with --exclude-methods)
  --exclude-methods <string>     HTTP methods to exclude, comma-separated (excl. with --test-methods)
  --endpoint-pattern <string>    Regex to match endpoints to test
  --exclude-endpoint-pattern <string> Regex to exclude endpoints from testing
  --categories <string>          Security test categories, comma-separated
  --endpoint-tags <string>       Endpoint tags, comma-separated
  --header <string>              Custom request header (repeatable). Example: --header 'Authorization: Bearer token'
  --use-target-url-from-traces   Use target URLs from traces instead of --target-url
  --use-auth-from-traces         Use authentication captured in traces
  --trace-received-time-in-minutes <int>  How far back to look for traces
  --testrunner-group-name <string>         On-prem testrunner group name
  --proxy-host <string> / --proxy-port <int>  Proxy for target API requests
  --ignore-ssl-verify            Disable target SSL verification
  --ignore-health-check          Skip target URL reachability checks
  --request-timeout <int>        Target request timeout in seconds
  --run-tests-sequentially       Run endpoint test batches sequentially
  --add-trailing-slash           Append trailing slash to endpoint paths
  --generate-junit-report        Request JUnit report generation
  --max-run-time-minutes <int>   Maximum total run time
  --suite-execution-delay <int>  Delay between endpoint/test-suite execution
  --case-execution-delay <int>   Delay between test case execution
  --skip-categories-run-within-minutes <int>  Skip recently run categories
  --fail-scope <string>          new|any|none (default: new)
  --fail-severity <string>       critical|high|medium|low|none (default: high)
  --fail-threshold <int>         Fail if vulnerability count exceeds this threshold
  --venv-dir <string>            Virtual environment directory (default: .levo-venv)
  --work-dir <string>            Working directory (default: current directory)

Examples:
  $SCRIPT_NAME test --target-url https://api.example.com
  $SCRIPT_NAME test --app-name myapp --environment production --target-url https://api.example.com
  $SCRIPT_NAME test --environment production --data-source Traces --run-on cloud --target-url https://api.example.com
  $SCRIPT_NAME test --data-source TestUserData --test-users 'Victim1,Victim2' --target-url https://api.example.com
  $SCRIPT_NAME test --target-url https://api.example.com --exclude-methods 'DELETE,PUT' --categories 'CORS,FUZZING'
  $SCRIPT_NAME test --target-url https://api.example.com --endpoint-pattern '^/api/v1/.*' --fail-threshold 10
  $SCRIPT_NAME test --environment UAT --use-target-url-from-traces --data-source Traces --use-auth-from-traces
  $SCRIPT_NAME test --target-url https://api.example.com --header 'Authorization: Bearer token' --ignore-ssl-verify
  $SCRIPT_NAME test --target-url https://api.example.com --run-on on-prem --testrunner-group-name uat-runners

Required environment variables:
  LEVOAI_AUTH_KEY      Levo Auth Key
  LEVOAI_ORG_ID        Levo organization ID

Artifact Registry auth (pick ONE):
  LEVOAI_GAR_SA_KEY_B64            Base64 Google SA JSON key (recommended)
  PYPI_USERNAME + PYPI_PASSWORD    Legacy ya29.* token path

Optional environment variables:
  LEVOAI_CLI_VERSION   Specific CLI version (default: latest)
  LEVOAI_BASE_URL      Custom Levo API URL
EOF
    return 0
}

invoke_install() {
    banner "Installing Levo CLI"
    find_python || return 1
    init_venv || return 1
    enter_venv || return 1
    install_levo_cli || return 1
    verify_installation || return 1
    banner "Levo CLI installed successfully!"
    return 0
}

invoke_version() {
    find_python || return 1
    init_venv || return 1
    enter_venv || return 1
    set_levo_env
    set_levo_bin

    printf "\n%bLevo CLI Version:%b\n" "$C_CYAN" "$C_RESET"

    local version_text=""
    version_text="$("${LEVO_BIN[@]}" --version 2>/dev/null | tr -d '\r' | head -n 1)"
    case "$version_text" in
        *"Usage:"*|*"No such command"*) version_text="" ;;
    esac

    if [ -z "$version_text" ]; then
        # Fallback: read installed package version from pip metadata.
        version_text="$(python -m pip show levo 2>/dev/null | awk -F': ' '/^Version:/ {print $2; exit}')"
    fi

    if [ -n "$version_text" ]; then
        printf "  %s\n" "$version_text"
        return 0
    fi
    log "Could not determine Levo CLI version" Error
    return 1
}

invoke_test() {
    banner "Levo Security Test"
    resolve_app_name
    set_levo_env

    test_requirements || return 1
    find_python || return 1
    init_venv || return 1
    enter_venv || return 1

    if python -m pip show levo >/dev/null 2>&1; then
        log "Levo CLI already installed"
    else
        log "Levo CLI not found, installing..."
        install_levo_cli || return 1
        verify_installation || return 1
    fi

    levo_login || return 1
    show_test_config

    local exit_code=0
    invoke_security_test || exit_code=$?

    printf "\n"
    if [ "$exit_code" -eq 0 ]; then
        banner "Security tests PASSED"
    else
        local border
        border="$(printf '=%.0s' $(seq 1 50))"
        printf "%b%s%b\n" "$C_RED" "$border" "$C_RESET"
        printf "%b  Security tests FAILED (exit code: %s)%b\n" "$C_RED" "$exit_code" "$C_RESET"
        printf "%b%s%b\n" "$C_RED" "$border" "$C_RESET"
    fi
    return "$exit_code"
}

invoke_audit() {
    banner "Levo Security Audit"
    resolve_app_name
    set_levo_env

    test_requirements || return 1
    find_python || return 1
    init_venv || return 1
    enter_venv || return 1

    if ! python -m pip show levo >/dev/null 2>&1; then
        log "Levo CLI not found, installing..."
        install_levo_cli || return 1
    fi

    levo_login || return 1

    # Audit defaults
    FAIL_SCOPE="none"
    FAIL_SEVERITY="none"
    TEST_METHODS="GET,POST,PUT,DELETE,PATCH"

    show_test_config
    printf "%b  Mode: AUDIT (will not fail build)%b\n" "$C_YELLOW" "$C_RESET"

    local exit_code=0
    invoke_security_test || exit_code=$?

    banner "Audit completed (exit code ignored: $exit_code)"
    # Always succeed for audit.
    return 0
}

# ============================================================================
# Argument parsing
# ============================================================================
require_value() {
    # require_value <flag> <count-remaining> <value> [numeric]
    #
    # Guards against an option silently consuming the next option as its value
    # (e.g. `--target-url --use-target-url-from-traces` setting TARGET_URL to the
    # literal flag and never enabling trace mode). No option in this runner takes
    # a value that legitimately starts with '-', with one exception: the numeric
    # options accept a negative number, which is let through here and rejected
    # later by the range check with a clearer message.
    if [ "$2" -lt 2 ]; then
        log "Option $1 requires a value" Error
        exit 2
    fi
    case "$3" in
        -*)
            if [ "${4:-}" = numeric ] && is_int "$3"; then
                return 0
            fi
            log "Option $1 requires a value, but got '$3' which looks like another option" Error
            exit 2
            ;;
    esac
    return 0
}

parse_args() {
    # First non-flag positional is the command.
    if [ $# -gt 0 ]; then
        case "$1" in
            install|test|audit|version|help) COMMAND="$1"; shift ;;
            -h|--help) COMMAND="help"; shift ;;
        esac
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            --app-name) require_value "$1" $# "${2:-}"; APP_NAME="$2"; shift 2 ;;
            --environment|--env) require_value "$1" $# "${2:-}"; ENVIRONMENT="$2"; shift 2 ;;
            --test-methods) require_value "$1" $# "${2:-}"; TEST_METHODS="$2"; shift 2 ;;
            --fail-scope) require_value "$1" $# "${2:-}"; FAIL_SCOPE="$2"; shift 2 ;;
            --fail-severity) require_value "$1" $# "${2:-}"; FAIL_SEVERITY="$2"; shift 2 ;;
            --data-source) require_value "$1" $# "${2:-}"; DATA_SOURCE="$2"; shift 2 ;;
            --run-on) require_value "$1" $# "${2:-}"; RUN_ON="$2"; shift 2 ;;
            --target-url) require_value "$1" $# "${2:-}"; TARGET_URL="$2"; shift 2 ;;
            --test-users) require_value "$1" $# "${2:-}"; TEST_USERS="$2"; shift 2 ;;
            --exclude-methods) require_value "$1" $# "${2:-}"; EXCLUDE_METHODS="$2"; shift 2 ;;
            --endpoint-pattern) require_value "$1" $# "${2:-}"; ENDPOINT_PATTERN="$2"; shift 2 ;;
            --exclude-endpoint-pattern) require_value "$1" $# "${2:-}"; EXCLUDE_ENDPOINT_PATTERN="$2"; shift 2 ;;
            --categories) require_value "$1" $# "${2:-}"; CATEGORIES="$2"; shift 2 ;;
            --fail-threshold) require_value "$1" $# "${2:-}" numeric; FAIL_THRESHOLD="$2"; shift 2 ;;
            --header) require_value "$1" $# "${2:-}"; HEADERS+=("$2"); shift 2 ;;
            --proxy-host) require_value "$1" $# "${2:-}"; PROXY_HOST="$2"; shift 2 ;;
            --proxy-port) require_value "$1" $# "${2:-}" numeric; PROXY_PORT="$2"; shift 2 ;;
            --max-run-time-minutes) require_value "$1" $# "${2:-}" numeric; MAX_RUN_TIME_MINUTES="$2"; shift 2 ;;
            --suite-execution-delay) require_value "$1" $# "${2:-}" numeric; SUITE_EXECUTION_DELAY="$2"; shift 2 ;;
            --case-execution-delay) require_value "$1" $# "${2:-}" numeric; CASE_EXECUTION_DELAY="$2"; shift 2 ;;
            --request-timeout) require_value "$1" $# "${2:-}" numeric; REQUEST_TIMEOUT="$2"; shift 2 ;;
            --endpoint-tags) require_value "$1" $# "${2:-}"; ENDPOINT_TAGS="$2"; shift 2 ;;
            --skip-categories-run-within-minutes) require_value "$1" $# "${2:-}" numeric; SKIP_CATEGORIES_RUN_WITHIN_MINUTES="$2"; shift 2 ;;
            --testrunner-group-name) require_value "$1" $# "${2:-}"; TESTRUNNER_GROUP_NAME="$2"; shift 2 ;;
            --trace-received-time-in-minutes) require_value "$1" $# "${2:-}" numeric; TRACE_RECEIVED_TIME_IN_MINUTES="$2"; shift 2 ;;
            --venv-dir) require_value "$1" $# "${2:-}"; VENV_DIR="$2"; shift 2 ;;
            --work-dir) require_value "$1" $# "${2:-}"; WORK_DIR="$2"; shift 2 ;;
            --ignore-ssl-verify) IGNORE_SSL_VERIFY=true; shift ;;
            --ignore-health-check) IGNORE_HEALTH_CHECK=true; shift ;;
            --generate-junit-report) GENERATE_JUNIT_REPORT=true; shift ;;
            --use-target-url-from-traces) USE_TARGET_URL_FROM_TRACES=true; shift ;;
            --run-tests-sequentially) RUN_TESTS_SEQUENTIALLY=true; shift ;;
            --add-trailing-slash) ADD_TRAILING_SLASH=true; shift ;;
            --use-auth-from-traces) USE_AUTH_FROM_TRACES=true; shift ;;
            -h|--help) COMMAND="help"; shift ;;
            *) log "Unknown option: $1" Error; exit 2 ;;
        esac
    done

    # Validate integer-typed options up front.
    local name val
    for name in FAIL_THRESHOLD PROXY_PORT MAX_RUN_TIME_MINUTES SUITE_EXECUTION_DELAY \
                CASE_EXECUTION_DELAY REQUEST_TIMEOUT SKIP_CATEGORIES_RUN_WITHIN_MINUTES \
                TRACE_RECEIVED_TIME_IN_MINUTES; do
        val="${!name}"   # indirect expansion (bash 3.2+), avoids eval
        if ! is_int "$val"; then
            log "$name must be an integer (got: '$val')" Error
            exit 2
        fi
    done
}

# ============================================================================
# Main
# ============================================================================
main() {
    parse_args "$@"

    # Ensure the working directory exists (it is advertised via --work-dir and is where
    # the venv, logs, and session config are written). Fail early with a clear message.
    if [ ! -d "$WORK_DIR" ]; then
        if ! mkdir -p "$WORK_DIR" 2>/dev/null; then
            log "--work-dir '$WORK_DIR' does not exist and could not be created" Error
            exit 2
        fi
    fi

    VENV_PATH="$WORK_DIR/$VENV_DIR"
    LOG_FILE="$WORK_DIR/levo-test-output.log"
    PIP_LOG_FILE="$WORK_DIR/pip-install.log"

    # Session config: honor a user-provided LEVOAI_CONFIG_FILE, otherwise use a dedicated
    # 0600 file in the work dir that we clean up on exit (holds the auth session).
    if [ -z "${LEVOAI_CONFIG_FILE:-}" ]; then
        export LEVOAI_CONFIG_FILE="$WORK_DIR/.levo-session.json"
        CONFIG_CLEAN_PATH="$LEVOAI_CONFIG_FILE"
    else
        export LEVOAI_CONFIG_FILE
    fi

    local exit_code=0
    case "$COMMAND" in
        help)    invoke_help || exit_code=$? ;;
        install) invoke_install || exit_code=$? ;;
        version) invoke_version || exit_code=$? ;;
        test)    invoke_test || exit_code=$? ;;
        audit)   invoke_audit || exit_code=$? ;;
        *)       invoke_help || exit_code=$? ;;
    esac
    exit "$exit_code"
}

# Run main only when executed directly, so the script can be `source`d by the test
# harness to unit-test individual functions without invoking the CLI.
if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    main "$@"
fi
