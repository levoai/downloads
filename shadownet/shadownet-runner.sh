#!/usr/bin/env bash
#
# ShadowNet DAST Runner for Linux/macOS
#
# Installs Levo's ShadowNet DAST scanner from Levo's private PyPI (Google
# Artifact Registry) into a local virtual environment, installs the Playwright
# Chromium browser it drives, and runs scans. Scans run in HEADED mode by
# default so you can watch the browser while the scanner works. Handles:
#   - Python 3.12+ detection and validation (uses existing installation)
#   - Virtual environment creation/reuse (.shadownet-venv/bin, POSIX layout)
#   - ShadowNet installation from Google Artifact Registry
#   - Playwright Chromium installation
#   - Scan / crawl execution via `shadownet scan` / `shadownet crawl`
#
# Modelled on bitbucket/levo-cli-runner.sh. Written to be bash 3.2 compatible
# (macOS default bash).
#
# Commands: install | scan | crawl | login | version | help
#
# Secret handling: no secret (Levo auth key, GAR/PyPI credentials) is ever passed
# as a command-line argument, because argv is world-readable on Unix hosts via
# `ps` / /proc/<pid>/cmdline. Secrets travel through the environment or 0600 temp
# files instead. ShadowNet itself reads LEVOAI_AUTH_KEY / LEVOAI_ORG_ID from the
# environment, so no login shim is needed.
#
# Required environment variables (scan only):
#   LEVOAI_AUTH_KEY   Levo Auth key for authentication
#   LEVOAI_ORG_ID     Levo organization ID
#   (or an existing session from `shadownet login` / this script's `login`)
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
#   SHADOWNET_VERSION    Specific ShadowNet version (default: latest)
#   LEVOAI_BASE_URL      Custom Levo API URL
#   PYPI_INDEX_URL       Override default GAR index URL
#
# Examples:
#   ./shadownet-runner.sh install
#   ./shadownet-runner.sh scan --target-url https://app.example.com
#   ./shadownet-runner.sh scan --target-url https://app.example.com --headless
#   ./shadownet-runner.sh scan --config levo-dast.yml
#   ./shadownet-runner.sh scan --target-url https://app.example.com -- --max-pages 50 --fail-on high
#   ./shadownet-runner.sh crawl --target-url https://app.example.com
#   ./shadownet-runner.sh login
#   ./shadownet-runner.sh version

set -uo pipefail

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"

# Levo's private PyPI repository in Google Artifact Registry (shared with the
# levo CLI; shadownet is a separate package inside it).
# Change this single value if the repository is renamed.
GAR_REPO_NAME="pypi-levo"

# ============================================================================
# Defaults
# ============================================================================
COMMAND="help"
TARGET_URL=""
CONFIG_FILE=""
HEADED=true
WITH_DEPS=false
VENV_DIR=".shadownet-venv"
WORK_DIR="$PWD"
PASSTHRU=()   # extra args forwarded verbatim to shadownet (after `--`)

# Populated after arg parse
PYPI_INDEX_URL_DEFAULT="${PYPI_INDEX_URL:-https://us-python.pkg.dev/levoai/${GAR_REPO_NAME}/simple/}"
PYTHON_CMD=""
VENV_PATH=""
PIP_LOG_FILE=""
SA_KEY_PATH=""          # temp GAR service-account key (keyring auth)
PIP_CONFIG_PATH=""      # temp 0600 pip.conf holding legacy index creds
WHEEL_DIR=""            # temp dir holding the downloaded shadownet wheel

# Overridable for tests (default: uname -s).
RUNNER_OS="${SHADOWNET_RUNNER_OS:-$(uname -s 2>/dev/null || echo unknown)}"

# ============================================================================
# Cleanup / colors
# ============================================================================
# shellcheck disable=SC2329  # invoked indirectly via `trap cleanup EXIT`
cleanup() {
    # Remove any secret-bearing temp files we created.
    local f
    for f in "$SA_KEY_PATH" "$PIP_CONFIG_PATH"; do
        if [ -n "$f" ] && [ -f "$f" ]; then
            rm -f "$f" 2>/dev/null || true
        fi
    done
    if [ -n "$WHEEL_DIR" ] && [ -d "$WHEEL_DIR" ]; then
        rm -rf "$WHEEL_DIR" 2>/dev/null || true
    fi
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
    case "$1" in
        ''|-) return 1 ;;
        -*) case "${1#-}" in *[!0-9]*) return 1 ;; esac ;;
        *[!0-9]*) return 1 ;;
    esac
    return 0
}

# url_host <url> -> prints the host[:port] portion of a URL.
url_host() {
    local rest="${1#*://}"
    rest="${rest%%/*}"
    # Strip any user:pass@ prefix.
    printf '%s' "${rest##*@}"
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
    export VIRTUAL_ENV="$VENV_PATH"
    export PATH="$VENV_PATH/bin:$PATH"
    python -m pip install --upgrade pip setuptools wheel -q >/dev/null 2>&1 || true
    log "Virtual environment activated" Success
    return 0
}

# ============================================================================
# ShadowNet installation
# ============================================================================
install_shadownet() {
    log "Installing ShadowNet..."

    # Auth mode priority:
    #   1. LEVOAI_GAR_SA_KEY_B64 -> keyring helper (auto-refresh, no gcloud).
    #   2. PYPI_USERNAME/PYPI_PASSWORD -> credentials in a 0600 pip.conf (no argv leak).
    local index_url="$PYPI_INDEX_URL_DEFAULT"
    local index_host
    index_host="$(url_host "$index_url")"
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
        if ! python -m pip install --no-cache-dir keyrings.google-artifactregistry-auth >"$PIP_LOG_FILE" 2>&1; then
            log "Failed to install keyring helper. See $PIP_LOG_FILE" Error
            return 1
        fi
        log "Using GAR service account key via keyring helper" Success
    elif [ -n "${PYPI_USERNAME:-}" ]; then
        if [ -z "${PYPI_PASSWORD:-}" ]; then
            log "PYPI_PASSWORD is required when PYPI_USERNAME is set" Error
            return 1
        fi
        # Do NOT embed the token in --index-url (it would leak via process argv).
        # Write it to a 0600 pip.conf and reference it via PIP_CONFIG_FILE.
        used_pip_config=true
        local old_umask_pc scheme rest
        old_umask_pc="$(umask)"
        umask 077
        PIP_CONFIG_PATH="$(mktemp "${TMPDIR:-/tmp}/shadownet-pip-XXXXXX.conf")" || {
            umask "$old_umask_pc"
            log "Failed to create temp pip config" Error
            return 1
        }
        scheme="${index_url%%://*}"
        rest="${index_url#*://}"
        {
            printf '[global]\n'
            printf 'index-url = %s://%s:%s@%s\n' "$scheme" "${PYPI_USERNAME}" "${PYPI_PASSWORD}" "$rest"
        } > "$PIP_CONFIG_PATH"
        umask "$old_umask_pc"
        log "Using authenticated repository (credentials in 0600 pip.conf, not argv)"
    else
        log "No Artifact Registry credentials configured." Error
        log "Set ONE of the following before running install/scan:" Error
        log "  export LEVOAI_GAR_SA_KEY_B64='<base64 SA key>'   (recommended)" Error
        log "  -- or --" Error
        log "  export PYPI_USERNAME='oauth2accesstoken'; export PYPI_PASSWORD='<ya29 token>'" Error
        return 1
    fi

    # Package spec
    local package_spec="shadownet"
    if [ -n "${SHADOWNET_VERSION:-}" ]; then
        package_spec="shadownet==${SHADOWNET_VERSION}"
        log "Installing version: ${SHADOWNET_VERSION}"
    else
        log "Installing latest version"
    fi

    # Dependency-confusion guard: pip does not prefer --index-url over
    # --extra-index-url, so the `shadownet` requirement itself must only ever be
    # resolved against the private index. Step 1 downloads just the shadownet
    # wheel from there (--no-deps); step 2 installs that explicit file and lets
    # its dependencies resolve from public PyPI, where shadownet is never looked up.
    WHEEL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shadownet-wheel-XXXXXX")" || {
        log "Failed to create temp directory for the wheel" Error
        return 1
    }

    log "Fetching $package_spec from the private index (this can take a moment)..."
    local rc
    if [ "$used_gar_key" = true ]; then
        GOOGLE_APPLICATION_CREDENTIALS="$SA_KEY_PATH" python -m pip download --no-cache-dir \
            "$package_spec" --no-deps -d "$WHEEL_DIR" \
            --index-url "$index_url" \
            --trusted-host "$index_host" \
            >"$PIP_LOG_FILE" 2>&1
        rc=$?
    else
        PIP_CONFIG_FILE="$PIP_CONFIG_PATH" python -m pip download --no-cache-dir \
            "$package_spec" --no-deps -d "$WHEEL_DIR" \
            --trusted-host "$index_host" \
            >"$PIP_LOG_FILE" 2>&1
        rc=$?
    fi
    [ "$used_pip_config" = true ] || true
    if [ "$rc" -ne 0 ]; then
        log "pip download failed. See $PIP_LOG_FILE for details" Error
        cat "$PIP_LOG_FILE" >&2 || true
        return 1
    fi

    local wheel
    wheel="$(ls "$WHEEL_DIR"/shadownet-*.whl 2>/dev/null | head -n 1 || true)"
    if [ -z "$wheel" ]; then
        log "No shadownet wheel was downloaded to $WHEEL_DIR" Error
        return 1
    fi

    log "Installing $(basename "$wheel") and its dependencies (this can take a few minutes)..."
    # Plain pip: default (public) index, no private credentials needed or exposed.
    # Two passes: force-reinstall the wheel itself (a re-published dev build keeps
    # its version number, so a plain install would say "already satisfied"), then
    # a normal install to pull in any dependencies the new build added.
    if ! python -m pip install --no-cache-dir --force-reinstall --no-deps "$wheel" >>"$PIP_LOG_FILE" 2>&1 \
        || ! python -m pip install --no-cache-dir "$wheel" >>"$PIP_LOG_FILE" 2>&1; then
        log "pip install failed. See $PIP_LOG_FILE for details" Error
        cat "$PIP_LOG_FILE" >&2 || true
        return 1
    fi

    log "ShadowNet installed" Success
    return 0
}

install_browser() {
    # ShadowNet drives Chromium through Playwright. The browser is not bundled in
    # the wheel, so fetch it into Playwright's per-user cache (idempotent).
    log "Installing Playwright Chromium browser..."
    local -a pw_args
    pw_args=(install chromium)
    if [ "$WITH_DEPS" = true ]; then
        # Installs the OS shared libraries Chromium needs (Linux only; needs root/sudo).
        pw_args=(install --with-deps chromium)
    fi
    if ! python -m playwright "${pw_args[@]}"; then
        log "Playwright browser installation failed" Error
        if [ "$RUNNER_OS" = "Linux" ] && [ "$WITH_DEPS" != true ]; then
            log "On Linux, Chromium needs system libraries. Retry with: $SCRIPT_NAME install --with-deps (requires sudo)" Warning
        fi
        return 1
    fi
    log "Chromium installed" Success
    return 0
}

verify_installation() {
    log "Verifying installation..."
    if ! python -m pip show shadownet >/dev/null 2>&1; then
        log "shadownet package not found" Error
        return 1
    fi
    log "Installation verified" Success
    return 0
}

# Sets SHADOWNET_BIN array to the shadownet entrypoint.
set_shadownet_bin() {
    if [ -x "$VENV_PATH/bin/shadownet" ]; then
        SHADOWNET_BIN=("$VENV_PATH/bin/shadownet")
    else
        SHADOWNET_BIN=(python -m shadownet.cli.main)
    fi
}

ensure_installed() {
    find_python || return 1
    init_venv || return 1
    enter_venv || return 1
    if python -m pip show shadownet >/dev/null 2>&1; then
        log "ShadowNet already installed"
    else
        log "ShadowNet not found, installing..."
        install_shadownet || return 1
        verify_installation || return 1
        install_browser || return 1
    fi
    set_shadownet_bin
    return 0
}

# ============================================================================
# Scan / crawl
# ============================================================================
check_display() {
    # Headed mode needs a display. macOS always has one for a logged-in user;
    # on Linux require an X11 or Wayland session.
    [ "$HEADED" = true ] || return 0
    case "$RUNNER_OS" in
        Linux)
            if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
                log "Headed mode requires a graphical session, but neither DISPLAY nor WAYLAND_DISPLAY is set." Error
                log "Run this from a desktop session, or pass --headless." Error
                return 1
            fi
            ;;
    esac
    return 0
}

check_levo_credentials() {
    # `shadownet scan` needs a Levo session: either LEVOAI_AUTH_KEY + LEVOAI_ORG_ID in
    # the environment (it logs in on its own), or a saved session from `shadownet login`.
    if [ -n "${LEVOAI_AUTH_KEY:-}" ] && [ -n "${LEVOAI_ORG_ID:-}" ]; then
        return 0
    fi
    if [ -f "${HOME:-}/.config/configstore/levo.json" ]; then
        log "Using saved Levo session (~/.config/configstore/levo.json)"
        return 0
    fi
    log "Levo credentials are required for a scan." Error
    log "Set LEVOAI_AUTH_KEY and LEVOAI_ORG_ID in the environment, or run: $SCRIPT_NAME login" Error
    return 1
}

target_requirements() {
    if [ -z "$TARGET_URL" ] && [ -z "$CONFIG_FILE" ]; then
        log "Either --target-url or --config <levo-dast.yml> is required" Error
        return 1
    fi
    if [ -n "$TARGET_URL" ]; then
        case "$TARGET_URL" in
            http://*|https://*) ;;
            *) log "--target-url must start with http:// or https://" Error; return 1 ;;
        esac
    fi
    if [ -n "$CONFIG_FILE" ] && [ ! -f "$CONFIG_FILE" ]; then
        log "--config file not found: $CONFIG_FILE" Error
        return 1
    fi
    return 0
}

# build_shadownet_args <subcommand> -> fills SN_ARGS
build_shadownet_args() {
    local sub="$1"
    SN_ARGS=("$sub")
    if [ -n "$TARGET_URL" ]; then
        SN_ARGS+=("$TARGET_URL")
    fi
    if [ -n "$CONFIG_FILE" ]; then
        SN_ARGS+=(--config "$CONFIG_FILE")
    fi
    if [ "$sub" = "crawl" ]; then
        # The AI crawler needs an LLM key; the standard crawler is what headed
        # customers want to watch.
        SN_ARGS+=(--crawler-type standard)
    fi
    if [ "$HEADED" = true ]; then
        SN_ARGS+=(--no-headless)
    else
        SN_ARGS+=(--headless)
    fi
    if [ ${#PASSTHRU[@]} -gt 0 ]; then
        SN_ARGS+=("${PASSTHRU[@]}")
    fi
}

show_run_config() {
    local mode="headed (browser window visible)"
    [ "$HEADED" = true ] || mode="headless"
    printf "\n%bConfiguration:%b\n" "$C_CYAN" "$C_RESET"
    [ -n "$TARGET_URL" ]  && printf "  Target URL:   %s\n" "$TARGET_URL"
    [ -n "$CONFIG_FILE" ] && printf "  Config file:  %s\n" "$CONFIG_FILE"
    printf "  Browser:      %s\n" "$mode"
    printf "  Venv:         %s\n" "$VENV_PATH"
    if [ ${#PASSTHRU[@]} -gt 0 ]; then
        printf "  Extra args:   %s\n" "${PASSTHRU[*]}"
    fi
    printf "\n"
}

run_shadownet() {
    # run_shadownet <subcommand>
    build_shadownet_args "$1"
    if [ -n "${LEVOAI_BASE_URL:-}" ]; then
        export LEVOAI_BASE_URL
    fi
    log "Running: shadownet ${SN_ARGS[*]}"
    printf "\n"
    # Foreground, inheriting the terminal: shadownet renders a live progress UI
    # and, in headed mode, opens the browser window.
    "${SHADOWNET_BIN[@]}" "${SN_ARGS[@]}"
    return $?
}

# ============================================================================
# Commands
# ============================================================================
invoke_help() {
    banner "ShadowNet DAST Runner v$SCRIPT_VERSION"
    cat <<EOF
Usage: $SCRIPT_NAME <command> [options] [-- <extra shadownet args>]

Commands:
  install   Install or upgrade ShadowNet + Chromium in a virtual environment
  scan      Run a DAST security scan (auto-installs if needed)
  crawl     Discovery-only crawl, no security testing (auto-installs if needed)
  login     Log in to the Levo platform interactively (saves a session)
  version   Show installed ShadowNet version
  help      Show this help message

Options:
  --target-url <url>       Target URL to scan (required unless --config is given)
  --config <path>          Path to a levo-dast.yml (may supply target.url)
  --headed                 Show the browser window while scanning (default)
  --headless               Run the browser headless (for servers / CI)
  --with-deps              Also install Chromium's OS libraries (Linux, needs sudo)
  --venv-dir <string>      Virtual environment directory (default: .shadownet-venv)
  --work-dir <string>      Working directory (default: current directory)
  --                       Everything after this is passed to shadownet verbatim

Examples:
  $SCRIPT_NAME install
  $SCRIPT_NAME scan --target-url https://app.example.com
  $SCRIPT_NAME scan --target-url https://app.example.com --headless
  $SCRIPT_NAME scan --config levo-dast.yml
  $SCRIPT_NAME scan --target-url https://app.example.com -- --max-pages 50 --fail-on high
  $SCRIPT_NAME scan --target-url https://app.example.com -- --username admin --password secret
  $SCRIPT_NAME crawl --target-url https://app.example.com
  $SCRIPT_NAME login

Required environment variables (scan):
  LEVOAI_AUTH_KEY      Levo Auth Key      (or run '$SCRIPT_NAME login' once)
  LEVOAI_ORG_ID        Levo organization ID

Artifact Registry auth (pick ONE):
  LEVOAI_GAR_SA_KEY_B64            Base64 Google SA JSON key (recommended)
  PYPI_USERNAME + PYPI_PASSWORD    Legacy ya29.* token path

Optional environment variables:
  SHADOWNET_VERSION    Specific ShadowNet version (default: latest)
  LEVOAI_BASE_URL      Custom Levo API URL
  PYPI_INDEX_URL       Override default GAR index URL
EOF
    return 0
}

invoke_install() {
    # Always (re)installs: this is how a customer upgrades to a new release or
    # refreshes a re-published dev build. `scan`/`crawl` only install when missing.
    banner "Installing ShadowNet"
    find_python || return 1
    init_venv || return 1
    enter_venv || return 1
    install_shadownet || return 1
    verify_installation || return 1
    install_browser || return 1
    banner "ShadowNet installed successfully!"
    log "Next: export LEVOAI_AUTH_KEY / LEVOAI_ORG_ID, then run: $SCRIPT_NAME scan --target-url <url>"
    return 0
}

invoke_version() {
    find_python || return 1
    init_venv || return 1
    enter_venv || return 1
    set_shadownet_bin

    printf "\n%bShadowNet Version:%b\n" "$C_CYAN" "$C_RESET"

    local version_text=""
    version_text="$("${SHADOWNET_BIN[@]}" --version 2>/dev/null | tr -d '\r' | head -n 1)"
    case "$version_text" in
        *"Usage:"*|*"No such command"*) version_text="" ;;
    esac

    if [ -z "$version_text" ]; then
        version_text="$(python -m pip show shadownet 2>/dev/null | awk -F': ' '/^Version:/ {print $2; exit}')"
    fi

    if [ -n "$version_text" ]; then
        printf "  %s\n" "$version_text"
        return 0
    fi
    log "Could not determine ShadowNet version" Error
    return 1
}

invoke_login() {
    banner "Levo Login"
    ensure_installed || return 1
    "${SHADOWNET_BIN[@]}" login
    return $?
}

invoke_scan() {
    banner "ShadowNet DAST Scan"
    target_requirements || return 1
    check_display || return 1
    check_levo_credentials || return 1
    ensure_installed || return 1
    show_run_config
    run_shadownet scan
    local rc=$?
    if [ "$rc" -eq 0 ]; then
        log "Scan completed" Success
    else
        log "Scan exited with code $rc" Warning
    fi
    return "$rc"
}

invoke_crawl() {
    banner "ShadowNet Crawl (discovery only)"
    target_requirements || return 1
    check_display || return 1
    ensure_installed || return 1
    show_run_config
    run_shadownet crawl
    local rc=$?
    if [ "$rc" -eq 0 ]; then
        log "Crawl completed" Success
    else
        log "Crawl exited with code $rc" Warning
    fi
    return "$rc"
}

# ============================================================================
# Argument parsing
# ============================================================================
require_value() {
    # require_value <flag> <count-remaining> <value>
    # Guards against an option silently consuming the next option as its value.
    if [ "$2" -lt 2 ]; then
        log "Option $1 requires a value" Error
        exit 2
    fi
    case "$3" in
        -*)
            log "Option $1 requires a value, but got '$3' which looks like another option" Error
            exit 2
            ;;
    esac
    return 0
}

parse_args() {
    if [ $# -gt 0 ]; then
        case "$1" in
            install|scan|crawl|login|version|help) COMMAND="$1"; shift ;;
            -h|--help) COMMAND="help"; shift ;;
        esac
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            --target-url) require_value "$1" $# "${2:-}"; TARGET_URL="$2"; shift 2 ;;
            --config) require_value "$1" $# "${2:-}"; CONFIG_FILE="$2"; shift 2 ;;
            --venv-dir) require_value "$1" $# "${2:-}"; VENV_DIR="$2"; shift 2 ;;
            --work-dir) require_value "$1" $# "${2:-}"; WORK_DIR="$2"; shift 2 ;;
            --headed) HEADED=true; shift ;;
            --headless) HEADED=false; shift ;;
            --with-deps) WITH_DEPS=true; shift ;;
            -h|--help) COMMAND="help"; shift ;;
            --) shift; PASSTHRU=("$@"); break ;;
            *) log "Unknown option: $1 (use '--' before extra shadownet arguments)" Error; exit 2 ;;
        esac
    done
}

# ============================================================================
# Main
# ============================================================================
main() {
    parse_args "$@"

    if [ ! -d "$WORK_DIR" ]; then
        if ! mkdir -p "$WORK_DIR" 2>/dev/null; then
            log "--work-dir '$WORK_DIR' does not exist and could not be created" Error
            exit 2
        fi
    fi

    VENV_PATH="$WORK_DIR/$VENV_DIR"
    PIP_LOG_FILE="$WORK_DIR/shadownet-pip-install.log"

    local exit_code=0
    case "$COMMAND" in
        help)    invoke_help || exit_code=$? ;;
        install) invoke_install || exit_code=$? ;;
        version) invoke_version || exit_code=$? ;;
        login)   invoke_login || exit_code=$? ;;
        scan)    invoke_scan || exit_code=$? ;;
        crawl)   invoke_crawl || exit_code=$? ;;
        *)       invoke_help || exit_code=$? ;;
    esac
    exit "$exit_code"
}

# Run main only when executed directly, so the script can be `source`d by the test
# harness to unit-test individual functions without invoking the CLI.
if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    main "$@"
fi
