#!/usr/bin/env bash

###########################################
#             Usage:
#             ./install-all.sh [install] [--dast N] [--scheduled N] [--testrunner M] [--testrunner-scheduled M] [options]
#             ./install-all.sh scale     [--dast N] [--scheduled N] [--testrunner M] [--testrunner-scheduled M]
#             ./install-all.sh status
#             ./install-all.sh logs      [dast|scheduled|testrunner]
#             ./install-all.sh down
############################################
#
# Installs, resizes and removes the Levo DAST workers and the API test runner with
# Docker Compose. One scan, or one test run, runs per container, so the number of
# containers is the number of things that run in parallel.
#
# Run it from a folder that already holds docker-compose.yml, or anywhere else: install
# downloads that file into --dir first.
#
# The auth key is taken from LEVOAI_AUTH_KEY, from .env, or prompted for. It is never
# written to disk; the .env this script writes holds settings only.
#
# Written for bash 3.2 (the macOS default) as well as newer versions.

set -Eeuo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_DIR="levo-dast-testrunner"
RAW_BASE="${LEVO_DOWNLOADS_BASE:-https://raw.githubusercontent.com/levoai/downloads}"

# Both numbers are per host. The memory cap is derived from the host (see max_dast);
# the hard caps protect Levo's shared pollers when a typo asks for 500 containers.
HARD_MAX_DAST=20
HARD_MAX_TESTRUNNER=20
HEALTH_WAIT_SECONDS=180
SERVICE_DAST="dast-worker"
SERVICE_SCHEDULED="dast-worker-scheduled"
SERVICE_TESTRUNNER="testrunner"
SERVICE_TESTRUNNER_SCHEDULED="testrunner-scheduled"
CERT_DIR_IN_CONTAINER="/etc/shadownet/certs"
DEFAULT_BASE_URL="https://api.levo.ai"
INDIA_BASE_URL="https://api.india-1.levo.ai"

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  install  Install, or converge to, the requested workers and test runner. Default.
  scale    Change the number of running containers without restarting the others.
  status   Show what is running.
  logs     Follow logs. Optional: dast, scheduled, testrunner or testrunner-scheduled.
  down     Stop and remove everything this script started.

Counts (install and scale):
  --dast N          DAST workers for on-demand scans.
  --scheduled N     DAST workers for scheduled scans.
  --testrunner M    API test runners for on-demand test runs.
  --testrunner-scheduled M   API test runners for scheduled test runs.
  An omitted count is left as it is (scale), or taken from DAST_REPLICAS /
  DAST_SCHEDULED_REPLICAS / TESTRUNNER_REPLICAS / TESTRUNNER_SCHEDULED_REPLICAS in the
  environment or .env, else 1 / 0 / 1 / 0 (install).

Other options (install):
  --org ID            Organization ID (or LEVOAI_ORG_ID).
  --group NAME        Group for DAST workers and test runners (or RUNNER_GROUP).
  --region us|india   API URL.   --base-url URL   A specific API URL.
  --image-tag TAG     Image tag for both images. Default: stable
  --dir DIR           Install folder when docker-compose.yml is downloaded. Default: ./${DEFAULT_DIR}
  --ref REF           Branch or tag of levoai/downloads to download from. Default: main
  --ca-cert FILE      CA the DAST workers trust for Levo, Temporal and the browser
                      (internal CA, TLS-inspecting proxy). Copied into ./certs.
  --target-ca-cert FILE   CA for the target application only.
  --client-cert FILE --client-key FILE   Client certificate (mutual TLS) presented to the target.
  --force             Allow more DAST workers than the memory check suggests.
  --no-wait           Do not wait for the DAST workers to report healthy.
  -h, --help          Show this help.

Limits: at most ${HARD_MAX_DAST} DAST workers (per kind) and ${HARD_MAX_TESTRUNNER} test runners per host; --force lifts only
the memory-based DAST limit.
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

COMMAND="install"
if [ "$#" -gt 0 ]; then
    case "$1" in
        install | scale | status | logs | down)
            COMMAND="$1"
            shift
            ;;
        up)
            COMMAND="install"
            shift
            ;;
    esac
fi

DAST=""
SCHEDULED=""
TESTRUNNER=""
TESTRUNNER_SCHEDULED=""
CA_CERT=""
TARGET_CA_CERT=""
CLIENT_CERT=""
CLIENT_KEY=""
FORCE="false"
WAIT="true"
LOG_TARGET=""
ORG="${LEVOAI_ORG_ID:-}"
GROUP="${RUNNER_GROUP:-}"
BASE_URL="${LEVOAI_BASE_URL:-}"
REGION=""
IMAGE_TAG=""
INSTALL_DIR=""
REF="main"

need_value() {
    [ "$2" -ge 2 ] || die "$1 needs a value"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dast) need_value "$1" "$#"; DAST="$2"; shift 2 ;;
        --scheduled) need_value "$1" "$#"; SCHEDULED="$2"; shift 2 ;;
        --testrunner) need_value "$1" "$#"; TESTRUNNER="$2"; shift 2 ;;
        --testrunner-scheduled) need_value "$1" "$#"; TESTRUNNER_SCHEDULED="$2"; shift 2 ;;
        --ca-cert) need_value "$1" "$#"; CA_CERT="$2"; shift 2 ;;
        --target-ca-cert) need_value "$1" "$#"; TARGET_CA_CERT="$2"; shift 2 ;;
        --client-cert) need_value "$1" "$#"; CLIENT_CERT="$2"; shift 2 ;;
        --client-key) need_value "$1" "$#"; CLIENT_KEY="$2"; shift 2 ;;
        --org) need_value "$1" "$#"; ORG="$2"; shift 2 ;;
        --group) need_value "$1" "$#"; GROUP="$2"; shift 2 ;;
        --region) need_value "$1" "$#"; REGION="$2"; shift 2 ;;
        --base-url) need_value "$1" "$#"; BASE_URL="$2"; shift 2 ;;
        --image-tag) need_value "$1" "$#"; IMAGE_TAG="$2"; shift 2 ;;
        --dir) need_value "$1" "$#"; INSTALL_DIR="$2"; shift 2 ;;
        --ref) need_value "$1" "$#"; REF="$2"; shift 2 ;;
        --force) FORCE="true"; shift ;;
        --no-wait) WAIT="false"; shift ;;
        -h | --help) usage; exit 0 ;;
        dast | scheduled | testrunner | testrunner-scheduled)
            [ "$COMMAND" = "logs" ] || die "Unexpected argument: $1"
            LOG_TARGET="$1"
            shift
            ;;
        *) usage >&2; die "Unknown option: $1" ;;
    esac
done

fetch() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url"
    else
        die "Neither curl nor wget was found, so docker-compose.yml cannot be downloaded."
    fi
}

# The folder holding docker-compose.yml and .env: next to this script if it has the compose file,
# else --dir. Only install may download the file; the other commands need an existing install.
prepare_dir() {
    if [ -z "$INSTALL_DIR" ] && [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
        INSTALL_DIR="$SCRIPT_DIR"
    else
        INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_DIR}"
        if [ ! -f "$INSTALL_DIR/docker-compose.yml" ]; then
            [ "$COMMAND" = "install" ] || die "No install found in $INSTALL_DIR. Run this from the install folder, or pass --dir."
            mkdir -p "$INSTALL_DIR"
            echo "Downloading docker-compose.yml (ref: $REF) into $INSTALL_DIR ..."
            fetch "$RAW_BASE/$REF/dast/docker-compose.yml" "$INSTALL_DIR/docker-compose.yml.part" || die "Could not download docker-compose.yml. Check your network and that ref '$REF' exists."
            [ -s "$INSTALL_DIR/docker-compose.yml.part" ] || die "Downloaded docker-compose.yml is empty."
            grep -q '^name: levo-dast-testrunner' "$INSTALL_DIR/docker-compose.yml.part" || die "Downloaded docker-compose.yml is not the expected file."
            mv "$INSTALL_DIR/docker-compose.yml.part" "$INSTALL_DIR/docker-compose.yml"
        fi
    fi
    INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"
    # Keep a copy beside docker-compose.yml, so "Manage it from <folder>" works whatever folder the
    # script was first run from.
    if [ "$COMMAND" = "install" ] && [ ! -f "$INSTALL_DIR/install-all.sh" ] && [ -f "${BASH_SOURCE[0]}" ]; then
        cp "${BASH_SOURCE[0]}" "$INSTALL_DIR/install-all.sh" && chmod +x "$INSTALL_DIR/install-all.sh"
    fi
    cd "$INSTALL_DIR"
}

# The script changes into the install folder later, so certificate paths must not stay relative.
absolute() {
    case "$1" in
        '' | /*) printf '%s' "$1" ;;
        *) printf '%s/%s' "$PWD" "$1" ;;
    esac
}
CA_CERT="$(absolute "$CA_CERT")"
TARGET_CA_CERT="$(absolute "$TARGET_CA_CERT")"
CLIENT_CERT="$(absolute "$CLIENT_CERT")"
CLIENT_KEY="$(absolute "$CLIENT_KEY")"

require_docker() {
    command -v docker >/dev/null 2>&1 || die "docker was not found. Install Docker (https://docs.docker.com/get-docker/) and try again."
    docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start Docker Desktop (or the Docker service) and try again."
    docker compose version >/dev/null 2>&1 || die "Docker Compose v2 was not found ('docker compose'). Update Docker Desktop, or install the compose plugin."
    prepare_dir
}

# Settings only, no secrets: later runs read them, so the org, group and URL need not be typed
# again. An existing .env is never overwritten.
write_env() {
    local dast="$1" scheduled="$2" testrunner="$3" testrunner_scheduled="$4"
    if [ -f .env ]; then
        echo "Keeping the existing $INSTALL_DIR/.env. Options given now apply to this run only; edit .env to make them permanent."
        return
    fi
    (
        umask 077
        {
            echo "# Written by install-all.sh. Settings only: the auth key is never stored here."
            echo "LEVOAI_ORG_ID=$LEVOAI_ORG_ID"
            echo "LEVOAI_BASE_URL=${LEVOAI_BASE_URL:-$DEFAULT_BASE_URL}"
            echo "DAST_REPLICAS=$dast"
            echo "DAST_SCHEDULED_REPLICAS=$scheduled"
            echo "TESTRUNNER_REPLICAS=$testrunner"
            echo "TESTRUNNER_SCHEDULED_REPLICAS=$testrunner_scheduled"
            [ -z "$GROUP" ] || echo "RUNNER_GROUP=$GROUP"
            [ -z "$IMAGE_TAG" ] || echo "DAST_IMAGE_TAG=$IMAGE_TAG"
            [ -z "$IMAGE_TAG" ] || echo "TESTRUNNER_IMAGE_TAG=$IMAGE_TAG"
            [ -z "${LEVOAI_CA_CERT:-}" ] || echo "LEVOAI_CA_CERT=$LEVOAI_CA_CERT"
            [ -z "${CA_CERT_PATH:-}" ] || echo "CA_CERT_PATH=$CA_CERT_PATH"
            [ -z "${CLIENT_CERT_PATH:-}" ] || echo "CLIENT_CERT_PATH=$CLIENT_CERT_PATH"
            [ -z "${CLIENT_KEY_PATH:-}" ] || echo "CLIENT_KEY_PATH=$CLIENT_KEY_PATH"
        } >.env
    )
}

# Environment first, then .env, so a count set in either place is honoured.
env_get() {
    local value="${!1:-}"
    if [ -z "$value" ] && [ -f .env ]; then
        value="$(grep -E "^$1=" .env | tail -n 1 | cut -d= -f2- | tr -d '\r' || true)"
    fi
    printf '%s' "$value"
}

dc() {
    docker compose --profile dast --profile scheduled --profile api-testing --profile api-testing-scheduled "$@"
}

running_count() {
    local n
    n="$(dc ps -q --status running "$1" 2>/dev/null | grep -c . || true)"
    printf '%s' "${n:-0}"
}

require_number() {
    case "$2" in
        '' | *[!0-9]*) die "$1 must be a whole number, got '$2'" ;;
    esac
}

# Reads the per-replica memory limit, like "2g" or "1536m", in MiB.
limit_mib() {
    case "$1" in
        *[gG]) echo $(( ${1%[gG]} * 1024 )) ;;
        *[mM]) echo "${1%[mM]}" ;;
        *) echo 2048 ;;
    esac
}

# Memory is what limits DAST workers: each is a headless Chromium. 1 GiB is left for the
# test runner and the host.
max_dast() {
    local mem_bytes mem_mib per_mib fits
    mem_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
    mem_mib=$(( mem_bytes / 1024 / 1024 ))
    per_mib="$(limit_mib "$(env_get DAST_MEMORY_LIMIT)")"
    [ "$per_mib" -gt 0 ] || per_mib=2048
    fits=$(( (mem_mib - 1024) / per_mib ))
    [ "$fits" -ge 1 ] || fits=1
    echo "$fits"
}

prompt_secret() {
    local var="$1" label="$2" value=""
    if [ -t 0 ]; then
        printf '%s: ' "$label" >&2
        read -r -s value
        printf '\n' >&2
    else
        die "$var is not set. Export it, put it in .env, or run this from a terminal."
    fi
    [ -n "$value" ] || die "$var cannot be empty."
    export "$var=$value"
}

# down, status and logs never use the key, but compose still insists the variables exist.
placeholder_credentials() {
    : "${LEVOAI_AUTH_KEY:=unused}"
    : "${LEVOAI_ORG_ID:=unused}"
    export LEVOAI_AUTH_KEY LEVOAI_ORG_ID
}

export_settings() {
    if [ -z "$(env_get LEVOAI_AUTH_KEY)" ]; then
        prompt_secret LEVOAI_AUTH_KEY "Levo auth key (input hidden)"
    else
        LEVOAI_AUTH_KEY="$(env_get LEVOAI_AUTH_KEY)"
        export LEVOAI_AUTH_KEY
    fi
    [ -n "$ORG" ] || ORG="$(env_get LEVOAI_ORG_ID)"
    if [ -z "$ORG" ]; then
        [ -t 0 ] || die "Organization ID is not set. Use --org, export LEVOAI_ORG_ID, or put it in .env."
        printf 'Levo organization ID: ' >&2
        read -r ORG
        [ -n "$ORG" ] || die "Organization ID cannot be empty."
    fi
    export LEVOAI_ORG_ID="$ORG"

    if [ -n "$REGION" ] && [ -z "$BASE_URL" ]; then
        case "$REGION" in
            us) BASE_URL="$DEFAULT_BASE_URL" ;;
            india) BASE_URL="$INDIA_BASE_URL" ;;
            *) die "--region must be 'us' or 'india'" ;;
        esac
    fi
    [ -z "$BASE_URL" ] || export LEVOAI_BASE_URL="$BASE_URL"
    if [ -n "$GROUP" ]; then
        export RUNNER_GROUP="$GROUP"
    fi
    if [ -n "$IMAGE_TAG" ]; then
        export DAST_IMAGE_TAG="$IMAGE_TAG" TESTRUNNER_IMAGE_TAG="$IMAGE_TAG"
    fi
}

# Copies a certificate file into ./certs and exports the variable that points the workers at it.
stage_cert() {
    local var="$1" src="$2" name
    [ -f "$src" ] || die "Certificate file not found: $src"
    name="$(basename "$src")"
    mkdir -p certs
    if [ ! -f "certs/$name" ] || ! cmp -s "$src" "certs/$name"; then
        cp "$src" "certs/$name"
    fi
    chmod 644 "certs/$name"
    export "$var=$CERT_DIR_IN_CONTAINER/$name"
}

stage_certs() {
    [ -z "$CLIENT_CERT$CLIENT_KEY" ] || { [ -n "$CLIENT_CERT" ] && [ -n "$CLIENT_KEY" ]; } || die "--client-cert and --client-key must be given together."
    [ -z "$CA_CERT" ] || stage_cert LEVOAI_CA_CERT "$CA_CERT"
    [ -z "$TARGET_CA_CERT" ] || stage_cert CA_CERT_PATH "$TARGET_CA_CERT"
    [ -z "$CLIENT_CERT" ] || stage_cert CLIENT_CERT_PATH "$CLIENT_CERT"
    [ -z "$CLIENT_KEY" ] || stage_cert CLIENT_KEY_PATH "$CLIENT_KEY"
}

resolve_count() {
    local explicit="$1" service="$2" env_name="$3" fallback="$4" value
    if [ -n "$explicit" ]; then
        printf '%s' "$explicit"
    elif [ "$COMMAND" = "scale" ]; then
        running_count "$service"
    else
        value="$(env_get "$env_name")"
        printf '%s' "${value:-$fallback}"
    fi
}

check_caps() {
    local dast="$1" scheduled="$2" testrunner="$3" testrunner_scheduled="$4" fits
    [ "$dast" -le "$HARD_MAX_DAST" ] || die "--dast $dast is above the limit of $HARD_MAX_DAST per host. Run another host instead."
    [ "$scheduled" -le "$HARD_MAX_DAST" ] || die "--scheduled $scheduled is above the limit of $HARD_MAX_DAST per host. Run another host instead."
    [ "$testrunner" -le "$HARD_MAX_TESTRUNNER" ] || die "--testrunner $testrunner is above the limit of $HARD_MAX_TESTRUNNER per host. Run another host instead."
    [ "$testrunner_scheduled" -le "$HARD_MAX_TESTRUNNER" ] || die "--testrunner-scheduled $testrunner_scheduled is above the limit of $HARD_MAX_TESTRUNNER per host. Run another host instead."
    fits="$(max_dast)"
    if [ $((dast + scheduled)) -gt "$fits" ] && [ "$FORCE" != "true" ]; then
        die "$((dast + scheduled)) DAST workers need about $(( (dast + scheduled) * $(limit_mib "$(env_get DAST_MEMORY_LIMIT)") / 1024 )) GiB, but Docker has memory for $fits. Lower the count, give Docker more memory, or add --force."
    fi
}

wait_healthy() {
    local waited=0 ids id state pending
    printf 'Waiting for DAST workers to become healthy'
    while [ "$waited" -lt "$HEALTH_WAIT_SECONDS" ]; do
        ids="$(dc ps -q "$SERVICE_DAST" "$SERVICE_SCHEDULED" 2>/dev/null || true)"
        pending=0
        for id in $ids; do
            state="$(docker inspect --format '{{if eq .State.Status "running"}}{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || echo missing)"
            case "$state" in
                healthy) ;;
                exited | dead | restarting | missing)
                    printf '\n'
                    die "A DAST worker keeps stopping. Run '$0 logs dast' to see why (a 401 means the auth key or organization ID is wrong)."
                    ;;
                *) pending=$((pending + 1)) ;;
            esac
        done
        [ "$pending" -eq 0 ] && break
        printf '.'
        sleep 3
        waited=$((waited + 3))
    done
    printf '\n'
    [ "$pending" -eq 0 ] || echo "Some DAST workers are still starting after ${HEALTH_WAIT_SECONDS}s. Check '$0 status'." >&2
}

summary() {
    echo
    echo "Running now:"
    echo "  DAST workers (on-demand): $(running_count "$SERVICE_DAST")"
    echo "  DAST workers (scheduled): $(running_count "$SERVICE_SCHEDULED")"
    echo "  API test runners:         $(running_count "$SERVICE_TESTRUNNER")"
    echo "  API test runners (sched.): $(running_count "$SERVICE_TESTRUNNER_SCHEDULED")"
}

cmd_apply() {
    # .env is read by Docker Compose, which treats these characters specially.
    case "$GROUP$IMAGE_TAG" in
        *[\$\#\"\'\\]*) die "--group and --image-tag cannot contain \$ # quotes or backslashes." ;;
    esac
    if [ "$COMMAND" = "scale" ] && [ -n "$CA_CERT$TARGET_CA_CERT$CLIENT_CERT$CLIENT_KEY" ]; then
        die "Certificate options apply to install only. Edit .env and run install again to change them."
    fi
    require_docker
    export_settings
    [ "$COMMAND" != "install" ] || stage_certs
    if docker container inspect levoai-shadownet-worker >/dev/null 2>&1; then
        echo "Note: a worker started by install-dast-proxy.sh (levoai-shadownet-worker) is also running on this host." >&2
    fi

    local dast scheduled testrunner testrunner_scheduled
    dast="$(resolve_count "$DAST" "$SERVICE_DAST" DAST_REPLICAS 1)"
    scheduled="$(resolve_count "$SCHEDULED" "$SERVICE_SCHEDULED" DAST_SCHEDULED_REPLICAS 0)"
    testrunner="$(resolve_count "$TESTRUNNER" "$SERVICE_TESTRUNNER" TESTRUNNER_REPLICAS 1)"
    require_number "--dast" "$dast"
    require_number "--scheduled" "$scheduled"
    testrunner_scheduled="$(resolve_count "$TESTRUNNER_SCHEDULED" "$SERVICE_TESTRUNNER_SCHEDULED" TESTRUNNER_SCHEDULED_REPLICAS 0)"
    require_number "--testrunner" "$testrunner"
    require_number "--testrunner-scheduled" "$testrunner_scheduled"
    check_caps "$dast" "$scheduled" "$testrunner" "$testrunner_scheduled"
    [ "$COMMAND" != "install" ] || write_env "$dast" "$scheduled" "$testrunner" "$testrunner_scheduled"

    if [ "$COMMAND" = "scale" ]; then
        echo "Scaling: DAST $(running_count "$SERVICE_DAST") -> $dast, scheduled $(running_count "$SERVICE_SCHEDULED") -> $scheduled, test runners $(running_count "$SERVICE_TESTRUNNER") -> $testrunner, scheduled test runners $(running_count "$SERVICE_TESTRUNNER_SCHEDULED") -> $testrunner_scheduled"
        echo "Removing a worker that is mid-scan lets it finish first (up to 5 minutes)."
    else
        echo "Starting: DAST $dast, scheduled $scheduled, test runners $testrunner, scheduled test runners $testrunner_scheduled"
    fi

    local recreate_args=()
    [ "$COMMAND" != "scale" ] || recreate_args+=(--no-recreate)

    dc up -d ${recreate_args[@]+"${recreate_args[@]}"} \
        --scale "$SERVICE_DAST=$dast" \
        --scale "$SERVICE_SCHEDULED=$scheduled" \
        --scale "$SERVICE_TESTRUNNER=$testrunner" \
        --scale "$SERVICE_TESTRUNNER_SCHEDULED=$testrunner_scheduled"

    if [ "$WAIT" = "true" ] && [ $((dast + scheduled)) -gt 0 ]; then
        wait_healthy
    fi
    summary
    if [ "$COMMAND" = "install" ]; then
        echo
        echo "Manage it from $INSTALL_DIR:"
        echo "  ./install-all.sh status"
        echo "  ./install-all.sh scale --dast 4 --testrunner 2"
        echo "  ./install-all.sh logs dast"
        echo "  ./install-all.sh down"
    fi
}

cmd_status() {
    require_docker
    placeholder_credentials
    dc ps
}

cmd_logs() {
    require_docker
    placeholder_credentials
    case "$LOG_TARGET" in
        dast) dc logs -f --tail 100 "$SERVICE_DAST" ;;
        scheduled) dc logs -f --tail 100 "$SERVICE_SCHEDULED" ;;
        testrunner) dc logs -f --tail 100 "$SERVICE_TESTRUNNER" ;;
        testrunner-scheduled) dc logs -f --tail 100 "$SERVICE_TESTRUNNER_SCHEDULED" ;;
        *) dc logs -f --tail 100 ;;
    esac
}

cmd_down() {
    require_docker
    placeholder_credentials
    echo "Stopping everything (a worker mid-scan is allowed up to 5 minutes to finish) ..."
    dc down
}

case "$COMMAND" in
    install | scale) cmd_apply ;;
    status) cmd_status ;;
    logs) cmd_logs ;;
    down) cmd_down ;;
esac
