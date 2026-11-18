#!/usr/bin/env bash

###########################################
#             Usage:
#             ./scale.sh up     [--dast N] [--scheduled N] [--testrunner M] [options]
#             ./scale.sh scale  [--dast N] [--scheduled N] [--testrunner M]
#             ./scale.sh status
#             ./scale.sh logs   [dast|scheduled|testrunner]
#             ./scale.sh down
############################################
#
# Runs and resizes the Levo DAST workers and the API test runner with
# docker-compose.yml (next to this script). One scan, or one test run, runs per
# container, so the number of containers is the number of things that run in parallel.
#
# The auth key is taken from LEVOAI_AUTH_KEY, from .env, or prompted for.
#
# Written for bash 3.2 (the macOS default) as well as newer versions.

set -Eeuo pipefail
export LC_ALL=C

cd "$(dirname "${BASH_SOURCE[0]}")"

# Both numbers are per host. The memory cap is derived from the host (see max_dast);
# the hard caps protect Levo's shared pollers when a typo asks for 500 containers.
HARD_MAX_DAST=20
HARD_MAX_TESTRUNNER=20
HEALTH_WAIT_SECONDS=180
SERVICE_DAST="dast-worker"
SERVICE_SCHEDULED="dast-worker-scheduled"
SERVICE_TESTRUNNER="testrunner"
DEFAULT_BASE_URL="https://api.levo.ai"
INDIA_BASE_URL="https://api.india-1.levo.ai"

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  up       Start (or converge) the workers and test runner. Default.
  scale    Change the number of running containers without restarting the others.
  status   Show what is running.
  logs     Follow logs. Optional: dast, scheduled or testrunner.
  down     Stop and remove everything this script started.

Counts (up and scale):
  --dast N          DAST workers for on-demand scans.
  --scheduled N     DAST workers for scheduled scans.
  --testrunner M    API test runners.
  An omitted count is left as it is (scale), or taken from DAST_REPLICAS /
  DAST_SCHEDULED_REPLICAS / TESTRUNNER_REPLICAS in the environment or .env, else
  1 / 0 / 0 (up).

Other options (up):
  --org ID            Organization ID (or LEVOAI_ORG_ID).
  --group NAME        Group for DAST workers and test runners (or DAST_GROUP / TESTRUNNER_GROUP).
  --region us|india   API URL.   --base-url URL   A specific API URL.
  --workspace ID      Workspace ID for the DAST health heartbeat.
  --image-tag TAG     Image tag for both images. Default: stable
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

COMMAND="up"
if [ "$#" -gt 0 ]; then
    case "$1" in
        up | scale | status | logs | down)
            COMMAND="$1"
            shift
            ;;
    esac
fi

DAST=""
SCHEDULED=""
TESTRUNNER=""
FORCE="false"
WAIT="true"
LOG_TARGET=""
ORG="${LEVOAI_ORG_ID:-}"
GROUP=""
BASE_URL="${LEVOAI_BASE_URL:-}"
REGION=""
WORKSPACE="${LEVOAI_WORKSPACE_ID:-}"
IMAGE_TAG=""

need_value() {
    [ "$2" -ge 2 ] || die "$1 needs a value"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dast) need_value "$1" "$#"; DAST="$2"; shift 2 ;;
        --scheduled) need_value "$1" "$#"; SCHEDULED="$2"; shift 2 ;;
        --testrunner) need_value "$1" "$#"; TESTRUNNER="$2"; shift 2 ;;
        --org) need_value "$1" "$#"; ORG="$2"; shift 2 ;;
        --group) need_value "$1" "$#"; GROUP="$2"; shift 2 ;;
        --region) need_value "$1" "$#"; REGION="$2"; shift 2 ;;
        --base-url) need_value "$1" "$#"; BASE_URL="$2"; shift 2 ;;
        --workspace) need_value "$1" "$#"; WORKSPACE="$2"; shift 2 ;;
        --image-tag) need_value "$1" "$#"; IMAGE_TAG="$2"; shift 2 ;;
        --force) FORCE="true"; shift ;;
        --no-wait) WAIT="false"; shift ;;
        -h | --help) usage; exit 0 ;;
        dast | scheduled | testrunner)
            [ "$COMMAND" = "logs" ] || die "Unexpected argument: $1"
            LOG_TARGET="$1"
            shift
            ;;
        *) usage >&2; die "Unknown option: $1" ;;
    esac
done

require_docker() {
    command -v docker >/dev/null 2>&1 || die "docker was not found. Install Docker (https://docs.docker.com/get-docker/) and try again."
    docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start Docker Desktop (or the Docker service) and try again."
    docker compose version >/dev/null 2>&1 || die "Docker Compose v2 was not found ('docker compose'). Update Docker Desktop, or install the compose plugin."
    [ -f docker-compose.yml ] || die "docker-compose.yml was not found next to this script."
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
    docker compose --profile dast --profile scheduled --profile api-testing "$@"
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
    [ -z "$WORKSPACE" ] || export LEVOAI_WORKSPACE_ID="$WORKSPACE"
    if [ -n "$GROUP" ]; then
        export DAST_GROUP="$GROUP" TESTRUNNER_GROUP="$GROUP"
    fi
    if [ -n "$IMAGE_TAG" ]; then
        export DAST_IMAGE_TAG="$IMAGE_TAG" TESTRUNNER_IMAGE_TAG="$IMAGE_TAG"
    fi
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
    local dast="$1" scheduled="$2" testrunner="$3" fits
    [ "$dast" -le "$HARD_MAX_DAST" ] || die "--dast $dast is above the limit of $HARD_MAX_DAST per host. Run another host instead."
    [ "$scheduled" -le "$HARD_MAX_DAST" ] || die "--scheduled $scheduled is above the limit of $HARD_MAX_DAST per host. Run another host instead."
    [ "$testrunner" -le "$HARD_MAX_TESTRUNNER" ] || die "--testrunner $testrunner is above the limit of $HARD_MAX_TESTRUNNER per host. Run another host instead."
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
            state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || echo missing)"
            case "$state" in
                healthy) ;;
                exited | dead | missing)
                    printf '\n'
                    die "A DAST worker stopped right after starting. Run '$0 logs dast' to see why."
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
}

cmd_apply() {
    require_docker
    export_settings

    local dast scheduled testrunner
    dast="$(resolve_count "$DAST" "$SERVICE_DAST" DAST_REPLICAS 1)"
    scheduled="$(resolve_count "$SCHEDULED" "$SERVICE_SCHEDULED" DAST_SCHEDULED_REPLICAS 0)"
    testrunner="$(resolve_count "$TESTRUNNER" "$SERVICE_TESTRUNNER" TESTRUNNER_REPLICAS 0)"
    require_number "--dast" "$dast"
    require_number "--scheduled" "$scheduled"
    require_number "--testrunner" "$testrunner"
    check_caps "$dast" "$scheduled" "$testrunner"

    if [ "$COMMAND" = "scale" ]; then
        echo "Scaling: DAST $(running_count "$SERVICE_DAST") -> $dast, scheduled $(running_count "$SERVICE_SCHEDULED") -> $scheduled, test runners $(running_count "$SERVICE_TESTRUNNER") -> $testrunner"
        echo "Removing a worker that is mid-scan lets it finish first (up to 5 minutes)."
    else
        echo "Starting: DAST $dast, scheduled $scheduled, test runners $testrunner"
    fi

    local recreate_args=()
    [ "$COMMAND" != "scale" ] || recreate_args+=(--no-recreate)

    dc up -d ${recreate_args[@]+"${recreate_args[@]}"} \
        --scale "$SERVICE_DAST=$dast" \
        --scale "$SERVICE_SCHEDULED=$scheduled" \
        --scale "$SERVICE_TESTRUNNER=$testrunner"

    if [ "$WAIT" = "true" ] && [ $((dast + scheduled)) -gt 0 ]; then
        wait_healthy
    fi
    summary
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
    up | scale) cmd_apply ;;
    status) cmd_status ;;
    logs) cmd_logs ;;
    down) cmd_down ;;
esac
