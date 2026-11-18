#!/usr/bin/env bash

###########################################
#             Usage:
#             ./install-shadownet.sh [install] [options]
#             ./install-shadownet.sh status  [--group G] [--scheduled]
#             ./install-shadownet.sh logs    [--group G] [--scheduled]
#             ./install-shadownet.sh stop    [--group G] [--scheduled] [--name N]
############################################
#
# Starts ONE Levo DAST worker (levoai/levoai-shadownet) in Docker. To run several
# workers, or the API test runner next to it, use docker-compose.yml in this folder.
#
# The auth key is taken from LEVOAI_AUTH_KEY or prompted for, and is handed to
# Docker by name, so it never appears on a command line or in a file.
#
# Written for bash 3.2 (the macOS default) as well as newer versions.

set -Eeuo pipefail
export LC_ALL=C

IMAGE_REPO="levoai/levoai-shadownet"
DEFAULT_BASE_URL="https://api.levo.ai"
INDIA_BASE_URL="https://api.india-1.levo.ai"
# install-dast-proxy.sh names its container this; warn rather than run two workers by accident.
PROXY_SCRIPT_CONTAINER="levoai-shadownet-worker"
HEALTH_WAIT_SECONDS=120

usage() {
    cat <<EOF
Usage: $0 [install|status|logs|stop] [options]

Starts one Levo DAST worker in Docker. Default command: install.

Environment:
  LEVOAI_AUTH_KEY      Your Levo authentication key (prompted for if unset).
  LEVOAI_ORG_ID        Your Levo organization ID (prompted for if unset).
  LEVOAI_BASE_URL      Levo API URL. Default: ${DEFAULT_BASE_URL}
  LEVOAI_WORKSPACE_ID  (Optional) Workspace for the health heartbeat.
  LEVOAI_GROUP         Same as --group.

Options:
  --org ID             Organization ID.
  --group NAME         Join a worker group. Used exactly as typed (case-sensitive).
  --scheduled          Take scheduled scans only (default: on-demand scans).
  --region us|india    Pick the API URL (us = ${DEFAULT_BASE_URL}, india = ${INDIA_BASE_URL}).
  --base-url URL       Use a specific API URL (overrides --region).
  --workspace ID       Workspace ID for the health heartbeat.
  --image-tag TAG      Image tag. Default: stable
  --name NAME          Container name. Default: levoai-shadownet[-GROUP][-scheduled]
  --no-pull            Use the local image instead of pulling.
  --no-wait            Do not wait for the worker to report healthy.
  -h, --help           Show this help.
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

# Container names allow letters, digits, "_", "." and "-"; anything else in a group becomes "-".
slug() {
    printf '%s' "$1" | sed 's/[^A-Za-z0-9_.-]/-/g'
}

require_docker() {
    command -v docker >/dev/null 2>&1 || die "docker was not found. Install Docker (https://docs.docker.com/get-docker/) and try again."
    docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start Docker Desktop (or the Docker service) and try again."
}

COMMAND="install"
ORG="${LEVOAI_ORG_ID:-}"
GROUP="${LEVOAI_GROUP:-}"
SCHEDULED="false"
BASE_URL="${LEVOAI_BASE_URL:-}"
REGION=""
WORKSPACE="${LEVOAI_WORKSPACE_ID:-}"
IMAGE_TAG="stable"
NAME=""
PULL="true"
WAIT="true"

if [ "$#" -gt 0 ]; then
    case "$1" in
        install | status | logs | stop)
            COMMAND="$1"
            shift
            ;;
    esac
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --org) [ "$#" -ge 2 ] || die "--org needs a value"; ORG="$2"; shift 2 ;;
        --group) [ "$#" -ge 2 ] || die "--group needs a value"; GROUP="$2"; shift 2 ;;
        --scheduled) SCHEDULED="true"; shift ;;
        --region) [ "$#" -ge 2 ] || die "--region needs a value"; REGION="$2"; shift 2 ;;
        --base-url) [ "$#" -ge 2 ] || die "--base-url needs a value"; BASE_URL="$2"; shift 2 ;;
        --workspace) [ "$#" -ge 2 ] || die "--workspace needs a value"; WORKSPACE="$2"; shift 2 ;;
        --image-tag) [ "$#" -ge 2 ] || die "--image-tag needs a value"; IMAGE_TAG="$2"; shift 2 ;;
        --name) [ "$#" -ge 2 ] || die "--name needs a value"; NAME="$2"; shift 2 ;;
        --no-pull) PULL="false"; shift ;;
        --no-wait) WAIT="false"; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; die "Unknown option: $1" ;;
    esac
done

NAME_GIVEN="false"
[ -n "$NAME" ] && NAME_GIVEN="true"
if [ -z "$NAME" ]; then
    NAME="levoai-shadownet"
    [ -n "$GROUP" ] && NAME="${NAME}-$(slug "$GROUP")"
    [ "$SCHEDULED" = "true" ] && NAME="${NAME}-scheduled"
fi

if [ -n "$REGION" ] && [ -z "$BASE_URL" ]; then
    case "$REGION" in
        us) BASE_URL="$DEFAULT_BASE_URL" ;;
        india) BASE_URL="$INDIA_BASE_URL" ;;
        *) die "--region must be 'us' or 'india'" ;;
    esac
fi
BASE_URL="${BASE_URL:-$DEFAULT_BASE_URL}"

container_exists() {
    docker ps -a --filter "name=^/$1\$" --format '{{.Names}}' | grep -qx "$1"
}

health_of() {
    docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$1" 2>/dev/null || echo "missing"
}

prompt_secret() {
    local var="$1" label="$2" value=""
    if [ -t 0 ]; then
        printf '%s: ' "$label" >&2
        read -r -s value
        printf '\n' >&2
    else
        die "$var is not set. Export it and run again."
    fi
    [ -n "$value" ] || die "$var cannot be empty."
    export "$var=$value"
}

cmd_install() {
    require_docker

    if [ -z "${LEVOAI_AUTH_KEY:-}" ]; then
        prompt_secret LEVOAI_AUTH_KEY "Levo auth key (input hidden)"
    fi
    if [ -z "$ORG" ]; then
        [ -t 0 ] || die "Organization ID is not set. Use --org or export LEVOAI_ORG_ID."
        printf 'Levo organization ID: ' >&2
        read -r ORG
        [ -n "$ORG" ] || die "Organization ID cannot be empty."
    fi

    if container_exists "$NAME"; then
        die "A container named '$NAME' already exists. Run '$0 stop --name $NAME' first, or pick another with --name."
    fi
    if [ "$NAME" != "$PROXY_SCRIPT_CONTAINER" ] && container_exists "$PROXY_SCRIPT_CONTAINER"; then
        echo "Note: '$PROXY_SCRIPT_CONTAINER' (from install-dast-proxy.sh) is already running. This starts a second, separate worker." >&2
    fi

    local image="${IMAGE_REPO}:${IMAGE_TAG}"
    if [ "$PULL" = "true" ]; then
        echo "Pulling $image ..."
        docker pull "$image" >/dev/null
    fi

    # Values reach the container through the environment, by name, so the key stays off the command line.
    export LEVOAI_ORG_ID="$ORG" LEVOAI_BASE_URL="$BASE_URL"

    # Registration-sensitive settings (group, workspace) are kept together in this block.
    local identity_args=()
    if [ -n "$GROUP" ]; then identity_args+=(-e "LEVOAI_GROUP=$GROUP"); fi
    if [ -n "$WORKSPACE" ]; then identity_args+=(-e "LEVOAI_WORKSPACE_ID=$WORKSPACE"); fi
    local mode_args=()
    if [ "$SCHEDULED" = "true" ]; then mode_args+=(-e "SHADOWNET_SCHEDULED=true"); fi

    echo "Starting $NAME ..."
    echo "  Image:    $image"
    echo "  Org:      $ORG"
    echo "  API URL:  $BASE_URL"
    echo "  Group:    ${GROUP:-(none)}"
    echo "  Scans:    $([ "$SCHEDULED" = "true" ] && echo scheduled || echo on-demand)"

    docker run -d \
        --name "$NAME" \
        --restart unless-stopped \
        --shm-size=1g \
        --stop-timeout 300 \
        --stop-signal SIGINT \
        --security-opt no-new-privileges:true \
        -e LEVOAI_AUTH_KEY \
        -e LEVOAI_ORG_ID \
        -e LEVOAI_BASE_URL \
        ${identity_args[@]+"${identity_args[@]}"} \
        ${mode_args[@]+"${mode_args[@]}"} \
        "$image" worker >/dev/null

    if [ "$WAIT" = "true" ]; then
        printf 'Waiting for the worker to become healthy'
        local waited=0 state
        while [ "$waited" -lt "$HEALTH_WAIT_SECONDS" ]; do
            state="$(health_of "$NAME")"
            case "$state" in
                healthy) break ;;
                exited | dead | missing)
                    printf '\n'
                    docker logs --tail 20 "$NAME" 2>&1 || true
                    die "The worker stopped right after starting. See the log lines above."
                    ;;
            esac
            printf '.'
            sleep 3
            waited=$((waited + 3))
        done
        printf '\n'
        state="$(health_of "$NAME")"
        if [ "$state" != "healthy" ]; then
            echo "The worker is '$state' after ${HEALTH_WAIT_SECONDS}s. It may still be starting; check the logs below." >&2
        fi
    fi

    echo "'$NAME' started."
    echo "  Check it:  docker ps --filter name=$NAME"
    echo "  Logs:      docker logs -f $NAME"
    if [ "$NAME_GIVEN" = "true" ]; then
        echo "  Stop it:   $0 stop --name $NAME"
    else
        echo "  Stop it:   $0 stop$([ -n "$GROUP" ] && echo " --group '$GROUP'")$([ "$SCHEDULED" = "true" ] && echo " --scheduled")"
    fi
}

cmd_status() {
    require_docker
    container_exists "$NAME" || die "No container named '$NAME'."
    docker ps -a --filter "name=^/${NAME}\$" --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
}

cmd_logs() {
    require_docker
    container_exists "$NAME" || die "No container named '$NAME'."
    docker logs -f "$NAME"
}

cmd_stop() {
    require_docker
    if container_exists "$NAME"; then
        echo "Stopping $NAME (a running scan is allowed up to 5 minutes to finish) ..."
        docker stop "$NAME" >/dev/null
        docker rm "$NAME" >/dev/null
        echo "'$NAME' stopped and removed."
    else
        echo "No container named '$NAME'."
    fi
}

case "$COMMAND" in
    install) cmd_install ;;
    status) cmd_status ;;
    logs) cmd_logs ;;
    stop) cmd_stop ;;
esac
