#!/usr/bin/env bash

###########################################
#             Usage:
#             ./install-all.sh [options]
############################################
#
# Installs the Levo DAST worker(s) AND the API test runner on one Docker host.
# An on-prem DAST scan hands its post-crawl API tests to the test runner, so
# on-prem customers need both.
#
# Run it from a folder that already holds docker-compose.yml and scale.sh, or
# anywhere else: it downloads those two files into --dir first.
#
# The auth key is taken from LEVOAI_AUTH_KEY or prompted for. It is never written
# to disk; the .env this script writes holds settings only.
#
# Written for bash 3.2 (the macOS default) as well as newer versions.

set -Eeuo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_BASE_URL="https://api.levo.ai"
INDIA_BASE_URL="https://api.india-1.levo.ai"
DEFAULT_DIR="levo-dast-testrunner"
RAW_BASE="${LEVO_DOWNLOADS_BASE:-https://raw.githubusercontent.com/levoai/downloads}"

usage() {
    cat <<EOF
Usage: $0 [options]

Installs Levo DAST workers and the API test runner with Docker Compose.

Options:
  --dast N            DAST workers for on-demand scans. Default: 1
  --scheduled N       DAST workers for scheduled scans. Default: 0
  --testrunner M      API test runners. Default: 1
  --org ID            Organization ID (or LEVOAI_ORG_ID).
  --group NAME        Group for DAST workers and test runners. Default: none.
  --region us|india   API URL (us = ${DEFAULT_BASE_URL}, india = ${INDIA_BASE_URL}).
  --base-url URL      A specific API URL (overrides --region).
  --workspace ID      Workspace ID for the DAST health heartbeat.
  --image-tag TAG     Image tag for both images. Default: stable
  --dir DIR           Install folder when the files are downloaded. Default: ./${DEFAULT_DIR}
  --ref REF           Branch or tag of levoai/downloads to download from. Default: main
  --no-wait           Do not wait for the DAST workers to report healthy.
  -h, --help          Show this help.

Environment: LEVOAI_AUTH_KEY (prompted for if unset), LEVOAI_ORG_ID, LEVOAI_BASE_URL,
LEVOAI_WORKSPACE_ID.

Afterwards use ./scale.sh in the install folder to resize, check or remove everything.
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

need_value() {
    [ "$2" -ge 2 ] || die "$1 needs a value"
}

DAST="1"
SCHEDULED="0"
TESTRUNNER="1"
ORG="${LEVOAI_ORG_ID:-}"
GROUP=""
BASE_URL="${LEVOAI_BASE_URL:-}"
REGION=""
WORKSPACE="${LEVOAI_WORKSPACE_ID:-}"
IMAGE_TAG=""
INSTALL_DIR=""
REF="main"
WAIT_ARGS=()

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
        --dir) need_value "$1" "$#"; INSTALL_DIR="$2"; shift 2 ;;
        --ref) need_value "$1" "$#"; REF="$2"; shift 2 ;;
        --no-wait) WAIT_ARGS+=(--no-wait); shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; die "Unknown option: $1" ;;
    esac
done

for pair in "--dast:$DAST" "--scheduled:$SCHEDULED" "--testrunner:$TESTRUNNER"; do
    case "${pair#*:}" in
        '' | *[!0-9]*) die "${pair%%:*} must be a whole number, got '${pair#*:}'" ;;
    esac
done

# .env is read by Docker Compose, which treats these characters specially.
case "$GROUP$WORKSPACE$IMAGE_TAG" in
    *[\$\#\"\'\\]*) die "--group, --workspace and --image-tag cannot contain \$ # quotes or backslashes." ;;
esac

command -v docker >/dev/null 2>&1 || die "docker was not found. Install Docker (https://docs.docker.com/get-docker/) and try again."
docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start Docker Desktop (or the Docker service) and try again."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 was not found ('docker compose'). Update Docker Desktop, or install the compose plugin."

fetch() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url"
    else
        die "Neither curl nor wget was found, so the install files cannot be downloaded."
    fi
}

if [ -z "$INSTALL_DIR" ] && [ -f "$SCRIPT_DIR/docker-compose.yml" ] && [ -f "$SCRIPT_DIR/scale.sh" ]; then
    INSTALL_DIR="$SCRIPT_DIR"
    echo "Using the files in $INSTALL_DIR"
else
    INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_DIR}"
    mkdir -p "$INSTALL_DIR"
    echo "Downloading install files (ref: $REF) into $INSTALL_DIR ..."
    for f in docker-compose.yml scale.sh; do
        fetch "$RAW_BASE/$REF/dast-and-testrunner/$f" "$INSTALL_DIR/$f.part" || die "Could not download $f. Check your network and that ref '$REF' exists."
        [ -s "$INSTALL_DIR/$f.part" ] || die "Downloaded $f is empty."
        mv "$INSTALL_DIR/$f.part" "$INSTALL_DIR/$f"
    done
    grep -q '^name: levo-dast-testrunner' "$INSTALL_DIR/docker-compose.yml" || die "Downloaded docker-compose.yml is not the expected file."
    chmod +x "$INSTALL_DIR/scale.sh"
fi
INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"

if [ -z "$ORG" ]; then
    [ -t 0 ] || die "Organization ID is not set. Use --org or export LEVOAI_ORG_ID."
    printf 'Levo organization ID: ' >&2
    read -r ORG
    [ -n "$ORG" ] || die "Organization ID cannot be empty."
fi

if [ -n "$REGION" ] && [ -z "$BASE_URL" ]; then
    case "$REGION" in
        us) BASE_URL="$DEFAULT_BASE_URL" ;;
        india) BASE_URL="$INDIA_BASE_URL" ;;
        *) die "--region must be 'us' or 'india'" ;;
    esac
fi
BASE_URL="${BASE_URL:-$DEFAULT_BASE_URL}"

# Settings only, no secrets: later `./scale.sh` runs read them, so the org, group and URL need not
# be typed again. An existing .env is never overwritten.
if [ -f "$INSTALL_DIR/.env" ]; then
    echo "Keeping the existing $INSTALL_DIR/.env. Options given now apply to this run only; edit .env to make them permanent."
else
    (
        umask 077
        {
            echo "# Written by install-all.sh. Settings only: the auth key is never stored here."
            echo "LEVOAI_ORG_ID=$ORG"
            echo "LEVOAI_BASE_URL=$BASE_URL"
            echo "DAST_REPLICAS=$DAST"
            echo "DAST_SCHEDULED_REPLICAS=$SCHEDULED"
            echo "TESTRUNNER_REPLICAS=$TESTRUNNER"
            [ -z "$GROUP" ] || echo "DAST_GROUP=$GROUP"
            [ -z "$GROUP" ] || echo "TESTRUNNER_GROUP=$GROUP"
            [ -z "$WORKSPACE" ] || echo "LEVOAI_WORKSPACE_ID=$WORKSPACE"
            [ -z "$IMAGE_TAG" ] || echo "DAST_IMAGE_TAG=$IMAGE_TAG"
            [ -z "$IMAGE_TAG" ] || echo "TESTRUNNER_IMAGE_TAG=$IMAGE_TAG"
        } >"$INSTALL_DIR/.env"
    )
fi

up_args=(up --dast "$DAST" --scheduled "$SCHEDULED" --testrunner "$TESTRUNNER" --org "$ORG" --base-url "$BASE_URL")
[ -z "$GROUP" ] || up_args+=(--group "$GROUP")
[ -z "$WORKSPACE" ] || up_args+=(--workspace "$WORKSPACE")
[ -z "$IMAGE_TAG" ] || up_args+=(--image-tag "$IMAGE_TAG")

"$INSTALL_DIR/scale.sh" ${up_args[@]+"${up_args[@]}"} ${WAIT_ARGS[@]+"${WAIT_ARGS[@]}"}

echo
echo "Done. Manage it from $INSTALL_DIR:"
echo "  ./scale.sh status"
echo "  ./scale.sh scale --dast 4 --testrunner 2"
echo "  ./scale.sh logs dast"
echo "  ./scale.sh down"
