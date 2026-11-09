#!/usr/bin/env bash

###########################################
#             Usage:
#             ./levo_aigateway.sh start
#             ./levo_aigateway.sh stop
#             ./levo_aigateway.sh restart
#             ./levo_aigateway.sh upgrade
#             ./levo_aigateway.sh host-ip
#             ./levo_aigateway.sh get-logs
############################################
#
# Runs the `prod` profile of the docker-compose.yml next to this script. Its
# one job beyond `docker compose` is working out the host machine's IP before
# the container starts, so the gateway's health heartbeat can report it as
# upstream_ip: from inside a container only the container's own address is
# visible. Modelled on the satellite's levo_satellite.sh (layer9 PR #1798).
#
# Configuration comes from the shell environment or the .env file next to
# docker-compose.yml. This script never reads .env itself: it asks Compose for
# the environment it would give the gateway, so .env syntax (quotes, comments,
# interpolation) and shell-over-.env precedence are exactly Compose's.

set -Eeuo pipefail
export LC_ALL=C
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
COMPOSE_FILE="$DIR/docker-compose.yml"
GATEWAY_SERVICE="agentgateway-prod"
# Test hook: lets the test suite exercise the macOS branch on Linux.
HOST_OS="${_LEVOAI_TEST_OSTYPE:-$OSTYPE}"

compose() {
    docker compose -f "$COMPOSE_FILE" --profile prod "$@"
}

# The gateway service's resolved environment, one KEY=value per line. Fatal if
# Compose cannot read the project: nothing else would work either.
GATEWAY_ENV=""
load_gateway_env() {
    if ! GATEWAY_ENV=$(compose config --format json | gateway_env_from_json); then
        echo "Error: docker compose could not read $COMPOSE_FILE."
        exit 1
    fi
}

# Reads `docker compose config --format json` on stdin and prints the
# $GATEWAY_SERVICE environment as KEY=value lines. Values Compose leaves unset
# (null) are skipped. Kept to what this script needs - string values without
# escaped quotes, which is every IP and URL - rather than a JSON parser.
gateway_env_from_json() {
    tr -d '\n' \
        | grep -oE "\"$GATEWAY_SERVICE\"[[:space:]]*:[[:space:]]*\\{.*" \
        | grep -oE '"environment"[[:space:]]*:[[:space:]]*\{[^}]*\}' \
        | head -n 1 \
        | grep -oE '"[A-Za-z_][A-Za-z0-9_]*"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | sed -E 's/^"([^"]*)"[[:space:]]*:[[:space:]]*"(.*)"$/\1=\2/' \
        || true
}

# Value Compose gives the gateway for $1, or nothing.
config_value() {
    printf '%s\n' "$GATEWAY_ENV" | sed -n "s/^$1=//p" | head -n 1
}

# Dotted-quad IPv4 as Rust's Ipv4Addr parses it: four decimal octets 0-255,
# no leading zeros (Rust rejects "01.2.3.4"; inet_aton would read it as octal).
is_ipv4() {
    [[ "$1" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || return 1
    local i
    for i in 1 2 3 4; do
        [ "${BASH_REMATCH[$i]}" -le 255 ] || return 1
    done
}

# IPv6 as Rust's Ipv6Addr parses it: eight groups of 1-4 hex digits, at most
# one "::" standing for one or more zero groups, optionally ending in a
# dotted-quad IPv4 that counts as two groups.
is_ipv6() {
    local ip="$1"
    [[ "$ip" == *:* && "$ip" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
    if [[ "$ip" == *.* ]]; then
        is_ipv4 "${ip##*:}" || return 1
        ip="${ip%:*}:0:0"
    fi
    case "$ip" in *:::*) return 1 ;; esac
    if [[ "$ip" == :* && "$ip" != ::* ]] || [[ "$ip" == *: && "$ip" != *:: ]]; then
        return 1
    fi
    local compressed=0
    if [[ "$ip" == *::* ]]; then
        [[ "${ip#*::}" == *::* ]] && return 1
        compressed=1
    fi
    local groups=0 part
    local -a parts
    IFS=: read -ra parts <<< "$ip"
    for part in "${parts[@]}"; do
        [ -n "$part" ] || continue
        [[ "$part" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
        groups=$((groups + 1))
    done
    if [ "$compressed" -eq 1 ]; then
        [ "$groups" -le 7 ]
    else
        [ "$groups" -eq 8 ]
    fi
}

# Whether $1 is something the gateway would accept as the host IP: a valid
# IPv4 or IPv6 literal that is not loopback or unspecified. The gateway ignores
# anything else, so passing it on would only hide detection.
usable_host_ip() {
    if is_ipv4 "$1"; then
        case "$1" in 127.*|0.0.0.0) return 1 ;; esac
        return 0
    fi
    if is_ipv6 "$1"; then
        case "$1" in ::1|::|0:0:0:0:0:0:0:1|0:0:0:0:0:0:0:0) return 1 ;; esac
        return 0
    fi
    return 1
}

# Host part of LEVOAI_BASE_URL, the onprem-api endpoint the heartbeat posts
# to. Lowercased because URL hostnames are case-insensitive. tr rather than
# ${host,,}: macOS ships bash 3.2.
levo_api_host() {
    local host
    host="$(config_value LEVOAI_BASE_URL)"
    [ -n "$host" ] || host="$(config_value LEVO_SAAS_URL)"
    [ -n "$host" ] || return 0
    host="${host#*://}"     # strip scheme
    host="${host%%/*}"      # strip path
    case "$host" in
        \[*) host="${host#\[}"; host="${host%%\]*}" ;;  # [v6-literal]:port
        *) host="${host%%:*}" ;;                         # name-or-v4:port
    esac
    printf '%s\n' "$host" | tr '[:upper:]' '[:lower:]'
}

# Seconds each host-IP lookup may take. Name resolution can block for as long
# as a stalled DNS backend likes, and host-IP reporting is optional, so a slow
# lookup must never hold up start/upgrade - it just leaves the host IP unset.
HOST_IP_LOOKUP_TIMEOUT_SECS=2

# Prints the stdout of "$@", killing it after HOST_IP_LOOKUP_TIMEOUT_SECS.
# Always succeeds. Hand-rolled because GNU timeout(1) is not on macOS.
run_with_deadline() {
    local out pid
    local ticks=0
    out=$(mktemp)
    "$@" > "$out" 2> /dev/null &
    pid=$!
    while kill -0 "$pid" 2> /dev/null; do
        if [ "$ticks" -ge $((HOST_IP_LOOKUP_TIMEOUT_SECS * 10)) ]; then
            kill -9 "$pid" 2> /dev/null || true
            break
        fi
        sleep 0.1
        ticks=$((ticks + 1))
    done
    wait "$pid" 2> /dev/null || true
    cat "$out"
    rm -f "$out"
}

# Source address the kernel would use to reach the IP address $1, or nothing
# if unroutable.
route_src_ip() {
    ip route get "$1" 2>/dev/null \
        | awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }' || true
}

# Exports LEVOAI_HOST_IP for docker-compose.yml to pass into the container.
#
# A value the operator configured - exported, or in .env, as Compose resolves
# it - wins. It is exported explicitly rather than left to Compose, so it
# reaches the container whichever way the compose file names the variable.
# A configured value the gateway would reject is reported and replaced by
# detection.
#
# Otherwise it is the source address of the route to the Levo endpoint - the
# same answer the gateway's own probe gives outside a container, and what the
# satellite and the ebpf/pcap sensors report. Not the default route: on a
# split-route host the endpoint can sit behind a VPN or private NIC. Every
# resolved address is tried, so a dual-stack name falls back from an
# unroutable AAAA to its A record. If nothing is found the variable stays
# unset and the heartbeat omits the field; the gateway still starts.
set_host_ip() {
    load_gateway_env
    local configured
    configured=$(config_value LEVOAI_HOST_IP)
    if usable_host_ip "$configured"; then
        export LEVOAI_HOST_IP="$configured"
        echo "Host IP (configured): $LEVOAI_HOST_IP"
        return 0
    fi
    if [ -n "$configured" ]; then
        echo "Warning: ignoring LEVOAI_HOST_IP=$configured: not a usable IP address; detecting instead."
    fi
    # Empty, not unset: Compose would otherwise fall back to a bad value in
    # .env. The gateway reads an empty LEVOAI_HOST_IP as unset.
    export LEVOAI_HOST_IP=""

    local api_host candidates candidate
    local host_ip=""
    local iface=""
    api_host=$(levo_api_host)
    if [ -z "$api_host" ]; then
        echo "LEVOAI_BASE_URL is not set; skipping host IP detection (no heartbeat is sent without it)."
        return 0
    fi

    if command -v ip &> /dev/null && command -v getent &> /dev/null; then
        candidates=$(run_with_deadline getent ahosts "$api_host" | awk '!seen[$1]++ { print $1 }' || true)
        for candidate in $candidates; do
            host_ip=$(route_src_ip "$candidate")
            if [ -n "$host_ip" ]; then
                break
            fi
        done
    fi
    if [ -z "$host_ip" ] && [[ "$HOST_OS" == "darwin"* ]]; then
        iface=$(run_with_deadline route -n get "$api_host" | awk '/interface:/ { print $2 }' || true)
        if [ -n "$iface" ]; then
            host_ip=$(ipconfig getifaddr "$iface" 2>/dev/null || true)
        fi
    fi

    # An endpoint on localhost routes over loopback, which is never the host's
    # address; the gateway would reject it anyway.
    if usable_host_ip "$host_ip"; then
        export LEVOAI_HOST_IP="$host_ip"
        echo "Host IP: $LEVOAI_HOST_IP"
    else
        echo "Warning: could not detect the host IP; the gateway heartbeat will not report it."
        echo "Set LEVOAI_HOST_IP in $DIR/.env to report it anyway."
    fi
}

require_compose_file() {
    if [ ! -f "$COMPOSE_FILE" ]; then
        echo "Error: $COMPOSE_FILE not found. Keep this script next to docker-compose.yml."
        exit 1
    fi
}

start() {
    require_compose_file
    echo "Starting Levo AI Gateway..."
    set_host_ip
    compose up -d
    echo "Levo AI Gateway started."
}

stop() {
    require_compose_file
    echo "Stopping Levo AI Gateway..."
    compose stop
    echo "Levo AI Gateway stopped."
}

restart() {
    stop
    start
}

upgrade() {
    require_compose_file
    echo "Upgrading Levo AI Gateway..."
    # Before the pull: nothing optional may run between pulling and `up`.
    set_host_ip
    compose pull
    compose up -d --force-recreate
    echo "Levo AI Gateway upgraded."
}

# Prints what start would pass as LEVOAI_HOST_IP, without starting anything.
host-ip() {
    require_compose_file
    set_host_ip
}

get-logs() {
    require_compose_file
    if ! command -v docker &> /dev/null; then
        echo "Error: docker is not installed or not in PATH."
        exit 1
    fi
    if ! docker info > /dev/null 2>&1; then
        echo "Error: the Docker daemon is not running."
        exit 1
    fi

    local temp_dir tar_file service
    temp_dir=$(mktemp -d)
    for service in $(compose ps --services); do
        echo "Collecting logs for $service"
        compose logs --no-color "$service" > "$temp_dir/$service.log" 2>&1 || true
    done
    tar_file="/tmp/aigateway_logs_$(date +%Y_%m_%d_%H_%M_%S).tar.gz"
    tar -czf "$tar_file" -C "$temp_dir" .
    rm -rf "$temp_dir"
    echo "Logs archived at $tar_file"
}

usage() {
    echo "Usage: $0 {start|stop|restart|upgrade|host-ip|get-logs}"
}

case "${1:-}" in
    start|stop|restart|upgrade|host-ip|get-logs) "$1" ;;
    *) usage; exit 1 ;;
esac
