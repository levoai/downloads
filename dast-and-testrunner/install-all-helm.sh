#!/usr/bin/env bash

###########################################
#             Usage:
#             ./install-all-helm.sh [install] [options]
#             ./install-all-helm.sh scale  [--dast N] [--scheduled N] [--testrunner M] [options]
#             ./install-all-helm.sh status    [options]
#             ./install-all-helm.sh uninstall [options]
############################################
#
# Installs the Levo DAST workers AND the API test runner on a Kubernetes cluster with
# Helm. An on-prem DAST scan hands its post-crawl API tests to the test runner, so
# on-prem customers need both. This is the Kubernetes twin of install-all.sh (Docker).
#
# Charts come from https://charts.levo.ai. The script passes --repo to Helm, so your
# local `helm repo` list is not changed.
#
# The auth key is taken from LEVOAI_AUTH_KEY or prompted for, and is handed to Helm on
# stdin, so it never appears on a command line. (The charts themselves pass the key to the
# container as an argument, so anyone who can read the Deployment can read it. Restrict
# access to the namespace.)
#
# Written for bash 3.2 (the macOS default) as well as newer versions.

set -Eeuo pipefail
export LC_ALL=C

CHART_REPO="https://charts.levo.ai"
DEFAULT_BASE_URL="https://api.levo.ai"
INDIA_BASE_URL="https://api.india-1.levo.ai"
HARD_MAX=20
WAIT_TIMEOUT="5m"

# Helm release and chart names. Each release owns one Deployment of the same name, so two
# groups in one namespace would collide: use one namespace per group.
RELEASE_DAST="levoai-shadownet"
RELEASE_SCHEDULED="levoai-shadownet-scheduled"
RELEASE_TESTRUNNER="testrunner"
CHART_DAST="levoai-shadownet"
CHART_TESTRUNNER="testrunner"

usage() {
    cat <<EOF
Usage: $0 [install|scale|status|uninstall] [options]

Installs Levo DAST workers and the API test runner on Kubernetes with Helm.
Default command: install.

Commands:
  install    Install or upgrade the releases. Needs the auth key.
  scale      Change the number of pods of existing releases (keeps their other settings).
  status     Show releases and pods.
  uninstall  Remove the releases. A scan that is running is stopped.

Counts (install and scale):
  --dast N          DAST workers for on-demand scans. Default: 1
  --scheduled N     DAST workers for scheduled scans. Default: 0
  --testrunner M    API test runners. Default: 1
  A count of 0 installs nothing for that release (scale: sets it to 0 pods).

Options:
  --namespace NS      Namespace. Default: levoai
  --context CTX       kubectl/Helm context to use. Default: the current context.
  --org ID            Organization ID (or LEVOAI_ORG_ID).
  --group NAME        Group for DAST workers and test runners. Default: none.
  --region us|india   API URL (us = ${DEFAULT_BASE_URL}, india = ${INDIA_BASE_URL}).
  --base-url URL      A specific API URL (overrides --region).
  --workspace ID      Workspace ID (DAST health heartbeat; test runner registration).
  --image-tag TAG     DAST worker image tag. Default: the chart's.
  --testrunner-image-tag TAG   Test runner image tag. Default: the chart's.
  --dast-chart-version V       Pin the DAST chart version.
  --testrunner-chart-version V Pin the test runner chart version.
  --dry-run           Ask Helm to validate everything without installing.
  --no-wait           Do not wait for the pods to start.
  --yes               Do not ask to confirm the cluster.
  -h, --help          Show this help.

Environment: LEVOAI_AUTH_KEY (prompted for if unset), LEVOAI_ORG_ID, LEVOAI_BASE_URL,
LEVOAI_WORKSPACE_ID.
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

need_value() {
    [ "$2" -ge 2 ] || die "$1 needs a value"
}

COMMAND="install"
if [ "$#" -gt 0 ]; then
    case "$1" in
        install | scale | status | uninstall)
            COMMAND="$1"
            shift
            ;;
    esac
fi

DAST=""
SCHEDULED=""
TESTRUNNER=""
NAMESPACE="levoai"
CONTEXT=""
ORG="${LEVOAI_ORG_ID:-}"
GROUP=""
BASE_URL="${LEVOAI_BASE_URL:-}"
REGION=""
WORKSPACE="${LEVOAI_WORKSPACE_ID:-}"
IMAGE_TAG=""
TESTRUNNER_IMAGE_TAG=""
DAST_CHART_VERSION=""
TESTRUNNER_CHART_VERSION=""
DRY_RUN="false"
WAIT="true"
ASSUME_YES="false"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dast) need_value "$1" "$#"; DAST="$2"; shift 2 ;;
        --scheduled) need_value "$1" "$#"; SCHEDULED="$2"; shift 2 ;;
        --testrunner) need_value "$1" "$#"; TESTRUNNER="$2"; shift 2 ;;
        --namespace) need_value "$1" "$#"; NAMESPACE="$2"; shift 2 ;;
        --context) need_value "$1" "$#"; CONTEXT="$2"; shift 2 ;;
        --org) need_value "$1" "$#"; ORG="$2"; shift 2 ;;
        --group) need_value "$1" "$#"; GROUP="$2"; shift 2 ;;
        --region) need_value "$1" "$#"; REGION="$2"; shift 2 ;;
        --base-url) need_value "$1" "$#"; BASE_URL="$2"; shift 2 ;;
        --workspace) need_value "$1" "$#"; WORKSPACE="$2"; shift 2 ;;
        --image-tag) need_value "$1" "$#"; IMAGE_TAG="$2"; shift 2 ;;
        --testrunner-image-tag) need_value "$1" "$#"; TESTRUNNER_IMAGE_TAG="$2"; shift 2 ;;
        --dast-chart-version) need_value "$1" "$#"; DAST_CHART_VERSION="$2"; shift 2 ;;
        --testrunner-chart-version) need_value "$1" "$#"; TESTRUNNER_CHART_VERSION="$2"; shift 2 ;;
        --dry-run) DRY_RUN="true"; shift ;;
        --no-wait) WAIT="false"; shift ;;
        --yes | -y) ASSUME_YES="true"; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; die "Unknown option: $1" ;;
    esac
done

command -v helm >/dev/null 2>&1 || die "helm was not found. Install Helm 3 (https://helm.sh/docs/intro/install/) and try again."
command -v kubectl >/dev/null 2>&1 || die "kubectl was not found. Install it (https://kubernetes.io/docs/tasks/tools/) and try again."

KUBE_ARGS=()
[ -z "$CONTEXT" ] || KUBE_ARGS+=(--kube-context "$CONTEXT")
KUBECTL_ARGS=()
[ -z "$CONTEXT" ] || KUBECTL_ARGS+=(--context "$CONTEXT")

hlm() {
    helm ${KUBE_ARGS[@]+"${KUBE_ARGS[@]}"} "$@"
}

kc() {
    kubectl ${KUBECTL_ARGS[@]+"${KUBECTL_ARGS[@]}"} "$@"
}

ACTIVE_CONTEXT="${CONTEXT:-$(kubectl config current-context 2>/dev/null || true)}"
[ -n "$ACTIVE_CONTEXT" ] || die "No Kubernetes context is set. Point kubectl at your cluster, or pass --context."
kc cluster-info >/dev/null 2>&1 || die "Cannot reach the cluster for context '$ACTIVE_CONTEXT'. Check your kubeconfig and network."

confirm_cluster() {
    echo "Cluster: $ACTIVE_CONTEXT   Namespace: $NAMESPACE"
    [ "$ASSUME_YES" = "true" ] && return 0
    [ -t 0 ] || die "Not a terminal, so I cannot ask. Re-run with --yes to confirm the cluster above."
    printf 'Continue on this cluster? [y/N] ' >&2
    local answer
    read -r answer
    case "$answer" in
        y | Y | yes | YES) ;;
        *) die "Cancelled." ;;
    esac
}

check_count() {
    case "$2" in
        '' | *[!0-9]*) die "$1 must be a whole number, got '$2'" ;;
    esac
    [ "$2" -le "$HARD_MAX" ] || die "$1 $2 is above the limit of $HARD_MAX. Use another cluster or namespace."
}

release_exists() {
    hlm status "$1" --namespace "$NAMESPACE" >/dev/null 2>&1
}

prompt_secret() {
    local value=""
    if [ -t 0 ]; then
        printf 'Levo auth key (input hidden): ' >&2
        read -r -s value
        printf '\n' >&2
    else
        die "LEVOAI_AUTH_KEY is not set. Export it and run again."
    fi
    [ -n "$value" ] || die "LEVOAI_AUTH_KEY cannot be empty."
    LEVOAI_AUTH_KEY="$value"
}

# Quotes a value as a YAML double-quoted scalar, so no character in it can change the YAML.
yaml_quote() {
    local escaped
    escaped="$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
    printf '"%s"' "$escaped"
}

# Every string value goes to Helm as YAML on stdin: the key stays off the command line, and group
# names with commas or spaces need no --set escaping.
# Registration-sensitive settings (group, workspace) are kept together in this block.
values_yaml() {
    local kind="$1"
    printf 'key: %s\n' "$(yaml_quote "$LEVOAI_AUTH_KEY")"
    printf 'orgId: %s\n' "$(yaml_quote "$ORG")"
    printf 'levoBaseUrl: %s\n' "$(yaml_quote "$BASE_URL")"
    [ -z "$GROUP" ] || printf 'group: %s\n' "$(yaml_quote "$GROUP")"
    if [ "$kind" = "dast" ]; then
        [ -z "$WORKSPACE" ] || printf 'extraEnv:\n  LEVOAI_WORKSPACE_ID: %s\n' "$(yaml_quote "$WORKSPACE")"
        [ -z "$IMAGE_TAG" ] || printf 'image:\n  tagOverride: %s\n' "$(yaml_quote "$IMAGE_TAG")"
    else
        [ -z "$WORKSPACE" ] || printf 'workspace: %s\n' "$(yaml_quote "$WORKSPACE")"
        [ -z "$TESTRUNNER_IMAGE_TAG" ] || printf 'image:\n  tag: %s\n' "$(yaml_quote "$TESTRUNNER_IMAGE_TAG")"
    fi
}

install_release() {
    local release="$1" chart="$2" count="$3" chart_version="$4" kind="$5"
    shift 5
    local extra_args=("$@")
    local version_args=()
    [ -z "$chart_version" ] || version_args+=(--version "$chart_version")
    local mode_args=()
    [ "$DRY_RUN" != "true" ] || mode_args+=(--dry-run)
    [ "$WAIT" != "true" ] || [ "$DRY_RUN" = "true" ] || mode_args+=(--wait --timeout "$WAIT_TIMEOUT")

    echo "Installing $release ($count pod(s)) ..."
    if [ "$DRY_RUN" = "true" ]; then
        # The rendered manifest contains the key, so only the result is shown.
        values_yaml "$kind" | hlm upgrade --install "$release" "$chart" --repo "$CHART_REPO" \
            --namespace "$NAMESPACE" --create-namespace -f - \
            ${version_args[@]+"${version_args[@]}"} ${extra_args[@]+"${extra_args[@]}"} \
            ${mode_args[@]+"${mode_args[@]}"} >/dev/null
        echo "  $release: dry run passed"
    else
        values_yaml "$kind" | hlm upgrade --install "$release" "$chart" --repo "$CHART_REPO" \
            --namespace "$NAMESPACE" --create-namespace -f - \
            ${version_args[@]+"${version_args[@]}"} ${extra_args[@]+"${extra_args[@]}"} \
            ${mode_args[@]+"${mode_args[@]}"} >/dev/null
    fi
}

cmd_install() {
    DAST="${DAST:-1}"
    SCHEDULED="${SCHEDULED:-0}"
    TESTRUNNER="${TESTRUNNER:-1}"
    check_count --dast "$DAST"
    check_count --scheduled "$SCHEDULED"
    check_count --testrunner "$TESTRUNNER"

    [ -n "$ORG" ] || {
        [ -t 0 ] || die "Organization ID is not set. Use --org or export LEVOAI_ORG_ID."
        printf 'Levo organization ID: ' >&2
        read -r ORG
        [ -n "$ORG" ] || die "Organization ID cannot be empty."
    }
    if [ -n "$REGION" ] && [ -z "$BASE_URL" ]; then
        case "$REGION" in
            us) BASE_URL="$DEFAULT_BASE_URL" ;;
            india) BASE_URL="$INDIA_BASE_URL" ;;
            *) die "--region must be 'us' or 'india'" ;;
        esac
    fi
    BASE_URL="${BASE_URL:-$DEFAULT_BASE_URL}"
    [ -n "${LEVOAI_AUTH_KEY:-}" ] || prompt_secret
    confirm_cluster

    if [ "$DAST" -gt 0 ]; then
        install_release "$RELEASE_DAST" "$CHART_DAST" "$DAST" "$DAST_CHART_VERSION" dast \
            --set "replicaCount=$DAST"
    fi
    if [ "$SCHEDULED" -gt 0 ]; then
        install_release "$RELEASE_SCHEDULED" "$CHART_DAST" "$SCHEDULED" "$DAST_CHART_VERSION" dast \
            --set "replicaCount=$SCHEDULED" --set scheduled=true
    fi
    if [ "$TESTRUNNER" -gt 0 ]; then
        install_release "$RELEASE_TESTRUNNER" "$CHART_TESTRUNNER" "$TESTRUNNER" "$TESTRUNNER_CHART_VERSION" runner \
            --set "replicaCount=$TESTRUNNER"
    fi

    [ "$DRY_RUN" = "true" ] || cmd_status
    echo
    echo "Manage it with this script:"
    echo "  $0 status --namespace $NAMESPACE"
    echo "  $0 scale --dast 4 --testrunner 2 --namespace $NAMESPACE"
    echo "  $0 uninstall --namespace $NAMESPACE"
}

# Each release owns one Deployment named like the release. kubectl scale leaves every other setting
# alone, so no chart version or key is needed. Re-running `install` sets the count in Helm again.
scale_release() {
    local release="$1" count="$2"
    release_exists "$release" || {
        [ "$count" -eq 0 ] || echo "  $release is not installed; run '$0 install' to add it."
        return 0
    }
    echo "Scaling $release to $count pod(s) ..."
    kc scale "deployment/$release" --namespace "$NAMESPACE" --replicas="$count" >/dev/null \
        || die "Could not scale $release."
}

cmd_scale() {
    [ -n "$DAST$SCHEDULED$TESTRUNNER" ] || die "Give at least one of --dast, --scheduled, --testrunner."
    [ -z "$DAST" ] || check_count --dast "$DAST"
    [ -z "$SCHEDULED" ] || check_count --scheduled "$SCHEDULED"
    [ -z "$TESTRUNNER" ] || check_count --testrunner "$TESTRUNNER"
    confirm_cluster
    echo "A pod that is mid-scan is stopped when the count is lowered."
    [ -z "$DAST" ] || scale_release "$RELEASE_DAST" "$DAST"
    [ -z "$SCHEDULED" ] || scale_release "$RELEASE_SCHEDULED" "$SCHEDULED"
    [ -z "$TESTRUNNER" ] || scale_release "$RELEASE_TESTRUNNER" "$TESTRUNNER"
    cmd_status
}

cmd_status() {
    echo
    echo "Releases in namespace $NAMESPACE (cluster $ACTIVE_CONTEXT):"
    local found="false" release
    for release in "$RELEASE_DAST" "$RELEASE_SCHEDULED" "$RELEASE_TESTRUNNER"; do
        if release_exists "$release"; then
            found="true"
            echo "  $release: $(hlm status "$release" --namespace "$NAMESPACE" -o json 2>/dev/null | sed -n 's/.*"status":"\([a-z-]*\)".*/\1/p' | head -n 1)"
        fi
    done
    [ "$found" = "true" ] || { echo "  (none)"; return 0; }
    echo
    kc get pods --namespace "$NAMESPACE" -l 'app in (levoai-shadownet,levoai-shadownet-scheduled,testrunner)' 2>/dev/null || true
}

cmd_uninstall() {
    confirm_cluster
    local release
    for release in "$RELEASE_DAST" "$RELEASE_SCHEDULED" "$RELEASE_TESTRUNNER"; do
        if release_exists "$release"; then
            echo "Removing $release ..."
            hlm uninstall "$release" --namespace "$NAMESPACE" >/dev/null
        fi
    done
    echo "Done. The namespace '$NAMESPACE' was left in place."
}

case "$COMMAND" in
    install) cmd_install ;;
    scale) cmd_scale ;;
    status) cmd_status ;;
    uninstall) cmd_uninstall ;;
esac
