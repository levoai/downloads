#!/usr/bin/env bash

CONTAINER_NAME="levoai-shadownet-worker"
IMAGE_REPO="levoai/levoai-shadownet"
# stable-proxy tracks the current stable release of the corporate-proxy image.
DEFAULT_SHADOWNET_VERSION="stable"
DEFAULT_LEVOAI_REGION="us"
US_LEVOAI_BASE_URL="https://api.levo.ai"
INDIA_LEVOAI_BASE_URL="https://api.india-1.levo.ai"
DEFAULT_NO_PROXY="localhost,127.0.0.1,::1"

# Function to load KEY=VALUE lines from the .env file, if present
load_env_file() {
  [[ -f .env ]] || return 0
  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*(#|$) || "$line" != *=* ]] && continue
    key="${line%%=*}"
    key="${key#export }"
    key="${key//[[:space:]]/}"
    value="${line#*=}"
    if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then
      value="${BASH_REMATCH[1]}"
    fi
    export "$key=$value"
  done < .env
}

# Function to display usage information
show_usage() {
  echo "Usage: $0 [start|stop]"
  echo ""
  echo "Arguments:"
  echo "  start       Start the $CONTAINER_NAME."
  echo "  stop        Stop and remove the $CONTAINER_NAME."
  echo "  --help, -h  Display this help message."
  echo ""
}

# Function to display the usage of the `start` option
show_start_usage() {
  echo "Usage: $0 start"
  echo ""
  echo "Starts the $CONTAINER_NAME with the provided environment variables."
  echo "Set the following in a .env file in the current directory, or export them:"
  echo "  LEVOAI_AUTH_KEY       Your Levo authentication key."
  echo "  LEVOAI_ORG_ID         Your Levo organization ID."
  echo "  UPSTREAM_HTTP_PROXY   Your corporate proxy, e.g. 'http://proxy.example.com:3128'."
  echo "  LEVOAI_REGION         (Optional) Your Levo region: 'us' or 'india'. Default is '${DEFAULT_LEVOAI_REGION}'."
  echo "  LEVOAI_BASE_URL       (Optional) Levo API URL. Overrides LEVOAI_REGION; only needed for"
  echo "                        a dedicated or on-prem deployment."
  echo "  SHADOWNET_VERSION     (Optional) Image version to run, e.g. '1.4.148'. Default is"
  echo "                        '${DEFAULT_SHADOWNET_VERSION}' (the ${IMAGE_REPO}:${DEFAULT_SHADOWNET_VERSION}-proxy image)."
  echo "  NO_PROXY              (Optional) Hosts to reach without the proxy. Default is '${DEFAULT_NO_PROXY}'."
  echo "  LEVOAI_ENV_ID         (Optional) Levo environment ID."
  echo ""
  echo "Example:"
  echo "  export LEVOAI_AUTH_KEY='your-auth-key'"
  echo "  export LEVOAI_ORG_ID='your-org-id'"
  echo "  export UPSTREAM_HTTP_PROXY='http://proxy_host:proxy_port'"
  echo "  $0 start"
}

# Function to check if an environment variable is set
check_env_var() {
  local var_name="$1"
  local var_value="${!var_name}"
  if [[ -z "$var_value" ]]; then
    echo "Error: Environment variable $var_name is not set."
    echo "Try setting the $var_name in the .env file."
    exit 1
  fi
}

# Function to resolve the Levo API URL from LEVOAI_BASE_URL or LEVOAI_REGION
resolve_base_url() {
  if [[ -n "$LEVOAI_BASE_URL" ]]; then
    echo "$LEVOAI_BASE_URL"
    return
  fi
  local region="${LEVOAI_REGION:-$DEFAULT_LEVOAI_REGION}"
  case "$(echo "$region" | tr '[:upper:]' '[:lower:]')" in
    us) echo "$US_LEVOAI_BASE_URL" ;;
    india|in|india-1) echo "$INDIA_LEVOAI_BASE_URL" ;;
    *)
      echo "Error: unknown LEVOAI_REGION '$region'. Use 'us' or 'india', or set LEVOAI_BASE_URL." >&2
      return 1
      ;;
  esac
}

# Function to pull the image, so a floating tag like stable-proxy picks up new releases
pull_image() {
  echo "Pulling $IMAGE_NAME..."
  if docker pull "$IMAGE_NAME"; then
    return
  fi
  if docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    echo "Warning: could not pull $IMAGE_NAME; starting the copy already on this host."
  else
    echo "Error: could not pull $IMAGE_NAME. Check the version in SHADOWNET_VERSION and that"
    echo "Docker can reach Docker Hub (configure the Docker daemon's proxy if it needs one)."
    exit 1
  fi
}

# Function to check if the container exists, running or stopped
container_exists() {
  docker container inspect "$CONTAINER_NAME" > /dev/null 2>&1
}

# Function to start the container
start_container() {
  load_env_file

  local version="${SHADOWNET_VERSION:-$DEFAULT_SHADOWNET_VERSION}"
  IMAGE_NAME="${IMAGE_REPO}:${version%-proxy}-proxy"

  # Check for required environment variables
  check_env_var "LEVOAI_AUTH_KEY"
  check_env_var "LEVOAI_ORG_ID"
  check_env_var "UPSTREAM_HTTP_PROXY"

  if container_exists; then
    echo "Error: a container named $CONTAINER_NAME already exists."
    echo "Run '$0 stop' to remove it, then start again."
    exit 1
  fi

  local base_url
  base_url="$(resolve_base_url)" || exit 1
  local no_proxy="${NO_PROXY:-$DEFAULT_NO_PROXY}"
  local env_id_args=()
  if [[ -n "$LEVOAI_ENV_ID" ]]; then
    env_id_args=(-e LEVOAI_ENV_ID="${LEVOAI_ENV_ID}")
  fi
  echo "LEVOAI_BASE_URL: $base_url"
  echo "LEVOAI_ENV_ID: ${LEVOAI_ENV_ID:-(not set)}"

  echo "Image: $IMAGE_NAME"

  pull_image

  echo "Starting the $CONTAINER_NAME..."

  # HTTP(S)_PROXY are not passed: the -proxy image points them at its bundled
  # tinyproxy, which chains to UPSTREAM_HTTP_PROXY.
  docker run -d \
    --name $CONTAINER_NAME \
    --restart unless-stopped \
    --shm-size=1g \
    --log-opt max-size=50m --log-opt max-file=5 \
    -e LEVOAI_AUTH_KEY="${LEVOAI_AUTH_KEY}" \
    -e LEVOAI_ORG_ID="${LEVOAI_ORG_ID}" \
    -e LEVOAI_BASE_URL="${base_url}" \
    "${env_id_args[@]}" \
    -e UPSTREAM_HTTP_PROXY="${UPSTREAM_HTTP_PROXY}" \
    -e NO_PROXY="${no_proxy}" \
    -e no_proxy="${no_proxy}" \
    "$IMAGE_NAME"

  if [[ $? -eq 0 ]]; then
    echo "'$CONTAINER_NAME' started successfully!"
    echo "You can view logs using the following command:"
    echo "  docker logs -f $CONTAINER_NAME"
  else
    echo "Failed to start the $CONTAINER_NAME."
    exit 1
  fi
}

# Function to stop the container
stop_container() {
  if container_exists; then
    echo "Stopping the $CONTAINER_NAME..."
    docker stop $CONTAINER_NAME > /dev/null
    echo "Removing the $CONTAINER_NAME..."
    docker rm $CONTAINER_NAME > /dev/null
    echo "$CONTAINER_NAME has been stopped and removed."
  else
    echo "No container found with name $CONTAINER_NAME."
  fi
}

# Main script logic
case "$1" in
  start)
    if [[ "$2" == "--help" || "$2" == "-h" ]]; then
      show_start_usage
    else
      start_container
    fi
    ;;
  stop)
    stop_container
    ;;
  --help|-h)
    show_usage
    ;;
  *)
    echo "Invalid argument: $1"
    show_usage
    exit 1
    ;;
esac
