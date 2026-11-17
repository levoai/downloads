#!/usr/bin/env bash

CONTAINER_NAME="levoai-shadownet-worker"
IMAGE_NAME="levoai/levoai-shadownet:1.4.75-proxy"
DEFAULT_LEVOAI_BASE_URL="https://api.levo.ai"
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
  echo "  LEVOAI_BASE_URL       (Optional) Levo Base URL. Default is '${DEFAULT_LEVOAI_BASE_URL}'."
  echo "                        For the India region, use 'https://api.india-1.levo.ai'."
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

# Function to check if the container exists, running or stopped
container_exists() {
  docker container inspect "$CONTAINER_NAME" > /dev/null 2>&1
}

# Function to start the container
start_container() {
  load_env_file

  # Check for required environment variables
  check_env_var "LEVOAI_AUTH_KEY"
  check_env_var "LEVOAI_ORG_ID"
  check_env_var "UPSTREAM_HTTP_PROXY"

  if container_exists; then
    echo "Error: a container named $CONTAINER_NAME already exists."
    echo "Run '$0 stop' to remove it, then start again."
    exit 1
  fi

  local base_url="${LEVOAI_BASE_URL:-$DEFAULT_LEVOAI_BASE_URL}"
  local no_proxy="${NO_PROXY:-$DEFAULT_NO_PROXY}"
  local env_id_args=()
  if [[ -n "$LEVOAI_ENV_ID" ]]; then
    env_id_args=(-e LEVOAI_ENV_ID="${LEVOAI_ENV_ID}")
  fi
  echo "LEVOAI_BASE_URL: $base_url"
  echo "LEVOAI_ENV_ID: ${LEVOAI_ENV_ID:-(not set)}"

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
    $IMAGE_NAME

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
