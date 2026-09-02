#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ENV_FILE="$ROOT/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "[Dify] .env does not exist; run ./bootstrap.sh first." >&2
  exit 1
fi

env_value() {
  key=$1
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE"
}

port=$(env_value EXPOSE_NGINX_PORT || true)
case "$port" in
  ""|*[!0-9]*) port=5800 ;;
esac
configured_url=${DIFY_URL:-}
if [ -z "$configured_url" ]; then
  configured_url=$(env_value DIFY_URL || true)
fi
url=${configured_url:-http://127.0.0.1:${port}}
configured_timeout=${DIFY_HEALTH_TIMEOUT:-}
if [ -z "$configured_timeout" ]; then
  configured_timeout=$(env_value DIFY_HEALTH_TIMEOUT || true)
fi
timeout=${configured_timeout:-180}

command -v curl >/dev/null 2>&1 || {
  echo "[Dify] curl is required for health checks." >&2
  exit 1
}

compose() {
  docker compose --project-directory "$ROOT" --env-file "$ENV_FILE" -f "$ROOT/docker-compose.yaml" "$@"
}

core_services_ready() {
  # API ping alone can be available while the code sandbox is still restarting.
  # Verify the official components required for a Chatflow/Workflow target.
  for service in api web worker worker_beat plugin_daemon nginx ssrf_proxy db redis sandbox; do
    container_id=$(compose ps -q "$service" 2>/dev/null || true)
    [ -n "$container_id" ] || return 1
    state=$(docker inspect --format '{{.State.Status}}' "$container_id" 2>/dev/null || true)
    [ "$state" = "running" ] || return 1
  done
  for service in db redis sandbox; do
    container_id=$(compose ps -q "$service" 2>/dev/null || true)
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_id" 2>/dev/null || true)
    [ "$health" = "healthy" ] || return 1
  done
}

echo "[Dify] checking ${url}/console/api/ping (timeout ${timeout}s)"
i=0
while [ "$i" -lt "$timeout" ]; do
  if response=$(curl -fsS --max-time 5 "$url/console/api/ping" 2>/dev/null) &&
     printf '%s' "$response" | grep -q 'pong' && core_services_ready; then
    echo "[Dify] ready: ${url}"
    exit 0
  fi
  i=$((i + 1))
  sleep 1
done

echo "[Dify] health check timed out; inspect logs with:" >&2
echo "docker compose --project-directory '$ROOT' --env-file '$ENV_FILE' -f '$ROOT/docker-compose.yaml' logs --tail=120" >&2
exit 1
