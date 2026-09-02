#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
ENV_FILE=${DVLAA_UPSTREAM_ENV_FILE:-$ROOT/.env}
RUNTIME_DIR=${DVLAA_UPSTREAM_RUNTIME_DIR:-$ROOT/runtime}

usage() {
  cat <<'EOF'
Usage: ./bootstrap.sh [up|down|config|health]

Starts the pinned upstream applications used by AWDP03-AWDP10.  The generated
runtime/targets.json contains only browser-facing URLs (the 5080 gateway
virtual hosts) and project versions; credentials and Flags are never returned
to the DVLAA browser.
EOF
}

command -v docker >/dev/null 2>&1 || { echo "Docker is required." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker daemon is not running." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required." >&2; exit 1; }

[ -f "$ENV_FILE" ] || { cp "$ROOT/.env.example" "$ENV_FILE"; chmod 600 "$ENV_FILE"; }
mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"

compose() { docker compose --project-directory "$ROOT" --env-file "$ENV_FILE" -f "$ROOT/docker-compose.yaml" "$@"; }

write_state() {
  # Keep this file intentionally boring: it is mounted read-only into DVLAA.
  # The private challenge verifier remains in DVLAA's persistent data volume.
  tmp="$RUNTIME_DIR/.targets.json.$$"
  cat >"$tmp" <<EOF
{
  "schema_version": 1,
  "targets": {
    "03": {"project": "RAGFlow", "version": "v0.14.1", "public_url": "http://awdp03.localhost:${GATEWAY_PORT:-5080}", "health_path": "/v1/system/status"},
    "04": {"project": "Langflow", "version": "1.0.18", "public_url": "http://awdp04.localhost:${GATEWAY_PORT:-5080}", "health_path": "/health"},
    "05": {"project": "Flowise", "version": "1.8.2", "public_url": "http://awdp05.localhost:${GATEWAY_PORT:-5080}", "health_path": "/api/v1/ping"},
    "07": {"project": "Open WebUI", "version": "v0.1.116", "public_url": "http://awdp07.localhost:${GATEWAY_PORT:-5080}", "health_path": "/health"},
    "09": {"project": "RAGFlow", "version": "v0.14.1", "public_url": "http://awdp09.localhost:${GATEWAY_PORT:-5080}", "health_path": "/v1/system/status"},
    "10": {"project": "n8n", "version": "1.99.0", "public_url": "http://awdp10.localhost:${GATEWAY_PORT:-5080}", "health_path": "/healthz"}
  }
}
EOF
  mv "$tmp" "$RUNTIME_DIR/targets.json"
  chmod 600 "$RUNTIME_DIR/targets.json"
}

case "${1:-up}" in
  -h|--help|help) usage ;;
  up)
    compose up -d
    write_state
    echo "[AWDP] upstream environments started"
    ;;
  down) compose down ;;
  config) compose config ;;
  health)
    curl -fsS "http://awdp05.localhost:${GATEWAY_PORT:-5080}/api/v1/ping" || true
    printf '\n'
    ;;
  *) usage >&2; exit 2 ;;
esac
