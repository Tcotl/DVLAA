#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: ./bootstrap.sh [up|down|config|health|reset ID]

The native target service is a separate local HTTP process.  It exposes
AWDP01 and AWDP03-AWDP10 at /challenge/<id>; AWDP02 stays on integrations/dify.

  up       Build and start the service (dvlaa-net 内容器，不发布宿主机端口)
  down     Stop the local service without deleting runtime state
  config   Render the Compose configuration
  health   Probe the service and list available challenge targets
  reset ID Rotate one target's local Flag and business records

容器在 dvlaa-net 内监听 5900，浏览器经 5080 网关的 /awdp-target/<id> 访问。
DVLAA 适配器通过 DVLAA_AWDP_NATIVE_URL（默认 http://dvlaa-awdp-native:5900）探测。
EOF
}

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required for Compose startup. Run python3 target_server.py for a dependency-free local process." >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not running." >&2
  exit 1
fi

compose() { docker compose --project-directory "$ROOT" -f "$ROOT/docker-compose.yaml" "$@"; }

command_name=${1:-up}
case "$command_name" in
  -h|--help|help) usage; exit 0 ;;
  up) mkdir -p runtime; chmod 700 runtime; compose up -d --build ;;
  down) compose down ;;
  config) compose config ;;
  health) "$ROOT/healthcheck.sh" ;;
  reset)
    id=${2:-}
    case "$id" in 1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30) : ;; *) echo "reset requires challenge ID 1-30" >&2; exit 2 ;; esac
    curl -fsS -X POST "${AWDP_NATIVE_RESET_URL:-http://127.0.0.1:${GATEWAY_PORT:-5080}}/awdp-target/${id}/api/reset"
    printf '\n'
    ;;
  *) usage >&2; exit 2 ;;
esac
