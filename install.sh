#!/usr/bin/env sh
set -eu

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  cat <<'EOF'
Usage: ./install.sh

Environment variables:
  DVLAA_IMAGE       Image tag to build and run. Default: dvlaa-lab:latest
  DVLAA_CONTAINER   Container name. Default: dvlaa-console
  DVLAA_PORT        Host port. Default: 5080
  DVLAA_DATA_VOLUME Docker volume for /app/data. Default: dvlaa-data
  DVLAA_ENV_FILE    Optional env-file path. Default: .env
  DVLAA_DIFY_RUNTIME_DIR  Native Dify runtime directory. Default: integrations/dify/runtime
  DVLAA_DIFY_URL    Native Dify URL from the DVLAA container. Default: http://host.docker.internal:5800
  DVLAA_AWDP_NATIVE_DIR   Native AWDP target directory. Default: integrations/targets
  DVLAA_AWDP_NATIVE_PORT  Native AWDP target host port. Default: 5900
  DVLAA_AWDP_NATIVE_URL   Native AWDP URL from the DVLAA container. Default: http://dvlaa-awdp-native:5900
  DVLAA_AWDP_NATIVE_BOOTSTRAP  Start AWDP01/03-10 targets. Default: true
  DVLAA_UPSTREAM_DIR   Official upstream Compose directory. Default: integrations/upstream
  DVLAA_UPSTREAM_BOOTSTRAP  Start RAGFlow/Langflow/Flowise/Open WebUI/n8n. Default: true
  DVLAA_UPSTREAM_STATE_FILE  Public upstream manifest mounted into DVLAA.
  DVLAA_GATEWAY_DIR  Nginx gateway Compose directory. Default: integrations/gateway
  DVLAA_GATEWAY_BOOTSTRAP  Start the single-port 5080 gateway. Default: true
EOF
  exit 0
fi

IMAGE="${DVLAA_IMAGE:-dvlaa-lab:latest}"
CONTAINER="${DVLAA_CONTAINER:-dvlaa-console}"
PORT="${DVLAA_PORT:-5080}"
DATA_VOLUME="${DVLAA_DATA_VOLUME:-dvlaa-data}"
ENV_FILE="${DVLAA_ENV_FILE:-.env}"
DIFY_RUNTIME_DIR="${DVLAA_DIFY_RUNTIME_DIR:-integrations/dify/runtime}"
DIFY_URL="${DVLAA_DIFY_URL:-http://host.docker.internal:5800}"
AWDP_NATIVE_DIR="${DVLAA_AWDP_NATIVE_DIR:-integrations/targets}"
AWDP_NATIVE_PORT="${DVLAA_AWDP_NATIVE_PORT:-5900}"
AWDP_NATIVE_URL="${DVLAA_AWDP_NATIVE_URL:-http://dvlaa-awdp-native:5900}"
AWDP_NATIVE_BOOTSTRAP="${DVLAA_AWDP_NATIVE_BOOTSTRAP:-true}"
UPSTREAM_DIR="${DVLAA_UPSTREAM_DIR:-integrations/upstream}"
UPSTREAM_BOOTSTRAP="${DVLAA_UPSTREAM_BOOTSTRAP:-true}"
UPSTREAM_STATE_FILE="${DVLAA_UPSTREAM_STATE_FILE:-${UPSTREAM_DIR}/runtime/targets.json}"
GATEWAY_DIR="${DVLAA_GATEWAY_DIR:-integrations/gateway}"
GATEWAY_BOOTSTRAP="${DVLAA_GATEWAY_BOOTSTRAP:-true}"

# 全部后端容器共用 dvlaa-net；网关是唯一对外端口，compose 均声明其为外部网络，
# 这里保证它存在，否则首个 compose up 会直接失败。
if ! docker network inspect dvlaa-net >/dev/null 2>&1; then
  echo "[DVLAA] Creating shared network: dvlaa-net"
  docker network create dvlaa-net >/dev/null
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker 24.0+ and run this script again." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not running. Start Docker and run this script again." >&2
  exit 1
fi

echo "[DVLAA] Building image: ${IMAGE}"
docker build -t "${IMAGE}" .

if docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER}"; then
  echo "[DVLAA] Recreating existing container: ${CONTAINER}"
  docker rm -f "${CONTAINER}" >/dev/null
fi

if [ -f "${ENV_FILE}" ]; then
  set -- --env-file "${ENV_FILE}"
else
  set --
fi

# AWDP01 and AWDP03-AWDP10 are independent local HTTP targets.  Start their
# dedicated Compose project first so it materializes its private runtime
# records, then mount that state read-only into DVLAA for scoring, reset and
# defense deployment coordination.  The learner-facing URL stays separate
# from the Docker-internal probe URL.
if [ "${AWDP_NATIVE_BOOTSTRAP}" = "true" ]; then
  if [ ! -x "${AWDP_NATIVE_DIR}/bootstrap.sh" ]; then
    echo "[DVLAA] Native AWDP bootstrap script not found: ${AWDP_NATIVE_DIR}/bootstrap.sh" >&2
    exit 1
  fi
  echo "[DVLAA] Starting native AWDP targets on port ${AWDP_NATIVE_PORT}"
  AWDP_NATIVE_PORT="${AWDP_NATIVE_PORT}" "${AWDP_NATIVE_DIR}/bootstrap.sh" up
fi

# AWDP03/04/05/07/09 use the released upstream applications themselves.  The
# Compose project writes only a public URL/version manifest; DVLAA never
# imports an upstream handler or falls back to its fixture while a target is
# healthy.
if [ "${UPSTREAM_BOOTSTRAP}" = "true" ]; then
  if [ ! -x "${UPSTREAM_DIR}/bootstrap.sh" ]; then
    echo "[DVLAA] Upstream bootstrap script not found: ${UPSTREAM_DIR}/bootstrap.sh" >&2
    exit 1
  fi
  echo "[DVLAA] Starting official AWDP upstream environments"
  "${UPSTREAM_DIR}/bootstrap.sh" up
fi

if [ -f "${AWDP_NATIVE_DIR}/runtime/1.json" ]; then
  AWDP_NATIVE_RUNTIME_ABS=$(cd "${AWDP_NATIVE_DIR}/runtime" && pwd)
  # 不注入 DVLAA_AWDP_NATIVE_PUBLIC_URL：探测地址是容器主机名时适配器会自动
  # 退化为同源相对路径 /awdp-target/<id>，由 5080 网关转发到目标容器。
  set -- "$@" \
    -v "${AWDP_NATIVE_RUNTIME_ABS}:/app/integrations/targets/runtime:ro" \
    -e "DVLAA_AWDP_NATIVE_MODE=native" \
    -e "DVLAA_AWDP_NATIVE_URL=${AWDP_NATIVE_URL}"
  echo "[DVLAA] Native AWDP targets enabled: ${AWDP_NATIVE_URL}"
fi

# A provisioned official Dify target owns AWDP02's model, prompt, and
# deployment verifier. Mount only the generated runtime metadata so DVLAA
# redirects learners to Dify instead of rendering the fixture fallback.
if [ -f "${DIFY_RUNTIME_DIR}/state.json" ]; then
  DIFY_RUNTIME_ABS=$(cd "${DIFY_RUNTIME_DIR}" && pwd)
  set -- "$@" \
    -v "${DIFY_RUNTIME_ABS}:/app/integrations/dify/runtime:ro" \
    -e "DVLAA_DIFY_MODE=native" \
    -e "DVLAA_DIFY_URL=${DIFY_URL}"
  echo "[DVLAA] Native Dify target enabled: ${DIFY_URL}"
fi

if [ -f "${UPSTREAM_STATE_FILE}" ]; then
  UPSTREAM_STATE_ABS=$(cd "$(dirname "${UPSTREAM_STATE_FILE}")" && pwd)/$(basename "${UPSTREAM_STATE_FILE}")
  # 上游容器不发布宿主机端口，console 经 dvlaa-net 用容器名探测；
  # AWDP03 与 AWDP09 共享同一个 RAGFlow 容器（网关同样如此路由）。
  set -- "$@" \
    -v "${UPSTREAM_STATE_ABS}:/app/integrations/upstream/runtime/targets.json:ro" \
    -e "DVLAA_UPSTREAM_MODE=auto" \
    -e "DVLAA_UPSTREAM_STATE_FILE=/app/integrations/upstream/runtime/targets.json" \
    -e "DVLAA_UPSTREAM_URL_03=http://dvlaa-upstream-ragflow-1:9380" \
    -e "DVLAA_UPSTREAM_URL_04=http://dvlaa-upstream-langflow-1:7860" \
    -e "DVLAA_UPSTREAM_URL_05=http://dvlaa-upstream-flowise-1:3005" \
    -e "DVLAA_UPSTREAM_URL_07=http://dvlaa-upstream-open-webui-1:8080" \
    -e "DVLAA_UPSTREAM_URL_09=http://dvlaa-upstream-ragflow-1:9380" \
    -e "DVLAA_UPSTREAM_URL_10=http://dvlaa-upstream-n8n-1:5678"
  echo "[DVLAA] Official upstream targets enabled"
fi

echo "[DVLAA] Starting container: ${CONTAINER}"
# console 不直接发布端口：全部流量经 5080 网关单端口进入。
docker run -d \
  --name "${CONTAINER}" \
  --restart unless-stopped \
  --add-host host.docker.internal:host-gateway \
  --network dvlaa-net \
  -v "${DATA_VOLUME}:/app/data" \
  "$@" \
  "${IMAGE}" >/dev/null

if [ "${GATEWAY_BOOTSTRAP}" = "true" ]; then
  echo "[DVLAA] Starting nginx gateway on 127.0.0.1:${PORT}"
  docker compose --project-directory "${GATEWAY_DIR}" -f "${GATEWAY_DIR}/docker-compose.yaml" up -d
fi

HEALTH_URL="http://127.0.0.1:${PORT}/health"
echo "[DVLAA] Waiting for service: ${HEALTH_URL}"
for i in $(seq 1 30); do
  if curl -fsS "${HEALTH_URL}" >/dev/null 2>&1; then
    echo "[DVLAA] Ready: http://127.0.0.1:${PORT}/"
    exit 0
  fi
  sleep 1
  if [ "$i" = "30" ]; then
    echo "[DVLAA] Container started, but health check is still pending. Inspect logs with:" >&2
    echo "docker logs ${CONTAINER}" >&2
    exit 1
  fi
done
