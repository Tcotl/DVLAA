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
EOF
  exit 0
fi

IMAGE="${DVLAA_IMAGE:-dvlaa-lab:latest}"
CONTAINER="${DVLAA_CONTAINER:-dvlaa-console}"
PORT="${DVLAA_PORT:-5080}"
DATA_VOLUME="${DVLAA_DATA_VOLUME:-dvlaa-data}"
ENV_FILE="${DVLAA_ENV_FILE:-.env}"

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

echo "[DVLAA] Starting container: ${CONTAINER}"
docker run -d \
  --name "${CONTAINER}" \
  --restart unless-stopped \
  -p "${PORT}:5000" \
  -v "${DATA_VOLUME}:/app/data" \
  "$@" \
  "${IMAGE}" >/dev/null

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
