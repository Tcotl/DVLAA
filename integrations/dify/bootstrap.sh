#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: ./bootstrap.sh [up|config|pull|down|provision]

Commands:
  up      generate .env, validate Compose, and start the real Dify stack
  config  generate .env and print the resolved Compose configuration
  pull    pull the pinned Dify and middleware images
  down    stop the stack without deleting persistent data
  provision initialize the native admin/app and refresh AWDP02 state
            (extra arguments are passed to provision.py, e.g. --require-model)

The default command is `up`. Set DIFY_PULL_IMAGES=false to skip an explicit
image pull before `up` (Compose will still pull missing images).
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[Dify] required command not found: $1" >&2
    exit 1
  }
}

require_command docker
docker info >/dev/null 2>&1 || {
  echo "[Dify] Docker daemon is not running." >&2
  exit 1
}
docker compose version >/dev/null 2>&1 || {
  echo "[Dify] Docker Compose v2 is required (docker compose)." >&2
  exit 1
}

if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
  echo "[Dify] created .env from .env.example"
fi

# Existing deployments may have been bootstrapped from an older example. Add
# only keys that are absent from the local file so upgrades remain
# deterministic without replacing operator-managed values (including empty
# optional values).
ensure_example_defaults() {
  tmp=".env.tmp.$$"
  awk -F= '
    NR == FNR {
      if ($0 ~ /^[A-Za-z_][A-Za-z0-9_]*=/) {
        key = $0
        sub(/=.*/, "", key)
        if (!(key in defaults)) {
          defaults[key] = $0
          order[++count] = key
        }
      }
      next
    }
    {
      print
      if ($0 ~ /^[A-Za-z_][A-Za-z0-9_]*=/) {
        key = $0
        sub(/=.*/, "", key)
        present[key] = 1
      }
    }
    END {
      for (i = 1; i <= count; i++) {
        key = order[i]
        if (!(key in present)) print defaults[key]
      }
    }
  ' .env.example .env > "$tmp"
  mv "$tmp" .env
  chmod 600 .env
}

ensure_example_defaults

env_value() {
  key=$1
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' .env
}

set_env() {
  key=$1
  value=$2
  tmp=".env.tmp.$$"
  awk -F= -v key="$key" -v value="$value" '
    BEGIN { replaced = 0 }
    $1 == key { print key "=" value; replaced = 1; next }
    { print }
    END { if (!replaced) print key "=" value }
  ' .env > "$tmp"
  mv "$tmp" .env
  chmod 600 .env
}

random_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
  fi
}

ensure_secret() {
  key=$1
  current=$(env_value "$key" || true)
  case "$current" in
    ""|CHANGE_ME_*) set_env "$key" "$(random_hex)" ;;
  esac
}

ensure_secret SECRET_KEY
ensure_secret REDIS_PASSWORD
ensure_secret SANDBOX_API_KEY
ensure_secret PLUGIN_DAEMON_KEY
ensure_secret PLUGIN_DIFY_INNER_API_KEY

# Keep PostgreSQL and Celery credentials in sync with the generated values.
db_password=$(env_value DB_PASSWORD || true)
case "$db_password" in
  ""|CHANGE_ME_*) db_password=$(random_hex); set_env DB_PASSWORD "$db_password" ;;
esac
set_env POSTGRES_PASSWORD "$db_password"
redis_password=$(env_value REDIS_PASSWORD)
set_env CELERY_BROKER_URL "redis://:${redis_password}@redis:6379/1"

# Bind-mounted paths used by the active upstream services. Creating them here
# makes first startup deterministic on both Docker Desktop and Linux/ARM64.
mkdir -p \
  volumes/app/storage \
  volumes/db/data \
  volumes/redis/data \
  volumes/sandbox/dependencies \
  volumes/sandbox/conf \
  volumes/plugin_daemon \
  volumes/weaviate \
  volumes/certbot/conf/live \
  volumes/certbot/logs \
  volumes/certbot/www \
  nginx/ssl

# The official sandbox image requires a mounted config.yaml. Keep the checked-
# in example immutable, then bind the generated sandbox API key into the local
# runtime file without putting credentials in Git.
sandbox_config="volumes/sandbox/conf/config.yaml"
if [ ! -f "$sandbox_config" ]; then
  cp volumes/sandbox/conf/config.yaml.example "$sandbox_config"
fi
sandbox_key=$(env_value SANDBOX_API_KEY)
tmp_config="${sandbox_config}.tmp.$$"
sed "s/^  key: .*/  key: ${sandbox_key}/" "$sandbox_config" > "$tmp_config"
mv "$tmp_config" "$sandbox_config"

compose() {
  docker compose --project-directory "$ROOT" --env-file "$ROOT/.env" -f "$ROOT/docker-compose.yaml" "$@"
}

command_name=${1:-up}
case "$command_name" in
  -h|--help|help)
    usage
    exit 0
    ;;
  config)
    compose config
    exit 0
    ;;
  pull)
    compose pull
    exit 0
    ;;
  down)
    compose down
    exit 0
    ;;
  provision)
    shift
    "$ROOT/healthcheck.sh"
    exec python3 "$ROOT/provision.py" "$@"
    ;;
  up)
    :
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

pull_images=${DIFY_PULL_IMAGES:-}
if [ -z "$pull_images" ]; then
  pull_images=$(env_value DIFY_PULL_IMAGES || true)
fi
if [ "$pull_images" != "false" ]; then
  echo "[Dify] pulling pinned upstream images (set DIFY_PULL_IMAGES=false to skip)"
  compose pull
fi

echo "[Dify] validating official Compose configuration"
compose config >/dev/null
echo "[Dify] starting Dify ${DIFY_VERSION:-1.9.2} (project: ${COMPOSE_PROJECT_NAME:-dvlaa-dify})"
compose up -d

echo "[Dify] waiting for the native console/API health endpoint"
"$ROOT/healthcheck.sh"

if [ "$(env_value DIFY_AUTO_PROVISION || true)" = "true" ]; then
  echo "[Dify] provisioning the native AWDP02 application through Console APIs"
  exec python3 "$ROOT/provision.py"
fi

echo "[Dify] ready: native service started; run ./bootstrap.sh provision after configuring a model provider"
