#!/usr/bin/env sh
set -eu

# Initialize the first Dify administrator through Dify's public self-hosted
# setup API. Credentials are supplied via the environment and are never
# persisted by this script.

BASE_URL=${DIFY_URL:-http://127.0.0.1:5800}
BASE_URL=${BASE_URL%/}
EMAIL=${DIFY_ADMIN_EMAIL:-}
NAME=${DIFY_ADMIN_NAME:-DVLAA Administrator}
PASSWORD=${DIFY_ADMIN_PASSWORD:-}
INIT_PASSWORD=${DIFY_INIT_PASSWORD:-}

if [ -z "$EMAIL" ] || [ -z "$PASSWORD" ]; then
  echo "Usage: DIFY_ADMIN_EMAIL=... DIFY_ADMIN_PASSWORD=... ./init-admin.sh" >&2
  echo "Optional: DIFY_ADMIN_NAME=... DIFY_INIT_PASSWORD=... DIFY_URL=..." >&2
  exit 2
fi
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required to encode setup JSON" >&2; exit 1; }

cookie_file=$(mktemp "${TMPDIR:-/tmp}/dify-init.XXXXXX")
response_file=$(mktemp "${TMPDIR:-/tmp}/dify-response.XXXXXX")
trap 'rm -f "$cookie_file" "$response_file"' EXIT HUP INT TERM

status=$(curl -sS --max-time 10 \
  -c "$cookie_file" -b "$cookie_file" \
  "$BASE_URL/console/api/setup" -o "$response_file" -w '%{http_code}') || {
  echo "[Dify] setup endpoint is not reachable at $BASE_URL" >&2
  cat "$response_file" >&2 || true
  exit 1
}

case "$status" in
  2??) : ;;
  *) echo "[Dify] setup status request returned HTTP $status" >&2; cat "$response_file" >&2; exit 1 ;;
esac

if grep -q '"step"[[:space:]]*:[[:space:]]*"finished"' "$response_file"; then
  echo "[Dify] administrator setup is already complete; no changes made."
  exit 0
fi

# INIT_PASSWORD is disabled by default in the checked-in example. When an
# operator enables it, validate it with Dify first and retain the session cookie.
if [ -n "$INIT_PASSWORD" ]; then
  init_json=$(jq -cn --arg password "$INIT_PASSWORD" '{password:$password}')
  init_status=$(curl -sS --max-time 10 \
    -c "$cookie_file" -b "$cookie_file" \
    -H 'Content-Type: application/json' \
    -d "$init_json" \
    "$BASE_URL/console/api/init" -o "$response_file" -w '%{http_code}') || init_status=000
  case "$init_status" in
    2??) : ;;
    *) echo "[Dify] initialization password validation failed (HTTP $init_status)." >&2; cat "$response_file" >&2; exit 1 ;;
  esac
fi

json=$(jq -cn --arg email "$EMAIL" --arg name "$NAME" --arg password "$PASSWORD" \
  '{email:$email,name:$name,password:$password}')
status=$(curl -sS --max-time 20 \
  -c "$cookie_file" -b "$cookie_file" \
  -H 'Content-Type: application/json' -d "$json" \
  "$BASE_URL/console/api/setup" -o "$response_file" -w '%{http_code}') || status=000

case "$status" in
  2??)
    echo "[Dify] administrator initialized at $BASE_URL"
    ;;
  400)
    echo "[Dify] Dify rejected the setup request (already initialized or validation failed)." >&2
    cat "$response_file" >&2
    exit 1
    ;;
  *)
    echo "[Dify] administrator setup failed with HTTP $status." >&2
    cat "$response_file" >&2
    exit 1
    ;;
esac
