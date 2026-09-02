#!/usr/bin/env sh
set -eu

# 容器不发布宿主机端口：默认在 dvlaa-net 容器内探测；外部地址可用 AWDP_NATIVE_URL 覆盖。
if [ -n "${AWDP_NATIVE_URL:-}" ]; then
  response=$(curl -fsS --max-time 3 "${AWDP_NATIVE_URL}/health")
else
  response=$(docker exec "${AWDP_NATIVE_CONTAINER:-dvlaa-awdp-native}" \
    python3 -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:5900/health', timeout=3).read().decode())")
fi
printf '%s\n' "$response"
printf '%s' "$response" | grep -q 'awdp-native-targets'
