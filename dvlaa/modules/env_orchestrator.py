"""AWDP 真实漏洞环境的按需编排（双轨制的"真实轨"）。

靶场默认运行在模拟链路（fixture / native target），学员在题目页点击
"真实复现"后，本模块通过 Docker socket 启动该题对应的真实上游容器组；
容器就绪后，既有的 dify_integration / upstream_targets 探测会自动把题目
切换到真实环境，停止后自动回退模拟链路，无需改动题目逻辑。

只使用 Python 标准库通过 /var/run/docker.sock 调用 Docker API，不引入
docker SDK 依赖。挂载 docker.sock 等同于授予宿主机 root 权限，仅限本地
教学靶场使用。
"""

from __future__ import annotations

import http.client
import json
import socket
from typing import Any

DOCKER_SOCKET = "/var/run/docker.sock"

# ── 题目 → 真实环境容器组 ─────────────────────────────────
# AWDP01 为本地案例，没有真实上游环境。Dify 三题共用一套栈，
# RAGFlow 两题共用一套栈；worker_beat / ssrf_proxy / certbot
# 等与漏洞复现无关的组件不纳入按需启动清单。
REAL_ENV_STACKS: dict[int, dict[str, Any]] = {
    2: {
        "name": "Dify 1.9.2",
        "containers": [
            "dvlaa-dify-db-1", "dvlaa-dify-redis-1", "dvlaa-dify-weaviate-1",
            "dvlaa-dify-sandbox-1", "dvlaa-dify-plugin_daemon-1",
            "dvlaa-dify-api-1", "dvlaa-dify-worker-1", "dvlaa-dify-web-1",
            "dvlaa-dify-nginx-1",
        ],
    },
    3: {
        "name": "RAGFlow v0.14.1",
        "containers": [
            "dvlaa-upstream-ragflow-es-1", "dvlaa-upstream-ragflow-mysql-1",
            "dvlaa-upstream-ragflow-redis-1", "dvlaa-upstream-ragflow-minio-1",
            "dvlaa-upstream-ragflow-1",
        ],
    },
    4: {
        "name": "Langflow 1.0.18",
        "containers": ["dvlaa-upstream-langflow-db-1", "dvlaa-upstream-langflow-1"],
    },
    5: {
        "name": "Flowise 1.8.2",
        "containers": ["dvlaa-upstream-flowise-1"],
    },
    6: {
        "name": "Dify 1.9.2",
        "containers": [
            "dvlaa-dify-db-1", "dvlaa-dify-redis-1", "dvlaa-dify-weaviate-1",
            "dvlaa-dify-sandbox-1", "dvlaa-dify-plugin_daemon-1",
            "dvlaa-dify-api-1", "dvlaa-dify-worker-1", "dvlaa-dify-web-1",
            "dvlaa-dify-nginx-1",
        ],
    },
    7: {
        "name": "Open WebUI v0.1.116",
        "containers": ["dvlaa-upstream-open-webui-1"],
    },
    8: {
        "name": "Dify 1.9.2",
        "containers": [
            "dvlaa-dify-db-1", "dvlaa-dify-redis-1", "dvlaa-dify-weaviate-1",
            "dvlaa-dify-sandbox-1", "dvlaa-dify-plugin_daemon-1",
            "dvlaa-dify-api-1", "dvlaa-dify-worker-1", "dvlaa-dify-web-1",
            "dvlaa-dify-nginx-1",
        ],
    },
    9: {
        "name": "RAGFlow v0.14.1",
        "containers": [
            "dvlaa-upstream-ragflow-es-1", "dvlaa-upstream-ragflow-mysql-1",
            "dvlaa-upstream-ragflow-redis-1", "dvlaa-upstream-ragflow-minio-1",
            "dvlaa-upstream-ragflow-1",
        ],
    },
    10: {
        "name": "n8n 1.99.0",
        "containers": ["dvlaa-upstream-n8n-1"],
    },
}


# ── Docker API（Unix socket，标准库实现） ──────────────────
def _docker_request(method: str, path: str, timeout: float = 10.0) -> tuple[int, Any]:
    """向 Docker socket 发一次请求，返回 (状态码, 解析后的 JSON 或文本)。"""
    conn = http.client.HTTPConnection("localhost", timeout=timeout)
    try:
        conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.sock.connect(DOCKER_SOCKET)
        conn.request(method, path)
        response = conn.getresponse()
        body = response.read().decode("utf-8", "replace")
    finally:
        conn.close()
    try:
        return response.status, json.loads(body)
    except ValueError:
        return response.status, body


def _container_state(name: str) -> str:
    """返回容器状态：running / exited / missing（及其他原生状态）。"""
    status, data = _docker_request("GET", f"/containers/{name}/json", timeout=4.0)
    if status != 200 or not isinstance(data, dict):
        return "missing"
    return str(data.get("State", {}).get("Status") or "unknown")


def available() -> bool:
    """docker.sock 是否可用（未挂载时编排功能整体降级为不可用）。"""
    try:
        status, _data = _docker_request("GET", "/_ping", timeout=2.0)
        return status == 200
    except OSError:
        return False


def stack_status(challenge_id: int) -> dict[str, Any]:
    """汇总某题真实环境的容器组状态。"""
    stack = REAL_ENV_STACKS.get(int(challenge_id))
    if stack is None:
        return {"supported": False, "state": "unsupported", "name": ""}
    if not available():
        return {"supported": True, "state": "unavailable", "name": stack["name"],
                "message": "控制台未挂载 docker.sock，无法按需启动真实环境。"}

    states = [_container_state(name) for name in stack["containers"]]
    missing = sum(1 for item in states if item == "missing")
    running = sum(1 for item in states if item == "running")
    total = len(states)
    if missing == total:
        state = "missing"
        message = "真实环境尚未安装，请在宿主机执行对应 integrations 目录下的 docker compose up -d。"
    elif running == total:
        state = "running"
        message = "真实环境容器已全部运行，应用就绪后题目会自动切换。"
    elif running > 0:
        state = "partial"
        message = "真实环境部分组件运行中。"
    else:
        state = "stopped"
        message = "真实环境已安装但未运行，可点击启动。"
    return {
        "supported": True,
        "state": state,
        "name": stack["name"],
        "running": running,
        "total": total,
        "missing": missing,
        "message": message,
    }


def start_stack(challenge_id: int) -> dict[str, Any]:
    """按依赖顺序启动某题的真实环境容器组。"""
    status = stack_status(challenge_id)
    if not status.get("supported"):
        return {"ok": False, "message": "本题没有真实上游环境。", **status}
    if status["state"] == "unavailable":
        return {"ok": False, **status}
    if status["state"] == "missing":
        return {"ok": False, **status}

    errors = []
    for name in REAL_ENV_STACKS[int(challenge_id)]["containers"]:
        if _container_state(name) == "running":
            continue
        code, data = _docker_request("POST", f"/containers/{name}/start", timeout=30.0)
        if code not in (204, 304):
            errors.append(f"{name}: {data if isinstance(data, str) else data.get('message', code)}")
    if errors:
        return {"ok": False, "message": "；".join(errors), **stack_status(challenge_id)}
    return {"ok": True, "message": "真实环境容器已启动，应用初始化完成后自动接管本题。", **stack_status(challenge_id)}


def stop_stack(challenge_id: int) -> dict[str, Any]:
    """停止某题的真实环境容器组（Dify/RAGFlow 为共用栈，三题同时受影响）。"""
    status = stack_status(challenge_id)
    if not status.get("supported") or status["state"] in {"unavailable", "missing", "unsupported"}:
        return {"ok": False, **status}
    for name in reversed(REAL_ENV_STACKS[int(challenge_id)]["containers"]):
        if _container_state(name) != "running":
            continue
        _docker_request("POST", f"/containers/{name}/stop?t=10", timeout=30.0)
    return {"ok": True, "message": "真实环境已停止，本题回退到模拟链路。", **stack_status(challenge_id)}


__all__ = ["REAL_ENV_STACKS", "available", "stack_status", "start_stack", "stop_stack"]
