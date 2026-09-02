"""Adapter for the standalone native AWDP target service.

The adapter is deliberately thin: the target application owns its records,
business rules, verifier, and patched deployment.  DVLAA only probes health,
redirects the learner to the native Web UI, proxies an optional API request,
and validates a Flag submitted through the console.  No target handler is
reimplemented here and this module never imports ``awdp_web_lab``.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from ..paths import PROJECT_ROOT


NATIVE_IDS = frozenset(range(1, 31))
DEFAULT_URL = "http://127.0.0.1:5900"
DEFAULT_STATE_DIR = PROJECT_ROOT / "integrations" / "targets" / "runtime"
_PROBE_TTL = 1.5
_probe_lock = threading.Lock()
_probe_cache: dict[str, tuple[float, bool]] = {}

# The browser-side target shell uses the same action metadata as the fixture
# renderer.  Keeping this tiny descriptor in the adapter avoids importing the
# fixture implementation and lets the Flask bootstrap endpoint remain useful
# when the native service is enabled.
_NATIVE_ACTIONS: dict[int, tuple[dict[str, Any], ...]] = {
    1: ({"name": "support.chat", "label": "S-Spring 客服对话", "method": "POST", "description": "通过 OpenAI 兼容 Chat Completions 接口咨询订单、退款、售后与服务时间。", "fields": ({"name": "message", "label": "消息内容", "default": "请介绍一下退款和服务时间。", "type": "textarea"},)}, {"name": "support.export_policy", "label": "导出客服交接策略", "method": "POST", "description": "生成客服交接所需的运行时策略副本。", "fields": ({"name": "handoff", "label": "交接类型", "default": "standard", "type": "text"}, {"name": "includeRuntimePolicy", "label": "包含运行时策略", "default": "false", "type": "boolean"})}),
    2: ({"name": "migration.import_ticket", "label": "导入迁移工单", "method": "POST", "description": "将外部工单保存到迁移队列。", "fields": ({"name": "ticketId", "label": "工单编号", "default": "TK-2048", "type": "text"}, {"name": "customer", "label": "客户名称", "default": "星辰零售", "type": "text"}, {"name": "status", "label": "迁移状态", "default": "待预览", "type": "text"}, {"name": "note", "label": "外部工单备注", "default": "", "type": "textarea"})}, {"name": "migration.preview_ticket", "label": "生成迁移预览", "method": "POST", "description": "读取已导入工单并生成业务迁移预览。", "fields": ({"name": "ticketId", "label": "工单编号", "default": "TK-2048", "type": "text"})}),
    3: ({"name": "knowledge.import_document", "label": "导入知识库文档", "method": "POST", "description": "向退货政策知识库新增文档。", "fields": ({"name": "documentId", "label": "文档编号", "default": "RET-2026-08", "type": "text"}, {"name": "title", "label": "文档标题", "default": "退货申请期限", "type": "text"}, {"name": "body", "label": "政策正文", "default": "退货申请需在签收后 7 天内提交。", "type": "textarea"}, {"name": "annotation", "label": "导入注释", "default": "", "type": "textarea"})}, {"name": "knowledge.search", "label": "检索退货知识库", "method": "GET", "description": "检索政策、期限与凭证说明。", "fields": ({"name": "query", "label": "检索词", "default": "退货申请期限", "type": "text"},)}),
    4: ({"name": "workflow.run_tool", "label": "执行流程诊断工具", "method": "POST", "description": "请求流程工具的诊断结果。", "fields": ({"name": "mode", "label": "运行模式", "default": "preview", "type": "text"}, {"name": "tool", "label": "工具名称", "default": "diagnostics", "type": "text"}, {"name": "field", "label": "诊断字段", "default": "node_status", "type": "text"})},),
    5: ({"name": "api.request", "label": "发送 Chatflow API 请求", "method": "GET", "description": "调用 Flowise 风格路由。", "fields": ({"name": "path", "label": "请求路径", "default": "/api/v1/health", "type": "text"}, {"name": "apiKey", "label": "x-api-key", "default": "", "type": "text"})},),
    6: ({"name": "dsl.list_apps", "label": "查看可访问应用", "method": "GET", "description": "查看公开应用与当前租户草稿。", "fields": ()}, {"name": "dsl.export", "label": "导出应用 DSL", "method": "POST", "description": "导出应用配置。", "fields": ({"name": "appId", "label": "应用 ID", "default": "public-assistant", "type": "text"}, {"name": "role", "label": "请求角色", "default": "viewer", "type": "text"})}),
    7: ({"name": "crawler.fetch", "label": "抓取网页资料", "method": "POST", "description": "抓取 URL 并生成摘要。", "fields": ({"name": "url", "label": "目标 URL", "default": "https://docs.example.test/refund-policy", "type": "text"}, {"name": "followRedirects", "label": "跟随重定向", "default": True, "type": "boolean"})},),
    8: ({"name": "report.execute", "label": "执行财务报表查询", "method": "POST", "description": "生成只读部门收入报表。", "fields": ({"name": "statement", "label": "报表查询", "default": "SELECT department, amount FROM revenue WHERE month = '2026-07'", "type": "textarea"})},),
    9: ({"name": "documents.view", "label": "查看合同文档", "method": "GET", "description": "读取当前租户合同摘要。", "fields": ({"name": "tenantId", "label": "租户 ID", "default": "tenant-blue", "type": "text"}, {"name": "documentId", "label": "文档 ID", "default": "contract-blue-2026", "type": "text"})},),
    10: ({"name": "executions.stop", "label": "停止工作流执行", "method": "POST", "description": "停止当前团队的运行中执行。", "fields": ({"name": "executionId", "label": "执行 ID", "default": "exec-blue-1042", "type": "text"})},),
}

# 决赛十题（AWDP11-AWDP20）的动作描述来自共享引擎（与目标服务同一份定义）。
import importlib.util as _importlib_util

_engine_path = PROJECT_ROOT / "integrations" / "targets" / "finals_core.py"
_spec = _importlib_util.spec_from_file_location("dvlaa_awdp_finals_core_native", _engine_path)
_finals_engine = _importlib_util.module_from_spec(_spec)
_spec.loader.exec_module(_finals_engine)
for _final_id in sorted(_finals_engine.FINAL_IDS):
    _NATIVE_ACTIONS[_final_id] = tuple(
        {**_action, "fields": tuple(dict(_field_item) for _field_item in _action["fields"])}
        for _action in _finals_engine.actions(_final_id)
    )



def _mode() -> str:
    value = os.environ.get("DVLAA_AWDP_NATIVE_MODE", "auto").strip().lower()
    return value if value in {"auto", "native", "fixture", "disabled"} else "auto"


def _base_url(challenge_id: int) -> str:
    specific = os.environ.get(f"DVLAA_AWDP_NATIVE_URL_{int(challenge_id):02d}", "").strip()
    value = specific or os.environ.get("DVLAA_AWDP_NATIVE_URL", "").strip()
    if not value:
        host = os.environ.get("DVLAA_AWDP_NATIVE_HOST", "").strip()
        port = os.environ.get("DVLAA_AWDP_NATIVE_PORT", "5900").strip()
        value = f"http://{host}:{port}" if host else f"http://127.0.0.1:{port}"
    return value.rstrip("/") or DEFAULT_URL


def _public_base_url(challenge_id: int) -> str:
    """Return the browser-facing URL without changing the server probe URL.

    A Dockerized DVLAA process reaches the host target through
    ``host.docker.internal``.  That hostname is not a portable browser URL,
    so operators can publish a separate address for the 302 target redirect.
    Source installs keep the one-address default.
    """
    specific = os.environ.get(f"DVLAA_AWDP_NATIVE_PUBLIC_URL_{int(challenge_id):02d}", "").strip()
    value = specific or os.environ.get("DVLAA_AWDP_NATIVE_PUBLIC_URL", "").strip()
    if value:
        return value.rstrip("/")
    base = _base_url(challenge_id)
    host = (urllib.parse.urlsplit(base).hostname or "").lower()
    if host in {"127.0.0.1", "localhost", "::1"} or host.endswith(".localhost"):
        return base
    # Docker 部署中探测地址是容器主机名（如 dvlaa-awdp-native），浏览器不可达。
    # 返回空串让 target_url 退化为同源相对路径，由 5080 网关按前缀路由到目标容器，
    # 避免 302 把选手带到丢失端口或不可解析的地址。
    return ""


def state_dir() -> Path:
    return Path(os.environ.get("DVLAA_AWDP_NATIVE_STATE_DIR", str(DEFAULT_STATE_DIR))).expanduser()


def _public_target_path(challenge_id: int) -> str:
    """Return the dedicated learner-facing AWDP path.

    Keeping AWDP targets under a distinct prefix prevents `/challenge/<level>/<sub>`
    from colliding with the OWASP LLM challenge routes in the shared 5080 gateway.
    """
    prefix = os.environ.get("DVLAA_AWDP_NATIVE_PUBLIC_PREFIX", "/awdp-target").strip().rstrip("/")
    return f"{prefix}/{int(challenge_id)}" if prefix else f"/challenge/{int(challenge_id)}"


def state_path(challenge_id: int) -> Path:
    return state_dir() / f"{int(challenge_id)}.json"


def _load_private(challenge_id: int) -> dict[str, Any]:
    try:
        value = json.loads(state_path(challenge_id).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _request(url: str, *, method: str = "GET", body: Mapping[str, Any] | None = None, headers: Mapping[str, str] | None = None, timeout: float = 1.5) -> tuple[int, dict[str, Any]]:
    encoded = None
    request_headers = {"Accept": "application/json"}
    if body is not None:
        encoded = json.dumps(dict(body), ensure_ascii=False).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update({str(k): str(v) for k, v in headers.items()})
    request = urllib.request.Request(url, data=encoded, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(2 * 1024 * 1024)
            value = json.loads(raw.decode("utf-8")) if raw else {}
            return int(response.status), value if isinstance(value, dict) else {}
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(2 * 1024 * 1024)
            value = json.loads(raw.decode("utf-8")) if raw else {}
        except (OSError, ValueError, TypeError):
            value = {}
        return int(exc.code), value if isinstance(value, dict) else {}
    except (OSError, TimeoutError, ValueError):
        return 0, {}


def reachable(challenge_id: int) -> bool:
    if int(challenge_id) not in NATIVE_IDS or _mode() in {"fixture", "disabled"}:
        return False
    url = _base_url(challenge_id)
    now = time.monotonic()
    with _probe_lock:
        cached = _probe_cache.get(url)
        if cached and now - cached[0] < _PROBE_TTL:
            return cached[1]
    status, value = _request(f"{url}/health?challenge_id={int(challenge_id)}", timeout=1.0)
    ok = 200 <= status < 300 and value.get("service") == "awdp-native-targets"
    with _probe_lock:
        _probe_cache[url] = (time.monotonic(), ok)
    return ok


def native_state(challenge_id: int) -> dict[str, Any]:
    challenge_id = int(challenge_id)
    private = _load_private(challenge_id)
    configured = challenge_id in NATIVE_IDS and bool(private.get("flag"))
    live = reachable(challenge_id) if configured else False
    enabled = _mode() == "native" or (_mode() == "auto" and configured and live)
    # ``native`` mode still requires a reachable HTTP target for redirecting;
    # exposing a dead URL creates a confusing blank training window.
    if _mode() == "native" and not live:
        enabled = False
    return {
        "challenge_id": challenge_id,
        "mode": _mode(),
        "enabled": enabled,
        "configured": configured,
        "reachable": live,
        "base_url": _base_url(challenge_id),
        "public_base_url": _public_base_url(challenge_id),
        "target_url": f"{_public_base_url(challenge_id)}{_public_target_path(challenge_id)}" if enabled else "",
        "patched": bool(private.get("patched")) if enabled else False,
        "attack_solved": bool(private.get("attack_solved")) if enabled else False,
        "service_version": "1.0-native",
    }


def enabled(challenge_id: int) -> bool:
    """Compatibility predicate used by the Flask bootstrap route."""
    return bool(native_state(int(challenge_id)).get("enabled"))


def status() -> dict[str, Any]:
    """Return aggregate browser-safe status for all standalone targets."""
    targets = {str(cid): native_state(cid) for cid in sorted(NATIVE_IDS)}
    return {
        "mode": _mode(),
        "enabled": any(bool(item.get("enabled")) for item in targets.values()),
        "service_version": "1.0-native",
        "base_url": _base_url(1),
        "public_base_url": _public_base_url(1),
        "targets": targets,
    }


def bootstrap(challenge_id: int, session_id: str = "", runtime_flag_value: str = "", patched: bool = False) -> dict[str, Any] | None:
    """Build the public lab descriptor consumed by the DVLAA Web shell.

    The native browser normally opens ``native_target_url`` directly.  This
    descriptor is useful when a same-origin embed or API bootstrap is desired;
    it contains no state secret and does not create a target session.
    """
    challenge_id = int(challenge_id)
    if not enabled(challenge_id):
        return None
    state = native_state(challenge_id)
    return {
        "challenge_id": challenge_id,
        "title": f"AWDP{challenge_id:02d} Native Target",
        "subtitle": "独立本地 HTTP 服务",
        "patched": bool(state.get("patched")),
        "actions": [dict(item) for item in _NATIVE_ACTIONS.get(challenge_id, ())],
        "target_url": state.get("target_url", ""),
    }


def native_target_url(challenge_id: int) -> str | None:
    status = native_state(challenge_id)
    value = str(status.get("target_url") or "").strip()
    return value if status.get("enabled") and value else None


def runtime_flag(challenge_id: int) -> str | None:
    challenge_id = int(challenge_id)
    if challenge_id not in NATIVE_IDS or not native_state(challenge_id).get("enabled"):
        return None
    value = str(_load_private(challenge_id).get("flag") or "").strip()
    return value if value.startswith("flag{") and value.endswith("}") else None


def attack_solved(challenge_id: int) -> bool:
    return bool(_load_private(int(challenge_id)).get("attack_solved")) if native_state(challenge_id).get("enabled") else False


def action(challenge_id: int, operation: str, payload: Mapping[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    """Proxy a browser-safe action to the native service."""
    if not native_state(challenge_id).get("enabled"):
        return 0, {"error": "native_target_unavailable"}
    path = urllib.parse.quote(str(operation), safe="")
    return _request(f"{_base_url(challenge_id)}/challenge/{int(challenge_id)}/api/action/{path}", method="POST", body=dict(payload or {}), timeout=10.0)


def reset(challenge_id: int) -> bool:
    if not reachable(challenge_id):
        return False
    status, _ = _request(f"{_base_url(challenge_id)}/challenge/{int(challenge_id)}/api/reset", method="POST", body={}, timeout=5.0)
    reset_probe_cache()
    return 200 <= status < 300


def set_patched(challenge_id: int, patched: bool) -> bool:
    """Switch the native service after DVLAA validates a repair package."""
    challenge_id = int(challenge_id)
    if not reachable(challenge_id):
        return False
    private = _load_private(challenge_id)
    token = str(private.get("internal_token") or "")
    if not token:
        return False
    status, _ = _request(
        f"{_base_url(challenge_id)}/challenge/{challenge_id}/api/internal/deploy",
        method="POST",
        body={"patched": bool(patched)},
        headers={"X-DVLAA-Internal": token},
        timeout=5.0,
    )
    reset_probe_cache()
    return 200 <= status < 300


def reset_probe_cache() -> None:
    with _probe_lock:
        _probe_cache.clear()


__all__ = [
    "NATIVE_IDS",
    "action",
    "attack_solved",
    "bootstrap",
    "enabled",
    "native_state",
    "native_target_url",
    "reachable",
    "reset",
    "reset_probe_cache",
    "runtime_flag",
    "status",
    "set_patched",
    "state_dir",
    "state_path",
]
