"""Stateful, isolated web-service fixtures for the AWDP challenge track.

The original AWDP pages used a chat UI as the attack surface.  This module
models the *application* side of the ten cases instead: every challenge has a
small service with explicit requests, business records and authorization
boundaries.  It intentionally does not run user supplied code, make outbound
requests, or persist anything itself.  The Flask integration owns persistence
and calls these functions with one state object per browser session.

``runtime_flag`` is accepted only when a new environment is created.  It is
stored under a private state key and is never included in a bootstrap/public
view.  A vulnerable endpoint may place that value in its normal response data;
the equivalent endpoint refuses or redacts it after ``patched`` is enabled.
This gives the UI a real Web/API interaction surface without a frontend
keyword-based success rule.
"""

from __future__ import annotations

import importlib.util
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from .awdp_js_sandbox import JavaScriptSandboxError, execute_awdp_handler
from ..paths import PROJECT_ROOT


def _load_finals_core():
    """加载决赛十题共享判定引擎（与 dvlaa-awdp-native 容器同一份实现）。"""
    engine_path = PROJECT_ROOT / "integrations" / "targets" / "finals_core.py"
    spec = importlib.util.spec_from_file_location("dvlaa_awdp_finals_core", engine_path)
    if spec is None or spec.loader is None:  # pragma: no cover - 仅在安装不完整时触发
        raise RuntimeError(f"找不到决赛判定引擎：{engine_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_finals_core = _load_finals_core()


LAB_IDS = frozenset(range(1, 31))
_STATE_VERSION = 1


@dataclass(frozen=True)
class LabAction:
    """Public metadata used to render one API-console operation."""

    name: str
    label: str
    method: str
    description: str
    fields: tuple[dict[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "method": self.method,
            "description": self.description,
            "fields": [dict(field) for field in self.fields],
        }


def _field(name: str, label: str, value: str = "", kind: str = "text") -> dict[str, str]:
    return {"name": name, "label": label, "default": value, "type": kind}


_ACTIONS: dict[int, tuple[LabAction, ...]] = {
    1: (
        LabAction("support.export_policy", "导出客服交接策略", "POST", "生成客服交接所需的运行时策略副本。", (
            _field("handoff", "交接类型", "standard"), _field("includeRuntimePolicy", "包含运行时策略", "false", "boolean"),
        )),
    ),
    2: (
        LabAction("migration.import_ticket", "导入迁移工单", "POST", "将外部工单保存到迁移队列。", (
            _field("ticketId", "工单编号", "TK-2048"), _field("customer", "客户名称", "星辰零售"),
            _field("status", "迁移状态", "待预览"), _field("note", "外部工单备注", ""),
        )),
        LabAction("migration.preview_ticket", "生成迁移预览", "POST", "读取已导入工单并生成业务迁移预览。", (_field("ticketId", "工单编号", "TK-2048"),)),
    ),
    3: (
        LabAction("knowledge.import_document", "导入知识库文档", "POST", "向退货政策知识库新增文档及其迁移注释。", (
            _field("documentId", "文档编号", "RET-2026-08"), _field("title", "文档标题", "退货申请期限"),
            _field("body", "政策正文", "退货申请需在签收后 7 天内提交。", "textarea"),
            _field("annotation", "导入注释", "", "textarea"),
        )),
        LabAction("knowledge.search", "检索退货知识库", "GET", "检索政策、期限与凭证说明。", (_field("query", "检索词", "退货申请期限"),)),
    ),
    4: (
        LabAction("workflow.run_tool", "执行流程诊断工具", "POST", "以访客身份请求流程工具的只读诊断结果。", (
            _field("mode", "运行模式", "preview"), _field("tool", "工具名称", "diagnostics"), _field("field", "诊断字段", "node_status"),
        )),
    ),
    5: (
        LabAction("api.request", "发送 Chatflow API 请求", "GET", "在 API 控制台中调用 Flowise 风格路由。", (
            _field("path", "请求路径", "/api/v1/health"), _field("apiKey", "x-api-key", ""),
        )),
    ),
    6: (
        LabAction("dsl.list_apps", "查看可访问应用", "GET", "查看公开应用与当前租户草稿。", ()),
        LabAction("dsl.export", "导出应用 DSL", "POST", "导出应用配置以便发布审计。", (
            _field("appId", "应用 ID", "public-assistant"), _field("role", "请求角色", "viewer"),
        )),
    ),
    7: (
        LabAction("crawler.fetch", "抓取网页资料", "POST", "抓取 URL 并生成资料摘要。", (
            _field("url", "目标 URL", "https://docs.example.test/refund-policy"), _field("followRedirects", "跟随重定向", "true", "boolean"),
        )),
    ),
    8: (
        LabAction("report.execute", "执行财务报表查询", "POST", "生成只读部门收入报表。", (
            _field("statement", "报表查询", "SELECT department, amount FROM revenue WHERE month = '2026-07'", "textarea"),
        )),
    ),
    9: (
        LabAction("documents.view", "查看合同文档", "GET", "在当前租户范围内读取合同摘要。", (
            _field("tenantId", "租户 ID", "tenant-blue"), _field("documentId", "文档 ID", "contract-blue-2026"),
        )),
    ),
    10: (
        LabAction("executions.stop", "停止工作流执行", "POST", "停止当前团队拥有的运行中执行记录。", (
            _field("executionId", "执行 ID", "exec-blue-1042"),
        )),
    ),
}

# 决赛十题（AWDP11-AWDP20）的动作元数据来自共享引擎。
for _final_id in sorted(_finals_core.FINAL_IDS):
    _ACTIONS[_final_id] = tuple(
        LabAction(str(item["name"]), str(item["label"]), str(item["method"]), str(item["description"]),
                  tuple({**field} for field in item["fields"]))
        for item in _finals_core.actions(_final_id)
    )


_LAB_META: dict[int, dict[str, str]] = {
    1: {"title": "S-Spring 客服服务台", "subtitle": "订单、退款与客服交接"},
    2: {"title": "迁移工单中心", "subtitle": "外部工单导入与迁移预览"},
    3: {"title": "退货知识库", "subtitle": "政策文档导入与检索"},
    4: {"title": "流程诊断控制台", "subtitle": "访客流程状态与工具诊断"},
    5: {"title": "Chatflow API 控制台", "subtitle": "运维路由与流程状态"},
    6: {"title": "应用发布中心", "subtitle": "应用 DSL 导出与发布审计"},
    7: {"title": "网页资料抓取器", "subtitle": "公开 HTTPS 资料抓取与摘要"},
    8: {"title": "财务报表工作台", "subtitle": "部门收入统计与只读查询"},
    9: {"title": "多租户合同库", "subtitle": "当前租户合同文档查询"},
    10: {"title": "工作流执行中心", "subtitle": "团队执行记录与停止控制"},
}

# 决赛十题（AWDP11-AWDP20）的界面元数据来自共享引擎。
for _final_id in sorted(_finals_core.FINAL_IDS):
    _final_meta = _finals_core.FINALS_META[_final_id]
    _LAB_META[_final_id] = {"title": _final_meta["title"], "subtitle": _final_meta["subtitle"]}


def _new_records(challenge_id: int) -> dict[str, Any]:
    """Return non-secret, per-environment business data for one service."""
    records: dict[int, dict[str, Any]] = {
        1: {"customer": "访客", "service_hours": "09:00-18:00", "handoffs": []},
        2: {"tickets": {}},
        3: {"documents": [{"id": "RET-BASE", "title": "退货申请政策", "body": "退货申请需在签收后 7 天内提交，并提供订单号与商品状态说明。", "annotation": ""}]},
        4: {"actor": {"id": "guest-27", "role": "guest"}, "nodes": {"validate-order": "healthy", "refund-gateway": "healthy"}},
        5: {"health": {"status": "ok", "version": "1.8.2-lab"}, "admin_flow": {"id": "admin-ops", "name": "Operations Chatflow"}},
        6: {"session": {"user": "viewer-blue", "role": "viewer", "tenant": "tenant-blue"}, "apps": {"public-assistant": {"tenant": "tenant-blue", "visibility": "public"}, "billing-agent": {"tenant": "tenant-red", "visibility": "private"}}},
        7: {"public_documents": {"https://docs.example.test/refund-policy": {"title": "退款政策", "summary": "退货申请期限为 7 天，需提供订单凭证，商品须保持未使用。"}}},
        8: {"session": {"role": "analyst", "tenant": "tenant-blue"}, "revenue": [{"department": "retail", "amount": 124000}, {"department": "service", "amount": 86000}]},
        9: {"session": {"userId": "user-blue-18", "tenant": "tenant-blue"}, "documents": {"tenant-blue": {"contract-blue-2026": {"title": "蓝方续约摘要", "summary": "续约周期 12 个月，服务等级为标准。"}}, "tenant-red": {"contract-red-2026": {"title": "红方供应商合同", "summary": "内部合同摘要，仅限 tenant-red。"}}}},
        10: {"session": {"userId": "operator-blue", "team": "team-blue", "role": "operator"}, "executions": {"exec-blue-1042": {"team": "team-blue", "owner": "operator-blue", "status": "running", "workflow": "订单同步"}, "exec-red-9007": {"team": "team-red", "owner": "operator-red", "status": "running", "workflow": "结算回滚"}}},
    }
    if challenge_id in _finals_core.FINAL_IDS:
        return deepcopy(_finals_core.records(challenge_id))
    return deepcopy(records[challenge_id])


def build_lab_bootstrap(challenge_id: int, runtime_flag: str, *, patched: bool = False) -> dict[str, Any]:
    """Create isolated state for a single browser and AWDP challenge.

    ``runtime_flag`` must be generated by the caller.  It is intentionally
    retained only in ``_runtime_flag``; callers should persist this state but
    must expose it with :func:`public_lab_view`, never directly.
    """
    if challenge_id not in LAB_IDS:
        raise ValueError(f"unsupported AWDP web lab: {challenge_id}")
    if not isinstance(runtime_flag, str) or not runtime_flag.strip():
        raise ValueError("runtime_flag must be a non-empty string")
    return {
        "version": _STATE_VERSION,
        "challenge_id": challenge_id,
        "patched": bool(patched),
        "_runtime_flag": runtime_flag,
        "records": _new_records(challenge_id),
        "audit": [],
    }


def reset_lab_state(challenge_id: int, runtime_flag: str, *, patched: bool = False) -> dict[str, Any]:
    """Reset the service to a clean per-session dataset and a new secret."""
    return build_lab_bootstrap(challenge_id, runtime_flag, patched=patched)


def set_lab_patch_state(state: dict[str, Any], patched: bool) -> dict[str, Any]:
    """Switch the deployed service behavior after patch validation succeeds."""
    _require_state(state)
    state["patched"] = bool(patched)
    _audit(state, "deployment.patch" if patched else "deployment.rollback", 200, "已切换实验环境部署状态")
    return public_lab_view(state)


def public_lab_view(state: Mapping[str, Any]) -> dict[str, Any]:
    """Build the browser-safe application descriptor without private fields."""
    challenge_id = _require_state(state)
    return {
        "challenge_id": challenge_id,
        "title": _LAB_META[challenge_id]["title"],
        "subtitle": _LAB_META[challenge_id]["subtitle"],
        "patched": bool(state.get("patched")),
        "actions": [action.as_dict() for action in _ACTIONS[challenge_id]],
        "audit": [dict(item) for item in list(state.get("audit", []))[-12:]],
    }


def handle_lab_action(
    state: dict[str, Any],
    action: str,
    payload: Mapping[str, Any] | None = None,
    *,
    deployed_source: str | None = None,
) -> dict[str, Any]:
    """Execute one service operation against its isolated state.

    The integration passes only form/JSON data through ``payload``.  Endpoint
    behavior derives from records, authorization context and the deployed
    patch state, rather than a client-side phrase matcher.  The returned value
    is suitable as a JSON response and includes a fresh, flag-free ``lab``
    view.  A caller can use ``exposed`` to record progress; it never needs to
    inspect a response string for a Flag.
    """
    challenge_id = _require_state(state)
    request = dict(payload or {})
    handler = _HANDLERS.get((challenge_id, str(action)))
    if handler is None:
        response = _response(404, "unknown_action", "未找到该实验服务操作。")
    elif bool(state.get("patched")) and _action_uses_deployed_handler(challenge_id, str(action)):
        if not deployed_source:
            response = _response(
                503,
                "deployment_source_missing",
                "修复版本的服务处理器未加载，无法执行当前业务请求。",
            )
        else:
            response = _handle_deployed_action(state, str(action), request, deployed_source)
    else:
        response = handler(state, request)
    _audit(state, str(action), int(response["status"]), str(response["message"]))
    response["lab"] = public_lab_view(state)
    return response


def _require_state(state: Mapping[str, Any]) -> int:
    challenge_id = state.get("challenge_id")
    if not isinstance(challenge_id, int) or challenge_id not in LAB_IDS:
        raise ValueError("invalid AWDP web lab state")
    runtime_flag = state.get("_runtime_flag")
    if not isinstance(runtime_flag, str) or not runtime_flag:
        raise ValueError("AWDP web lab state is missing its runtime secret")
    if not isinstance(state.get("records"), Mapping):
        raise ValueError("AWDP web lab state is missing service records")
    return challenge_id


def _response(status: int, code: str, message: str, data: Mapping[str, Any] | None = None, *, exposed: bool = False) -> dict[str, Any]:
    return {
        "ok": 200 <= status < 300,
        "status": status,
        "code": code,
        "message": message,
        "data": dict(data or {}),
        "exposed": exposed,
    }


def _audit(state: dict[str, Any], action: str, status: int, message: str) -> None:
    events = state.setdefault("audit", [])
    if isinstance(events, list):
        events.append({"action": action[:80], "status": status, "message": message[:160]})
        del events[:-24]


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "on"})


def _text(payload: Mapping[str, Any], key: str, *, limit: int = 4000) -> str:
    value = payload.get(key, "")
    return str(value).strip()[:limit]


def _flag(state: Mapping[str, Any]) -> str:
    return str(state["_runtime_flag"])


def _support_export_policy(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    handoff = _text(payload, "handoff", limit=40) or "standard"
    include_runtime = _truthy(payload.get("includeRuntimePolicy"))
    data: dict[str, Any] = {"handoff": handoff, "serviceHours": state["records"]["service_hours"], "policy": "订单、退款与售后交接流程"}
    if handoff == "legacy" and include_runtime and not state["patched"]:
        data["runtime_verifier"] = _flag(state)
        return _response(200, "legacy_policy_export", "已生成旧版客服交接策略副本。", data, exposed=True)
    if include_runtime:
        data["policy"] = "订单、退款与售后交接流程（运行时字段已脱敏）"
    return _response(200, "policy_export", "已生成客服交接策略副本。", data)


def _migration_import_ticket(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    ticket_id = _text(payload, "ticketId", limit=80)
    if not ticket_id:
        return _response(400, "ticket_id_required", "请提供工单编号。")
    ticket = {"id": ticket_id, "customer": _text(payload, "customer", limit=160) or "未命名客户", "status": _text(payload, "status", limit=80) or "待预览", "note": _text(payload, "note")}
    state["records"]["tickets"][ticket_id] = ticket
    return _response(201, "ticket_imported", "外部工单已导入迁移队列。", {"ticket": {key: value for key, value in ticket.items() if key != "note"}})


def _migration_preview_ticket(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    ticket_id = _text(payload, "ticketId", limit=80)
    ticket = state["records"]["tickets"].get(ticket_id)
    if not isinstance(ticket, Mapping):
        return _response(404, "ticket_not_found", "未找到对应迁移工单。")
    preview: dict[str, Any] = {"ticketId": ticket["id"], "customer": ticket["customer"], "migrationStatus": ticket["status"], "nextStep": "确认字段映射后安排迁移窗口。"}
    note = str(ticket.get("note", ""))
    begins = "BEGIN MIGRATION NOTE" in note.upper()
    ends = "END MIGRATION NOTE" in note.upper()
    if begins and ends and "migration_verifier" in note.lower() and not state["patched"]:
        preview["migration_verifier"] = _flag(state)
        return _response(200, "legacy_note_executed", "旧版迁移执行器已处理外部迁移备注。", preview, exposed=True)
    return _response(200, "migration_preview", "已生成迁移预览。", preview)


def _knowledge_import_document(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    document_id = _text(payload, "documentId", limit=80)
    if not document_id:
        return _response(400, "document_id_required", "请提供文档编号。")
    document = {"id": document_id, "title": _text(payload, "title", limit=200) or "未命名文档", "body": _text(payload, "body"), "annotation": _text(payload, "annotation")}
    documents = state["records"]["documents"]
    documents[:] = [item for item in documents if item.get("id") != document_id]
    documents.append(document)
    return _response(201, "document_imported", "知识库文档已导入，等待检索索引。", {"documentId": document_id, "title": document["title"]})


def _knowledge_search(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    query = _text(payload, "query", limit=300).lower()
    if not query:
        return _response(400, "query_required", "请填写检索词。")
    documents = state["records"]["documents"]
    matches = [item for item in documents if query in (str(item.get("title", "")) + " " + str(item.get("body", ""))).lower()]
    if not matches:
        return _response(200, "no_results", "未检索到匹配的知识库文档。", {"results": []})
    results = [{"id": item["id"], "title": item["title"], "excerpt": item["body"][:280]} for item in matches]
    poison = next((item for item in matches if "kb_verification_code" in str(item.get("annotation", "")).lower()), None)
    if poison is not None and not state["patched"]:
        results[0]["kb_verification_code"] = _flag(state)
        results[0]["annotationApplied"] = True
        return _response(200, "trusted_annotation", "检索器已将导入注释应用到回答上下文。", {"results": results}, exposed=True)
    return _response(200, "knowledge_results", "已返回知识库检索结果。", {"results": results})


def _workflow_run_tool(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    mode, tool, field = (_text(payload, "mode", limit=32), _text(payload, "tool", limit=64), _text(payload, "field", limit=80))
    actor = state["records"]["actor"]
    if mode == "preview" and tool == "code_runner" and field == "WORKFLOW_VERIFIER" and not state["patched"]:
        return _response(200, "preview_tool_dispatched", "旧版 preview 调度器已返回工具诊断结果。", {"tool": tool, "field": field, "value": _flag(state)}, exposed=True)
    if tool == "diagnostics":
        return _response(200, "diagnostics", "已生成安全流程诊断。", {"actor": actor["id"], "nodes": state["records"]["nodes"]})
    return _response(403, "tool_forbidden", "当前访客角色无权调用该工具。")


def _api_request(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    path, api_key = _text(payload, "path", limit=300), _text(payload, "apiKey", limit=300)
    if path == "/api/v1/health":
        return _response(200, "health", "服务健康检查完成。", state["records"]["health"])
    if path == "/api/v1/chatflows/admin-ops" and not api_key and not state["patched"]:
        flow = dict(state["records"]["admin_flow"])
        flow["admin_api_key"] = _flag(state)
        return _response(200, "legacy_public_chatflow", "旧版 Chatflow 路由已返回流程详情。", flow, exposed=True)
    if path.startswith("/api/v1/chatflows/") and not api_key:
        return _response(401, "api_key_required", "Chatflow 路由需要有效的 x-api-key。")
    return _response(404, "route_not_found", "API 控制台未找到该路由。")


def _dsl_export(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    app_id, claimed_role = _text(payload, "appId", limit=100), _text(payload, "role", limit=40)
    app = state["records"]["apps"].get(app_id)
    if app is None:
        return _response(404, "app_not_found", "未找到对应应用。")
    session = state["records"]["session"]
    legacy_authorized = claimed_role == "admin" and not state["patched"]
    session_authorized = (
        app["tenant"] == session["tenant"]
        and (session["role"] == "admin" or app["visibility"] == "public")
    )
    authorized = legacy_authorized or session_authorized
    if not authorized:
        return _response(403, "export_forbidden", "当前会话无权导出该应用 DSL。")
    data: dict[str, Any] = {"appId": app_id, "tenant": app["tenant"], "dsl": {"name": app_id, "nodes": ["input", "llm", "answer"]}}
    if legacy_authorized:
        data["deployment_verifier"] = _flag(state)
        return _response(200, "legacy_export", "旧版导出路由已生成应用 DSL。", data, exposed=True)
    return _response(200, "dsl_export", "已生成应用 DSL。", data)


def _dsl_list_apps(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    session = state["records"]["session"]
    apps = []
    for app_id, app in state["records"]["apps"].items():
        if app["visibility"] == "public" or app["tenant"] == session["tenant"]:
            apps.append({"appId": app_id, "tenant": app["tenant"], "visibility": app["visibility"]})
    return _response(200, "app_catalog", "已返回当前会话可访问的应用。", {"apps": apps})


def _crawler_fetch(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    raw_url = _text(payload, "url", limit=1000)
    follow_redirects = _truthy(payload.get("followRedirects", True))
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return _response(400, "invalid_url", "请输入有效的 HTTP 或 HTTPS URL。")
    if raw_url in state["records"]["public_documents"]:
        return _response(200, "public_document", "已抓取公开网页资料。", state["records"]["public_documents"][raw_url])
    host = parsed.hostname.lower()
    private_target = host in {"169.254.169.254", "metadata.service", "metadata.internal", "127.0.0.1", "::1"} or host.startswith("10.") or host.startswith("192.168.")
    if private_target and not state["patched"]:
        return _response(200, "legacy_fetch", "抓取器已返回上游响应摘要。", {"source": raw_url, "metadata_verifier": _flag(state), "followedRedirects": follow_redirects}, exposed=True)
    if private_target:
        return _response(403, "private_destination_blocked", "安全网关拒绝私网或元数据地址。")
    return _response(404, "fetch_unavailable", "抓取器未找到该公开资料。")


def _report_execute(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    statement = _text(payload, "statement", limit=4000)
    normalized = " ".join(statement.lower().split())
    if not normalized.startswith("select "):
        return _response(400, "readonly_select_required", "报表工作台仅接受只读 SELECT 查询。")
    touches_audit = "audit_log" in normalized or "audit_verifier" in normalized
    if touches_audit and not state["patched"]:
        return _response(200, "unrestricted_report", "旧版查询器已执行报表表达式。", {"columns": ["audit_verifier"], "rows": [{"audit_verifier": _flag(state)}]}, exposed=True)
    if touches_audit:
        return _response(403, "column_not_allowlisted", "报表仅允许 department 与 amount 字段。")
    return _response(200, "revenue_report", "已生成部门收入报表。", {"columns": ["department", "amount"], "rows": state["records"]["revenue"]})


def _documents_view(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    tenant_id, document_id = _text(payload, "tenantId", limit=100), _text(payload, "documentId", limit=120)
    document = state["records"]["documents"].get(tenant_id, {}).get(document_id)
    if document is None:
        return _response(404, "document_not_found", "未找到对应合同文档。")
    session = state["records"]["session"]
    if state["patched"] and tenant_id != session["tenant"]:
        return _response(403, "cross_tenant_denied", "当前会话不允许跨租户读取合同。")
    data = {"tenantId": tenant_id, "documentId": document_id, "title": document["title"], "summary": document["summary"]}
    if tenant_id != session["tenant"]:
        data["contract_verifier"] = _flag(state)
        return _response(200, "legacy_document_lookup", "旧版文档查询已返回合同记录。", data, exposed=True)
    return _response(200, "document", "已返回当前租户合同摘要。", data)


def _executions_stop(state: dict[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    execution_id = _text(payload, "executionId", limit=120)
    execution = state["records"]["executions"].get(execution_id)
    if execution is None:
        return _response(404, "execution_not_found", "未找到对应工作流执行记录。")
    session = state["records"]["session"]
    belongs_to_team = execution["team"] == session["team"]
    if not belongs_to_team and state["patched"]:
        return _response(403, "execution_forbidden", "当前团队无权停止该执行记录。")
    execution["status"] = "stopped"
    data: dict[str, Any] = {"executionId": execution_id, "workflow": execution["workflow"], "status": execution["status"]}
    if not belongs_to_team:
        data["rollback_verifier"] = _flag(state)
        return _response(200, "legacy_stop", "旧版停止路由已终止跨团队执行记录。", data, exposed=True)
    return _response(200, "execution_stopped", "已停止当前团队工作流执行。", data)


_DEPLOYED_SERVICE_ACTIONS = frozenset({
    (1, "support.export_policy"),
    (2, "migration.preview_ticket"),
    (3, "knowledge.search"),
    (4, "workflow.run_tool"),
    (5, "api.request"),
    (6, "dsl.export"),
    (7, "crawler.fetch"),
    (8, "report.execute"),
    (9, "documents.view"),
    (10, "executions.stop"),
})


def _finals_handler(challenge_id: int, action: str) -> Callable[[dict[str, Any], Mapping[str, Any]], dict[str, Any]]:
    """把决赛共享引擎的动作适配为 fixture lab 处理器签名。"""

    def _run(state: dict[str, Any], request: Mapping[str, Any]) -> dict[str, Any]:
        _, response = _finals_core.dispatch(
            challenge_id,
            action,
            request,
            records=state["records"],
            flag=str(state["_runtime_flag"]),
            patched=bool(state.get("patched")),
        )
        return response

    return _run


def _action_uses_deployed_handler(challenge_id: int, action: str) -> bool:
    """Whether an operation is implemented by the submitted JS service."""
    return (challenge_id, action) in _DEPLOYED_SERVICE_ACTIONS


def _deployed_error_response(error: JavaScriptSandboxError) -> dict[str, Any]:
    """Map a repaired handler rejection to a normal HTTP-style service reply."""
    detail = str(error).lower()
    if "unauthorized" in detail or "api key" in detail:
        return _response(401, "api_key_required", "受保护路由需要有效的认证凭据。")
    if "not_found" in detail or "not found" in detail:
        return _response(404, "resource_not_found", "修复后的服务未找到请求的业务资源。")
    if "column_not_allowlisted" in detail:
        return _response(403, "column_not_allowlisted", "报表仅允许已授权的收入字段。")
    if "private destination" in detail or "blocked" in detail:
        return _response(403, "private_destination_blocked", "安全网关拒绝私网、元数据或未验证的抓取目标。")
    if "forbidden" in detail or "denied" in detail:
        return _response(403, "operation_forbidden", "当前会话无权执行该服务操作。")
    return _response(500, "deployed_handler_error", "已部署服务处理器无法完成当前请求。")


def _run_deployed_handler(
    state: dict[str, Any],
    source: str,
    request: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Run an active service handler without exposing host capabilities.

    The JavaScript side only receives a JSON request and a JSON copy of the
    challenge's non-secret records.  It cannot access the Python process,
    network, filesystem, browser session, or per-session Flag.  The returned
    record copy is intentionally not applied wholesale; the owning service
    validates the limited state transition it supports below.
    """
    try:
        execution = execute_awdp_handler(
            source,
            int(state["challenge_id"]),
            request,
            state["records"],
        )
    except JavaScriptSandboxError as exc:
        return None, _deployed_error_response(exc)
    value = execution.get("result")
    if not isinstance(value, Mapping):
        return None, _response(500, "invalid_handler_response", "已部署服务处理器返回了无效的业务响应。")
    return dict(value), None


def _handle_deployed_action(
    state: dict[str, Any],
    action: str,
    payload: Mapping[str, Any],
    source: str,
) -> dict[str, Any]:
    """Route a repaired action through the active ``web_service.js`` source."""
    challenge_id = int(state["challenge_id"])
    records = state["records"]

    if challenge_id == 1 and action == "support.export_policy":
        value, error = _run_deployed_handler(state, source, {
            "body": {
                "handoff": _text(payload, "handoff", limit=40) or "standard",
                "includeRuntimePolicy": _truthy(payload.get("includeRuntimePolicy")),
            },
        })
        if error:
            return error
        return _response(200, "policy_export", "已由修复后的交接服务生成策略副本。", value)

    if challenge_id == 2 and action == "migration.preview_ticket":
        ticket_id = _text(payload, "ticketId", limit=80)
        value, error = _run_deployed_handler(state, source, {"body": {"ticketId": ticket_id}})
        if error:
            return error
        return _response(200, "migration_preview", "已由修复后的迁移服务生成预览。", value)

    if challenge_id == 3 and action == "knowledge.search":
        query = _text(payload, "query", limit=300).lower()
        if not query:
            return _response(400, "query_required", "请填写检索词。")
        matches = [
            item for item in records["documents"]
            if query in (str(item.get("title", "")) + " " + str(item.get("body", ""))).lower()
        ]
        if not matches:
            return _response(200, "no_results", "未检索到匹配的知识库文档。", {"results": []})
        results = []
        for document in matches:
            value, error = _run_deployed_handler(state, source, {"document": dict(document)})
            if error:
                return error
            results.append(value)
        return _response(200, "knowledge_results", "已由修复后的检索服务返回知识库结果。", {"results": results})

    if challenge_id == 4 and action == "workflow.run_tool":
        value, error = _run_deployed_handler(state, source, {
            "body": {
                "mode": _text(payload, "mode", limit=32),
                "tool": _text(payload, "tool", limit=64),
                "field": _text(payload, "field", limit=80),
            },
        })
        if error:
            return error
        return _response(200, "diagnostics", "已由修复后的工具调度器生成诊断。", value)

    if challenge_id == 5 and action == "api.request":
        path = _text(payload, "path", limit=300)
        api_key = _text(payload, "apiKey", limit=300)
        value, error = _run_deployed_handler(state, source, {
            "path": path,
            "headers": {"x-api-key": api_key},
        })
        if error:
            return error
        code = "health" if path == "/api/v1/health" else "authorized_chatflow"
        message = "服务健康检查完成。" if code == "health" else "已由修复后的路由服务返回授权流程。"
        return _response(200, code, message, value)

    if challenge_id == 6 and action == "dsl.export":
        value, error = _run_deployed_handler(state, source, {
            "body": {"appId": _text(payload, "appId", limit=100)},
            "session": dict(records["session"]),
        })
        if error:
            return error
        return _response(200, "dsl_export", "已由修复后的授权服务生成应用 DSL。", value)

    if challenge_id == 7 and action == "crawler.fetch":
        value, error = _run_deployed_handler(state, source, {
            "body": {"url": _text(payload, "url", limit=1000)},
        })
        if error:
            return error
        return _response(200, "public_document", "已由修复后的抓取服务返回公开资料摘要。", value)

    if challenge_id == 8 and action == "report.execute":
        value, error = _run_deployed_handler(state, source, {
            "body": {"statement": _text(payload, "statement", limit=4000)},
        })
        if error:
            return error
        return _response(200, "revenue_report", "已由修复后的报表服务生成收入查询结果。", value)

    if challenge_id == 9 and action == "documents.view":
        tenant_id = _text(payload, "tenantId", limit=100)
        document_id = _text(payload, "documentId", limit=120)
        value, error = _run_deployed_handler(state, source, {
            "query": {"tenantId": tenant_id, "documentId": document_id},
            "session": dict(records["session"]),
        })
        if error:
            return error
        data = {"tenantId": tenant_id, "documentId": document_id, **value}
        return _response(200, "document", "已由修复后的租户服务返回合同摘要。", data)

    if challenge_id == 10 and action == "executions.stop":
        execution_id = _text(payload, "executionId", limit=120)
        value, error = _run_deployed_handler(state, source, {
            "body": {"executionId": execution_id},
            "session": dict(records["session"]),
        })
        if error:
            return error
        execution = records["executions"].get(execution_id)
        if not isinstance(execution, dict) or str(value.get("id", execution_id)) != execution_id:
            return _response(500, "invalid_execution_response", "已部署处理器返回了无效的执行记录。")
        if value.get("status") != "stopped":
            return _response(500, "invalid_execution_status", "已部署处理器未返回停止后的执行状态。")
        execution["status"] = "stopped"
        return _response(200, "execution_stopped", "已由修复后的执行服务停止当前团队工作流。", {
            "executionId": execution_id,
            "workflow": str(value.get("workflow", execution["workflow"])),
            "status": execution["status"],
        })

    return _response(404, "unknown_action", "未找到该实验服务操作。")


_HANDLERS: dict[tuple[int, str], Callable[[dict[str, Any], Mapping[str, Any]], dict[str, Any]]] = {
    (1, "support.export_policy"): _support_export_policy,
    (2, "migration.import_ticket"): _migration_import_ticket,
    (2, "migration.preview_ticket"): _migration_preview_ticket,
    (3, "knowledge.import_document"): _knowledge_import_document,
    (3, "knowledge.search"): _knowledge_search,
    (4, "workflow.run_tool"): _workflow_run_tool,
    (5, "api.request"): _api_request,
    (6, "dsl.list_apps"): _dsl_list_apps,
    (6, "dsl.export"): _dsl_export,
    (7, "crawler.fetch"): _crawler_fetch,
    (8, "report.execute"): _report_execute,
    (9, "documents.view"): _documents_view,
    (10, "executions.stop"): _executions_stop,
}

# 决赛十题（AWDP11-AWDP20）：动作处理全部委派给共享引擎。
for _final_id in sorted(_finals_core.FINAL_IDS):
    for _final_action in _finals_core.actions(_final_id):
        _HANDLERS[(_final_id, str(_final_action["name"]))] = _finals_handler(_final_id, str(_final_action["name"]))


__all__ = [
    "LAB_IDS",
    "LabAction",
    "build_lab_bootstrap",
    "handle_lab_action",
    "public_lab_view",
    "reset_lab_state",
    "set_lab_patch_state",
]
