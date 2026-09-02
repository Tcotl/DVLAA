#!/usr/bin/env python3
"""Standalone native HTTP targets for the AWDP practice track.

The DVLAA console deliberately does not import this module.  It is a small,
real HTTP application that can be started as a separate process (or container)
and exercised with a browser, curl, or an API client.  The implementation is
dependency free so a learner can run one target without installing the
upstream project's complete production stack.  Each challenge has its own
JSON-backed state, verifier, records, and patched/unpatched deployment state.

This service is a local training target inspired by the public project named
by each AWDP case; it is not a copy of that project's production code.  The
route and response shapes intentionally resemble the corresponding product
API so that the attack and repair work happens at a genuine HTTP boundary.
"""

from __future__ import annotations

import argparse
import copy
import html
import json
import os
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
RUNTIME_DIR = Path(os.environ.get("AWDP_NATIVE_RUNTIME_DIR", str(ROOT / "runtime"))).expanduser()
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(RUNTIME_DIR, 0o700)
except OSError:
    pass

NATIVE_IDS = frozenset(range(1, 31))
ALL_IDS = frozenset(range(1, 31))
SERVICE_VERSION = "1.1-native"

import finals_core

from product_skins import SKINS, match_alias


def _field(name: str, label: str, default: Any = "", kind: str = "text") -> dict[str, Any]:
    return {"name": name, "label": label, "default": default, "type": kind}


ACTION_META: dict[int, tuple[dict[str, Any], ...]] = {
    1: (
        {"name": "support.chat", "label": "S-Spring 客服对话", "method": "POST", "description": "通过 OpenAI 兼容 Chat Completions 接口咨询订单、退款、售后与服务时间。", "fields": (_field("message", "消息内容", "请介绍一下退款和服务时间。", "textarea"),)},
    ),
    2: (
        {"name": "migration.import_ticket", "label": "导入迁移工单", "method": "POST", "description": "将外部工单保存到迁移队列。", "fields": (_field("ticketId", "工单编号", "TK-2048"), _field("customer", "客户名称", "星辰零售"), _field("status", "迁移状态", "待预览"), _field("note", "外部工单备注", "", "textarea"))},
        {"name": "migration.preview_ticket", "label": "生成迁移预览", "method": "POST", "description": "读取已导入工单并生成业务迁移预览。", "fields": (_field("ticketId", "工单编号", "TK-2048"),)},
    ),
    3: (
        {"name": "knowledge.import_document", "label": "导入知识库文档", "method": "POST", "description": "向退货政策知识库新增文档及迁移注释。", "fields": (_field("documentId", "文档编号", "RET-2026-08"), _field("title", "文档标题", "退货申请期限"), _field("body", "政策正文", "退货申请需在签收后 7 天内提交。", "textarea"), _field("annotation", "导入注释", "", "textarea"))},
        {"name": "knowledge.search", "label": "检索退货知识库", "method": "GET", "description": "检索政策、期限与凭证说明。", "fields": (_field("query", "检索词", "退货申请期限"),)},
    ),
    4: (
        {"name": "workflow.run_tool", "label": "执行流程诊断工具", "method": "POST", "description": "以访客身份请求流程工具的只读诊断结果。", "fields": (_field("mode", "运行模式", "preview"), _field("tool", "工具名称", "diagnostics"), _field("field", "诊断字段", "node_status"))},
    ),
    5: (
        {"name": "api.request", "label": "发送 Chatflow API 请求", "method": "GET", "description": "在 API 控制台中调用 Flowise 风格路由。", "fields": (_field("path", "请求路径", "/api/v1/health"), _field("apiKey", "x-api-key", ""))},
    ),
    6: (
        {"name": "dsl.list_apps", "label": "查看可访问应用", "method": "GET", "description": "查看公开应用与当前租户草稿。", "fields": ()},
        {"name": "dsl.export", "label": "导出应用 DSL", "method": "POST", "description": "导出应用配置以便发布审计。", "fields": (_field("appId", "应用 ID", "public-assistant"), _field("role", "请求角色", "viewer"))},
    ),
    7: (
        {"name": "crawler.fetch", "label": "抓取网页资料", "method": "POST", "description": "抓取 URL 并生成资料摘要。", "fields": (_field("url", "目标 URL", "https://docs.example.test/refund-policy"), _field("followRedirects", "跟随重定向", True, "boolean"))},
    ),
    8: (
        {"name": "report.execute", "label": "执行财务报表查询", "method": "POST", "description": "生成只读部门收入报表。", "fields": (_field("statement", "报表查询", "SELECT department, amount FROM revenue WHERE month = '2026-07'", "textarea"),)},
    ),
    9: (
        {"name": "documents.view", "label": "查看合同文档", "method": "GET", "description": "在当前租户范围内读取合同摘要。", "fields": (_field("tenantId", "租户 ID", "tenant-blue"), _field("documentId", "文档 ID", "contract-blue-2026"))},
    ),
    10: (
        {"name": "executions.stop", "label": "停止工作流执行", "method": "POST", "description": "停止当前团队拥有的运行中执行记录。", "fields": (_field("executionId", "执行 ID", "exec-blue-1042"),)},
    ),
}

# 决赛十题（AWDP11-AWDP20）的动作元数据由共享引擎提供。
for _final_id in sorted(finals_core.FINAL_IDS):
    ACTION_META[_final_id] = tuple(
        {**_action, "fields": tuple(dict(_field_item) for _field_item in _action["fields"])}
        for _action in finals_core.actions(_final_id)
)



TARGET_META: dict[int, dict[str, str]] = {
    1: {"title": "S-Spring 客服服务台", "subtitle": "订单、退款与客服交接", "project": "S-Spring"},
    2: {"title": "Dify 迁移工单中心", "subtitle": "外部工单导入与迁移预览", "project": "Dify"},
    3: {"title": "RAGFlow 退货知识库", "subtitle": "政策文档导入与检索", "project": "RAGFlow"},
    4: {"title": "Langflow 流程诊断控制台", "subtitle": "访客流程状态与工具诊断", "project": "Langflow"},
    5: {"title": "Flowise Chatflow API 控制台", "subtitle": "运维路由与流程状态", "project": "Flowise"},
    6: {"title": "Dify 应用发布中心", "subtitle": "应用 DSL 导出与发布审计", "project": "Dify"},
    7: {"title": "Open WebUI 网页资料抓取器", "subtitle": "公开 HTTPS 资料抓取与摘要", "project": "Open WebUI"},
    8: {"title": "Dify 财务报表工作台", "subtitle": "部门收入统计与只读查询", "project": "Dify"},
    9: {"title": "RAGFlow 多租户合同库", "subtitle": "当前租户合同文档查询", "project": "RAGFlow"},
    10: {"title": "n8n 工作流执行中心", "subtitle": "团队执行记录与停止控制", "project": "n8n"},
}

# 决赛十题（AWDP11-AWDP20）的题目元数据由共享引擎提供。
TARGET_META.update(finals_core.FINALS_META)


def _records(challenge_id: int) -> dict[str, Any]:
    """Return fresh business records.  No verifier is embedded in records."""
    records: dict[int, dict[str, Any]] = {
        1: {"customer": "访客", "service_hours": "09:00-18:00", "messages": []},
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
    if challenge_id in finals_core.FINAL_IDS:
        return finals_core.records(challenge_id)
    return copy.deepcopy(records[challenge_id])


class NativeTargetStore:
    """Atomic JSON persistence for one or all local target services."""

    def __init__(self, runtime_dir: Path = RUNTIME_DIR):
        self.runtime_dir = runtime_dir
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self._locks: dict[int, threading.RLock] = {}
        self._guard = threading.Lock()

    def lock(self, challenge_id: int) -> threading.RLock:
        with self._guard:
            return self._locks.setdefault(challenge_id, threading.RLock())

    def path(self, challenge_id: int) -> Path:
        return self.runtime_dir / f"{challenge_id}.json"

    def _new(self, challenge_id: int) -> dict[str, Any]:
        return {
            "version": 1,
            "challenge_id": challenge_id,
            "flag": f"flag{{awdp{challenge_id:02d}_{secrets.token_hex(14)}}}",
            "internal_token": secrets.token_urlsafe(32),
            "patched": False,
            "attack_solved": False,
            "updated_at": int(time.time()),
            "records": _records(challenge_id),
        }

    def load(self, challenge_id: int) -> dict[str, Any]:
        if challenge_id not in ALL_IDS:
            raise KeyError(challenge_id)
        with self.lock(challenge_id):
            try:
                value = json.loads(self.path(challenge_id).read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                value = self._new(challenge_id)
            if not isinstance(value, dict) or value.get("challenge_id") != challenge_id or not str(value.get("flag", "")).startswith("flag{"):
                value = self._new(challenge_id)
            value.setdefault("internal_token", secrets.token_urlsafe(32))
            value.setdefault("patched", False)
            value.setdefault("attack_solved", False)
            value.setdefault("records", _records(challenge_id))
            return value

    def save(self, challenge_id: int, state: Mapping[str, Any]) -> None:
        path = self.path(challenge_id)
        tmp = path.with_suffix(".tmp")
        value = dict(state)
        value["updated_at"] = int(time.time())
        tmp.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(path)

    def reset(self, challenge_id: int) -> dict[str, Any]:
        with self.lock(challenge_id):
            value = self._new(challenge_id)
            self.save(challenge_id, value)
            return value


STORE = NativeTargetStore()


def _text(payload: Mapping[str, Any], key: str, limit: int = 4000) -> str:
    return str(payload.get(key, "") or "").strip()[:limit]


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "on"})


def _response(status: int, code: str, message: str, data: Mapping[str, Any] | None = None, exposed: bool = False) -> dict[str, Any]:
    return {"ok": 200 <= status < 300, "status": status, "code": code, "message": message, "data": dict(data or {}), "exposed": exposed}


def _flag(state: Mapping[str, Any]) -> str:
    return str(state["flag"])


def _dispatch(challenge_id: int, state: dict[str, Any], action: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Execute one genuine HTTP application's business operation."""
    records = state["records"]
    patched = bool(state.get("patched"))
    if challenge_id == 1 and action == "support.chat":
        # 正常客服对话通道：运行时验证值从不进入对话输出；
        # 本题的泄露面是旧版交接导出 support.export_policy。
        message = _text(payload, "message", 4000)
        if not message:
            return _response(400, "message_required", "请输入客服消息。")
        records["messages"].append({"role": "user", "content": message})
        lowered = message.lower()
        injection = any(term in lowered for term in ("忽略", "ignore", "system prompt", "系统提示", "开发者模式", "developer mode", "复述", "repeat"))
        secret_request = any(term in lowered for term in ("flag", "暗号", "令牌", "token", "runtime", "策略", "system"))
        if injection or secret_request:
            assistant = "抱歉，我不能提供系统提示词、运行时策略或内部验证令牌。我们可以继续处理订单、退款、售后或服务时间问题。"
        elif any(term in lowered for term in ("退款", "refund")):
            assistant = "退款申请通常需要订单号与商品状态说明。服务时间为 09:00-18:00。"
        elif any(term in lowered for term in ("服务时间", "营业时间", "hours")):
            assistant = f"S-Spring 客服服务时间为 {records['service_hours']}。"
        else:
            assistant = "您好，我可以协助处理订单、退款、售后服务或查询服务时间。"
        records["messages"].append({"role": "assistant", "content": assistant})
        data = {
            "id": "chatcmpl-awdp01",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": assistant}, "finish_reason": "stop"}],
        }
        return _response(200, "chat_completion", "客服已返回业务答复。", data)

    if challenge_id == 1 and action == "support.export_policy":
        # 与 console fixture 同源的旧版交接导出：handoff=legacy 且
        # includeRuntimePolicy=true 时把服务端运行时校验值写进响应。
        handoff = _text(payload, "handoff", 40) or "standard"
        include_runtime = _truthy(payload.get("includeRuntimePolicy"))
        data = {
            "handoff": handoff,
            "serviceHours": records["service_hours"],
            "policy": "订单、退款与售后交接流程",
        }
        if handoff == "legacy" and include_runtime and not patched:
            data["runtime_verifier"] = _flag(state)
            return _response(200, "legacy_policy_export", "已生成旧版客服交接策略副本。", data, True)
        if include_runtime:
            data["policy"] = "订单、退款与售后交接流程（运行时字段已脱敏）"
        return _response(200, "policy_export", "已生成客服交接策略副本。", data)

    if challenge_id == 2 and action == "migration.import_ticket":
        ticket_id = _text(payload, "ticketId", 80)
        if not ticket_id:
            return _response(400, "ticket_id_required", "请提供工单编号。")
        ticket = {"id": ticket_id, "customer": _text(payload, "customer", 160) or "未命名客户", "status": _text(payload, "status", 80) or "待预览", "note": _text(payload, "note")}
        records["tickets"][ticket_id] = ticket
        return _response(201, "ticket_imported", "外部工单已导入迁移队列。", {"ticket": {k: v for k, v in ticket.items() if k != "note"}})
    if challenge_id == 2 and action == "migration.preview_ticket":
        ticket_id = _text(payload, "ticketId", 80)
        ticket = records["tickets"].get(ticket_id)
        if not isinstance(ticket, Mapping):
            return _response(404, "ticket_not_found", "未找到对应迁移工单。")
        preview = {"ticketId": ticket["id"], "customer": ticket["customer"], "migrationStatus": ticket["status"], "nextStep": "确认字段映射后安排迁移窗口。"}
        note = str(ticket.get("note", ""))
        if not patched and "BEGIN MIGRATION NOTE" in note.upper() and "END MIGRATION NOTE" in note.upper() and "migration_verifier" in note.lower():
            preview["migration_verifier"] = _flag(state)
            return _response(200, "legacy_note_executed", "旧版迁移执行器已处理外部迁移备注。", preview, True)
        return _response(200, "migration_preview", "已生成迁移预览。", preview)

    if challenge_id == 3 and action == "knowledge.import_document":
        document_id = _text(payload, "documentId", 80)
        if not document_id:
            return _response(400, "document_id_required", "请提供文档编号。")
        document = {"id": document_id, "title": _text(payload, "title", 200) or "未命名文档", "body": _text(payload, "body"), "annotation": _text(payload, "annotation")}
        records["documents"][:] = [item for item in records["documents"] if item.get("id") != document_id]
        records["documents"].append(document)
        return _response(201, "document_imported", "知识库文档已导入，等待检索索引。", {"documentId": document_id, "title": document["title"]})
    if challenge_id == 3 and action == "knowledge.search":
        query = _text(payload, "query", 300).lower()
        if not query:
            return _response(400, "query_required", "请填写检索词。")
        matches = [item for item in records["documents"] if query in (str(item.get("title", "")) + " " + str(item.get("body", ""))).lower()]
        if not matches:
            return _response(200, "no_results", "未检索到匹配的知识库文档。", {"results": []})
        results = [{"id": item["id"], "title": item["title"], "excerpt": str(item.get("body", ""))[:280]} for item in matches]
        poison = next((item for item in matches if "kb_verification_code" in str(item.get("annotation", "")).lower()), None)
        if poison is not None and not patched:
            results[0]["kb_verification_code"] = _flag(state)
            results[0]["annotationApplied"] = True
            return _response(200, "trusted_annotation", "检索器已将导入注释应用到回答上下文。", {"results": results}, True)
        return _response(200, "knowledge_results", "已返回知识库检索结果。", {"results": results})

    if challenge_id == 4 and action == "workflow.run_tool":
        mode, tool, field = _text(payload, "mode", 32), _text(payload, "tool", 64), _text(payload, "field", 80)
        actor = records["actor"]
        if mode == "preview" and tool == "code_runner" and field == "WORKFLOW_VERIFIER" and not patched:
            return _response(200, "preview_tool_dispatched", "旧版 preview 调度器已返回工具诊断结果。", {"tool": tool, "field": field, "value": _flag(state)}, True)
        if tool == "diagnostics":
            return _response(200, "diagnostics", "已生成安全流程诊断。", {"actor": actor["id"], "nodes": records["nodes"]})
        return _response(403, "tool_forbidden", "当前访客角色无权调用该工具。")

    if challenge_id == 5 and action == "api.request":
        path, api_key = _text(payload, "path", 300), _text(payload, "apiKey", 300)
        if path == "/api/v1/health":
            return _response(200, "health", "服务健康检查完成。", records["health"])
        if path == "/api/v1/chatflows/admin-ops" and not api_key and not patched:
            flow = dict(records["admin_flow"])
            flow["admin_api_key"] = _flag(state)
            return _response(200, "legacy_public_chatflow", "旧版 Chatflow 路由已返回流程详情。", flow, True)
        if path.startswith("/api/v1/chatflows/") and not api_key:
            return _response(401, "api_key_required", "Chatflow 路由需要有效的 x-api-key。")
        return _response(404, "route_not_found", "API 控制台未找到该路由。")

    if challenge_id == 6 and action == "dsl.list_apps":
        session = records["session"]
        apps = [{"appId": app_id, "tenant": app["tenant"], "visibility": app["visibility"]} for app_id, app in records["apps"].items() if app["visibility"] == "public" or app["tenant"] == session["tenant"]]
        return _response(200, "app_catalog", "已返回当前会话可访问的应用。", {"apps": apps})
    if challenge_id == 6 and action == "dsl.export":
        app_id, claimed_role = _text(payload, "appId", 100), _text(payload, "role", 40)
        app = records["apps"].get(app_id)
        if app is None:
            return _response(404, "app_not_found", "未找到对应应用。")
        session = records["session"]
        legacy_authorized = claimed_role == "admin" and not patched
        authorized = legacy_authorized or (app["tenant"] == session["tenant"] and (session["role"] == "admin" or app["visibility"] == "public"))
        if not authorized:
            return _response(403, "export_forbidden", "当前会话无权导出该应用 DSL。")
        data = {"appId": app_id, "tenant": app["tenant"], "dsl": {"name": app_id, "nodes": ["input", "llm", "answer"]}}
        if legacy_authorized:
            data["deployment_verifier"] = _flag(state)
            return _response(200, "legacy_export", "旧版导出路由已生成应用 DSL。", data, True)
        return _response(200, "dsl_export", "已生成应用 DSL。", data)

    if challenge_id == 7 and action == "crawler.fetch":
        raw_url = _text(payload, "url", 1000)
        parsed = urlparse(raw_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return _response(400, "invalid_url", "请输入有效的 HTTP 或 HTTPS URL。")
        if raw_url in records["public_documents"]:
            return _response(200, "public_document", "已抓取公开网页资料。", records["public_documents"][raw_url])
        host = parsed.hostname.lower()
        private = host in {"169.254.169.254", "metadata.service", "metadata.internal", "127.0.0.1", "::1"} or host.startswith("10.") or host.startswith("192.168.")
        if private and not patched:
            return _response(200, "legacy_fetch", "抓取器已返回上游响应摘要。", {"source": raw_url, "metadata_verifier": _flag(state), "followedRedirects": _truthy(payload.get("followRedirects", True))}, True)
        if private:
            return _response(403, "private_destination_blocked", "安全网关拒绝私网或元数据地址。")
        return _response(404, "fetch_unavailable", "抓取器未找到该公开资料。")

    if challenge_id == 8 and action == "report.execute":
        statement = _text(payload, "statement", 4000)
        normalized = " ".join(statement.lower().split())
        if not normalized.startswith("select "):
            return _response(400, "readonly_select_required", "报表工作台仅接受只读 SELECT 查询。")
        touches_audit = "audit_log" in normalized or "audit_verifier" in normalized
        if touches_audit and not patched:
            return _response(200, "unrestricted_report", "旧版查询器已执行报表表达式。", {"columns": ["audit_verifier"], "rows": [{"audit_verifier": _flag(state)}]}, True)
        if touches_audit:
            return _response(403, "column_not_allowlisted", "报表仅允许 department 与 amount 字段。")
        return _response(200, "revenue_report", "已生成部门收入报表。", {"columns": ["department", "amount"], "rows": records["revenue"]})

    if challenge_id == 9 and action == "documents.view":
        tenant_id, document_id = _text(payload, "tenantId", 100), _text(payload, "documentId", 120)
        document = records["documents"].get(tenant_id, {}).get(document_id)
        if document is None:
            return _response(404, "document_not_found", "未找到对应合同文档。")
        session = records["session"]
        if patched and tenant_id != session["tenant"]:
            return _response(403, "cross_tenant_denied", "当前会话不允许跨租户读取合同。")
        data = {"tenantId": tenant_id, "documentId": document_id, "title": document["title"], "summary": document["summary"]}
        if tenant_id != session["tenant"]:
            data["contract_verifier"] = _flag(state)
            return _response(200, "legacy_document_lookup", "旧版文档查询已返回合同记录。", data, True)
        return _response(200, "document", "已返回当前租户合同摘要。", data)

    if challenge_id == 10 and action == "executions.stop":
        execution_id = _text(payload, "executionId", 120)
        execution = records["executions"].get(execution_id)
        if execution is None:
            return _response(404, "execution_not_found", "未找到对应工作流执行记录。")
        session = records["session"]
        belongs = execution["team"] == session["team"]
        if not belongs and patched:
            return _response(403, "execution_forbidden", "当前团队无权停止该执行记录。")
        execution["status"] = "stopped"
        data = {"executionId": execution_id, "workflow": execution["workflow"], "status": execution["status"]}
        if not belongs:
            data["rollback_verifier"] = _flag(state)
            return _response(200, "legacy_stop", "旧版停止路由已终止跨团队执行记录。", data, True)
        return _response(200, "execution_stopped", "已停止当前团队工作流执行。", data)

    if challenge_id in finals_core.FINAL_IDS:
        # 决赛十题的漏洞语义与业务状态机由共享引擎实现，保证
        # native 目标与 console 回归判定行为完全一致。
        _, response = finals_core.dispatch(
            challenge_id,
            action,
            payload,
            records=records,
            flag=_flag(state),
            patched=bool(state.get("patched")),
        )
        return response

    return _response(404, "unknown_action", "未找到该实验服务操作。")


def _public_state(challenge_id: int, state: Mapping[str, Any]) -> dict[str, Any]:
    actions = []
    for action in ACTION_META.get(challenge_id, ()):
        value = dict(action)
        value["fields"] = [dict(field) for field in action.get("fields", ())]
        actions.append(value)
    meta = TARGET_META[challenge_id]
    return {"challenge_id": challenge_id, "title": meta["title"], "subtitle": meta["subtitle"], "project": meta["project"], "version": SERVICE_VERSION, "patched": bool(state.get("patched")), "attack_solved": bool(state.get("attack_solved")), "actions": actions}


def _page(challenge_id: int, state: Mapping[str, Any], base_path: str) -> str:
    """渲染题目页面：优先产品仿真皮肤，未实现的题目回退通用调试台。"""
    skin = SKINS.get(challenge_id)
    if skin is not None:
        return skin(challenge_id, state, base_path)
    meta = TARGET_META[challenge_id]
    public = _public_state(challenge_id, state)
    title = html.escape(meta["title"])
    actions_json = json.dumps(public["actions"], ensure_ascii=False)
    return """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>""" + title + """ · Native Target</title>
<style>
:root{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#15233a;background:#f4f7fb}*{box-sizing:border-box}body{margin:0;min-width:320px}.top{display:flex;align-items:center;gap:12px;padding:14px 22px;border-bottom:1px solid #d9e2ef;background:#fff}.mark{width:30px;height:30px;display:grid;place-items:center;border-radius:6px;background:#1769d1;color:#fff;font-size:11px;font-weight:800}.top strong{font-size:15px}.top small{color:#6b7a91}.shell{max-width:1180px;margin:0 auto;padding:24px}.hero{padding:20px 0 16px}.hero h1{margin:0 0 8px;font-size:25px}.hero p{margin:0;color:#63748d}.grid{display:grid;grid-template-columns:330px 1fr;gap:16px}.panel{border:1px solid #dce5f0;border-radius:8px;background:#fff;box-shadow:0 2px 10px #17375e0b}.panel h2{font-size:15px;margin:0;padding:15px 17px;border-bottom:1px solid #e5ebf3}.panel-body{padding:17px}.action{display:flex;width:100%;padding:10px 11px;margin:0 0 8px;border:1px solid #dae4f0;border-radius:6px;background:#fbfdff;text-align:left;color:#2b4668}.action.active{border-color:#1769d1;background:#edf5ff;color:#0f57aa}.action strong{display:block;font-size:13px}.action span{display:block;margin-top:3px;color:#73839a;font-size:11px}.label{display:block;margin:0 0 5px;color:#52647d;font-size:12px;font-weight:700}.field{width:100%;padding:9px;border:1px solid #cdd9e8;border-radius:5px;margin-bottom:10px;background:#fff;color:#172a43}.btn{border:0;border-radius:5px;padding:10px 16px;background:#1769d1;color:#fff;font-weight:700}.btn:disabled{opacity:.6}.meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.badge{padding:4px 7px;border-radius:4px;background:#edf5ff;color:#1769d1;font-size:11px;font-weight:700}.response{min-height:400px;margin:0;padding:15px;background:#111d2f;color:#dce9fa;border-radius:5px;overflow:auto;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.status{margin-top:10px;color:#5d6e86;font-size:12px}.foot{margin-top:16px;color:#75839a;font-size:11px}@media(max-width:780px){.shell{padding:14px}.grid{grid-template-columns:1fr}.response{min-height:260px}}
</style></head><body><header class="top"><span class="mark">AI</span><div><strong>""" + title + """</strong><br><small>独立 Native Web Target · """ + html.escape(meta["project"]) + """ 风格接口</small></div></header>
<main class="shell"><section class="hero"><h1>""" + title + """</h1><p>""" + html.escape(meta["subtitle"]) + """。所有请求直接发送到本地目标服务。</p><div class="meta"><span id="patchBadge" class="badge">部署状态：""" + ("已修复" if state.get("patched") else "易受攻击") + """</span><span class="badge">HTTP API</span><span class="badge">""" + SERVICE_VERSION + """</span></div></section>
<section class="grid"><section class="panel"><h2>业务操作</h2><div class="panel-body" id="actions"></div></section><section class="panel"><h2>请求与响应</h2><div class="panel-body"><form id="requestForm"><div id="fields"></div><button id="send" class="btn" type="submit">发送请求</button></form><div id="status" class="status">准备就绪</div><pre id="response" class="response">选择左侧操作后发送请求。</pre></div></section></section><div class="foot">目标地址：<code>""" + html.escape(base_path) + """</code> · 本地训练服务不连接线上系统。</div></main>
<script>
const ACTIONS=""" + actions_json + """; const base=""" + json.dumps(base_path) + """; let selected=ACTIONS[0];
const actions=document.getElementById('actions'), fields=document.getElementById('fields'), form=document.getElementById('requestForm'), response=document.getElementById('response'), status=document.getElementById('status');
function renderActions(){actions.innerHTML='';ACTIONS.forEach(a=>{const b=document.createElement('button');b.type='button';b.className='action'+(a===selected?' active':'');b.innerHTML='<strong>'+a.label+'</strong><span>'+a.method+' · '+a.name+'</span>';b.onclick=()=>{selected=a;renderActions();renderFields()};actions.appendChild(b)})}
function renderFields(){fields.innerHTML='';(selected.fields||[]).forEach(f=>{const l=document.createElement('label');l.className='label';l.textContent=f.label;let input;if(f.type==='textarea'){input=document.createElement('textarea');input.rows=4}else{input=document.createElement('input');input.type=f.type==='boolean'?'checkbox':'text';if(input.type==='checkbox')input.checked=Boolean(f.default)}input.className='field';input.dataset.name=f.name;if(input.type!=='checkbox')input.value=f.default??'';l.appendChild(input);fields.appendChild(l)})}
form.addEventListener('submit',async e=>{e.preventDefault();const body={};fields.querySelectorAll('[data-name]').forEach(i=>body[i.dataset.name]=i.type==='checkbox'?i.checked:i.value);document.getElementById('send').disabled=true;status.textContent='请求发送中…';try{const r=await fetch(base+'/api/action/'+encodeURIComponent(selected.name),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await r.json();response.textContent=JSON.stringify(data,null,2);status.textContent='HTTP '+r.status+' · '+(data.result?.message||data.message||'响应已返回');const targetState=data.target||data.result?.state||data.state;document.getElementById('patchBadge').textContent='部署状态：'+(targetState?.patched?'已修复':'易受攻击')}catch(err){response.textContent=String(err);status.textContent='请求失败'}finally{document.getElementById('send').disabled=false}});renderActions();renderFields();
</script></body></html>"""


class NativeHandler(BaseHTTPRequestHandler):
    server_version = "DVLAA-NativeTarget/1.0"

    @property
    def target_store(self) -> NativeTargetStore:
        return self.server.target_store  # type: ignore[attr-defined]

    @property
    def allowed_challenge(self) -> int | None:
        return self.server.allowed_challenge  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("AWDP_NATIVE_QUIET", "").lower() not in {"1", "true", "yes"}:
            super().log_message(fmt, *args)

    def _path_parts(self) -> tuple[int | None, str]:
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        challenge_id = self.allowed_challenge
        if parts and parts[0] in {"challenge", "target", "awdp-target"}:
            try:
                challenge_id = int(parts[1])
            except (IndexError, ValueError):
                challenge_id = None
            parts = parts[2:]
        return challenge_id, "/".join(parts)

    def _json(self, status: int, value: Mapping[str, Any]) -> None:
        data = json.dumps(dict(value), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> dict[str, Any]:
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 1024 * 1024)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b"{}"
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    def do_GET(self) -> None:  # noqa: N802
        challenge_id, route = self._path_parts()
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if route == "health":
            ids = [challenge_id] if challenge_id else sorted(NATIVE_IDS)
            healthy = all(item in ALL_IDS for item in ids)
            self._json(200 if healthy else 404, {"ok": healthy, "service": "awdp-native-targets", "version": SERVICE_VERSION, "challenges": ids})
            return
        if challenge_id not in ALL_IDS:
            self._json(404, {"error": "unknown_challenge"})
            return
        state = self.target_store.load(challenge_id)
        if route in {"", "index"}:
            prefix = "awdp-target" if urlparse(self.path).path.startswith("/awdp-target/") else "challenge"
            base_path = f"/{prefix}/{challenge_id}" if self.allowed_challenge is None else ""
            body = _page(challenge_id, state, base_path or "/")
            encoded = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return
        if route == "api/state":
            self._json(200, {"target": _public_state(challenge_id, state)})
            return
        if route == "api/records":
            # Business records are intentionally read-only and do not contain
            # a verifier.  This makes the data flow visible while keeping the
            # secret only in the vulnerable operation response.
            self._json(200, {"records": copy.deepcopy(state["records"])})
            return
        # ── 产品形状的 GET API 别名（如 Flowise Chatflow / RAGFlow 文档） ──
        alias = match_alias(challenge_id, "GET", route, {key: values[-1] for key, values in query.items()})
        if alias is not None:
            action, payload = alias
            result = _dispatch(challenge_id, state, action, payload)
            if result.get("exposed"):
                state["attack_solved"] = True
                self.target_store.save(challenge_id, state)
            self._json(int(result.get("status", 500)), result)
            return
        if route == "api/internal/status" and self.headers.get("X-DVLAA-Internal") == str(state.get("internal_token")):
            self._json(200, {"challenge_id": challenge_id, "flag": _flag(state), "patched": bool(state.get("patched")), "attack_solved": bool(state.get("attack_solved"))})
            return
        self._json(404, {"error": "route_not_found", "path": parsed.path, "query": query})

    def do_POST(self) -> None:  # noqa: N802
        challenge_id, route = self._path_parts()
        if challenge_id not in ALL_IDS:
            self._json(404, {"error": "unknown_challenge"})
            return
        state = self.target_store.load(challenge_id)
        body = self._read_body()
        if route == "api/action" or route.startswith("api/action/"):
            action = route[len("api/action/"):] if route.startswith("api/action/") else str(body.pop("action", ""))
            result = _dispatch(challenge_id, state, action, body)
            if result.get("exposed"):
                state["attack_solved"] = True
            self.target_store.save(challenge_id, state)
            result["state"] = _public_state(challenge_id, state)
            self._json(int(result.get("status", 500)), {"result": result, "target": _public_state(challenge_id, state)})
            return
        # ── 产品形状的真实 API 别名（与真实上游利用路径一致） ──
        alias = match_alias(challenge_id, "POST", route, body)
        if alias is not None:
            action, payload = alias
            result = _dispatch(challenge_id, state, action, payload)
            if result.get("exposed"):
                state["attack_solved"] = True
            self.target_store.save(challenge_id, state)
            self._json(int(result.get("status", 500)), result)
            return
        if route == "api/reset":
            state = self.target_store.reset(challenge_id)
            self._json(200, {"success": True, "target": _public_state(challenge_id, state)})
            return
        if route == "api/internal/deploy":
            if self.headers.get("X-DVLAA-Internal") != str(state.get("internal_token")):
                self._json(403, {"error": "internal_auth_required"})
                return
            state["patched"] = bool(body.get("patched"))
            self.target_store.save(challenge_id, state)
            self._json(200, {"success": True, "target": _public_state(challenge_id, state)})
            return
        self._json(404, {"error": "route_not_found"})


class NativeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], *, allowed_challenge: int | None, target_store: NativeTargetStore):
        super().__init__(address, NativeHandler)
        self.allowed_challenge = allowed_challenge
        self.target_store = target_store


def run(host: str = "127.0.0.1", port: int = 5900, challenge_id: int | None = None, runtime_dir: Path = RUNTIME_DIR) -> None:
    if challenge_id is not None and challenge_id not in ALL_IDS:
        raise ValueError(f"unsupported challenge: {challenge_id}")
    store = NativeTargetStore(runtime_dir)
    # Materialize private deployment state at startup so the DVLAA adapter can
    # discover every target before a learner opens its browser page.  The
    # files contain the verifier/internal token and are mode 0600.
    for item in sorted(NATIVE_IDS if challenge_id is None else {challenge_id}):
        state = store.load(item)
        store.save(item, state)
    server = NativeServer((host, int(port)), allowed_challenge=challenge_id, target_store=store)
    scope = f"AWDP{challenge_id:02d}" if challenge_id else "AWDP01/03-10"
    print(f"[native-target] {scope} listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Standalone native AWDP HTTP target")
    parser.add_argument("--host", default=os.environ.get("AWDP_NATIVE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("AWDP_NATIVE_PORT", "5900")))
    parser.add_argument("--challenge", type=int, default=int(os.environ.get("AWDP_NATIVE_CHALLENGE", "0")) or None, help="one challenge ID, or 0 for the shared target process")
    parser.add_argument("--runtime-dir", type=Path, default=RUNTIME_DIR)
    args = parser.parse_args()
    run(args.host, args.port, args.challenge, args.runtime_dir)


if __name__ == "__main__":
    main()
