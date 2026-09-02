"""DVLAA 统一审计事件模型。

该模块只负责生成、脱敏、迁移和投影 AuditEvent，不参与任何题目判定。
事件可以记录业务动作与安全证据，但绝不保存 Flag、令牌、API Key、完整
提示词、完整用户输入或完整敏感响应。旧版 AWDP 的 ``audit`` 和
``submissions`` 字段通过投影继续兼容现有前端。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any, Callable, Iterable, Mapping

MAX_EVENTS = 64
_MAX_TEXT = 500
_FLAG_RE = re.compile(r"flag\{[^}\r\n]{1,256}\}", re.IGNORECASE)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:flag|token|secret|password|passwd|api[_-]?key|credential|authorization|internal[_-]?key)",
    re.IGNORECASE,
)


def _json_default(value: Any) -> str:
    return repr(value)


def _digest(value: Any, secret: str = "dvlaa-audit") -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, default=_json_default, separators=(",", ":"))
    return hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def session_digest(session_id: str | None, secret: str = "dvlaa-audit") -> str:
    """返回不可逆会话标识，避免在事件中保存 Flask session id。"""
    return _digest(str(session_id or "anonymous"), secret)[:24]


def input_digest(value: Any, secret: str = "dvlaa-audit") -> dict[str, Any]:
    """返回输入摘要；摘要不包含输入原文。"""
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, default=_json_default, separators=(",", ":"))
    return {"hmac": _digest(value, secret), "length": len(raw)}


def _sanitize(value: Any, key: str = "") -> Any:
    """递归删除敏感值并截断文本，保证事件可公开展示。"""
    if _SENSITIVE_KEY_RE.search(key):
        return "[已脱敏]"
    if isinstance(value, str):
        value = _FLAG_RE.sub("flag{REDACTED}", value)
        if len(value) > _MAX_TEXT:
            value = value[:_MAX_TEXT] + "…"
        return value
    if isinstance(value, Mapping):
        return {str(k): _sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, key) for item in value[:32]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _sanitize(str(value), key)


def emit_event(
    *,
    event_type: str,
    phase: str,
    challenge_id: int | str,
    action: str,
    outcome: str,
    message: str = "",
    session_id: str | None = None,
    actor: str = "",
    route: str = "",
    verdict: str | None = None,
    http_status: int | None = None,
    input_value: Any = None,
    data_classification: Iterable[str] = (),
    security_findings: Iterable[str] = (),
    invariant_results: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    secret: str = "dvlaa-audit",
    event_id_factory: Callable[[], str] | None = None,
    clock: Callable[[], int] | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """生成脱敏 canonical AuditEvent。"""
    event_id = event_id or (event_id_factory() if event_id_factory else f"evt_{secrets.token_hex(8)}")
    created_at = int(clock() if clock else time.time())
    event = {
        "schema_version": 1,
        "id": str(event_id),
        "created_at": created_at,
        "event_type": str(event_type),
        "phase": str(phase),
        "challenge_id": int(challenge_id) if str(challenge_id).isdigit() else str(challenge_id),
        "session_hash": session_digest(session_id, secret),
        "actor": str(actor)[:120],
        "action": str(action)[:160],
        "route": str(route)[:240],
        "outcome": str(outcome)[:80],
        "verdict": str(verdict)[:120] if verdict is not None else None,
        "http_status": int(http_status) if http_status is not None else None,
        "message": _sanitize(message),
        "input_digest": input_digest(input_value, secret) if input_value is not None else None,
        "data_classification": [str(item)[:80] for item in list(data_classification)[:16]],
        "security_findings": [str(item)[:120] for item in list(security_findings)[:16]],
        "invariant_results": _sanitize(dict(invariant_results or {})),
        "metadata": _sanitize(dict(metadata or {})),
    }
    return event


def append_events(events: Iterable[Mapping[str, Any]], event: Mapping[str, Any], limit: int = MAX_EVENTS) -> list[dict[str, Any]]:
    """追加事件并按上限保留最新记录。"""
    values = [dict(item) for item in events]
    event_id = event.get("id")
    if event_id and any(item.get("id") == event_id for item in values):
        return values[-max(1, int(limit)) :]
    values.append(dict(event))
    return values[-max(1, int(limit)) :]


def project_legacy_audit(event: Mapping[str, Any]) -> dict[str, Any]:
    """把 canonical 事件投影为旧版 Web 审计日志。"""
    return {
        "action": str(event.get("action", "")),
        "status": int(event.get("http_status") or 0),
        "message": str(event.get("message", "")),
    }


def project_legacy_submission(event: Mapping[str, Any]) -> dict[str, Any]:
    """把 patch/flag 事件投影为现有提交记录字段，不包含提交的 Flag。"""
    metadata = event.get("metadata") if isinstance(event.get("metadata"), Mapping) else {}
    return {
        "id": str(event.get("id", "")),
        "type": str(metadata.get("submission_type") or event.get("event_type", "")),
        "content": str(event.get("message", "")),
        "filename": str(metadata.get("filename", "")),
        "created_at": int(event.get("created_at") or 0),
        "status": str(event.get("verdict") or event.get("outcome", "")),
        "logs": list(metadata.get("logs", [])) if isinstance(metadata.get("logs"), list) else [],
    }


def _legacy_event_id(kind: str, index: int, value: Mapping[str, Any]) -> str:
    raw = json.dumps({"kind": kind, "index": index, "value": value}, ensure_ascii=False, sort_keys=True, default=_json_default)
    return "evt_legacy_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def migrate_legacy_events(
    legacy_audit: Iterable[Mapping[str, Any]] = (),
    submissions: Iterable[Mapping[str, Any]] = (),
    *,
    challenge_id: int | str = "unknown",
    session_id: str | None = None,
    secret: str = "dvlaa-audit",
) -> list[dict[str, Any]]:
    """把旧 audit/submissions 幂等迁移为 canonical 事件。"""
    result: list[dict[str, Any]] = []
    for index, old in enumerate(legacy_audit):
        old = dict(old)
        event = emit_event(
            event_type="service_action",
            phase="system",
            challenge_id=challenge_id,
            session_id=session_id,
            action=str(old.get("action", "legacy.audit")),
            outcome="completed",
            http_status=int(old.get("status") or 0),
            message=str(old.get("message", "")),
            secret=secret,
            event_id=_legacy_event_id("audit", index, old),
            metadata={"migrated": True, "legacy_kind": "audit"},
        )
        result = append_events(result, event)
    offset = len(result)
    for index, old in enumerate(submissions):
        old = dict(old)
        event = emit_event(
            event_type="submission",
            phase="defense" if "补丁" in str(old.get("type", "")) else "attack",
            challenge_id=challenge_id,
            session_id=session_id,
            action="legacy.submission",
            outcome="completed",
            verdict=str(old.get("status", "")),
            message=str(old.get("detail") or old.get("content", "")),
            secret=secret,
            event_id=_legacy_event_id("submission", index + offset, old),
            metadata={"migrated": True, "legacy_kind": "submission", "submission_type": old.get("type", ""), "filename": old.get("filename", ""), "logs": old.get("logs", [])},
            clock=lambda old=old: int(old.get("created_at") or 0),
        )
        result = append_events(result, event)
    return result


__all__ = [
    "MAX_EVENTS", "append_events", "emit_event", "input_digest", "migrate_legacy_events",
    "project_legacy_audit", "project_legacy_submission", "session_digest",
]
