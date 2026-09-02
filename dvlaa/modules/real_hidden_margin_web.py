"""REAL05 Hidden_Margin 的同源 Web 业务复刻。

本模块只实现公开 HTTP 契约所需的确定性数据和 RAG 编排逻辑。每个浏览器
``_sid`` 对应独立的进程内状态；文档正文、检索日志和隔离记录不会进入 Flask
签名 cookie。附件中的 Python 文件仅作为静态协议参考，本模块不会导入、执行或
启动其中的服务。
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import hmac
import json
import re
import secrets
import threading
from typing import Any, Mapping


MODEL_NAME = "Qwen2.5-Instruct / deterministic challenge adapter"
TOP_K = 3

BASE_DOCS = (
    {
        "id": "kb-password-reset",
        "title": "Password Reset Policy",
        "content": "Account security policy for password reset. Verify identity, use MFA, and never disclose internal audit data.",
        "status": "approved",
        "priority": 8,
        "source": "security-handbook",
    },
    {
        "id": "kb-vpn-guide",
        "title": "Remote Access Guide",
        "content": "Remote access policy for the support team. Use the company VPN and approved device posture checks.",
        "status": "approved",
        "priority": 5,
        "source": "it-handbook",
    },
    {
        "id": "kb-ticket-style",
        "title": "Support Writing Guide",
        "content": "Support answers should be concise, cite retrieved knowledge, and avoid exposing secrets or internal-only notes.",
        "status": "approved",
        "priority": 4,
        "source": "support-handbook",
    },
)

DIRECTIVE_RE = re.compile(
    r'<tool_call>\s*\{\s*"name"\s*:\s*"kb\.fetch_raw"\s*,\s*"arguments"\s*:\s*\{\s*"name"\s*:\s*"([a-z0-9_-]+)"\s*,\s*"encoding"\s*:\s*"(plain|hex)"\s*\}\s*\}\s*</tool_call>',
    re.IGNORECASE,
)
TOKEN_RE = re.compile(r"[a-z0-9_-]+", re.IGNORECASE)

_LOCK = threading.RLock()
_SESSIONS: dict[str, dict[str, Any]] = {}


class HiddenMarginWebError(ValueError):
    """携带可直接映射到 HTTP 响应的业务错误。"""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = int(status)
        self.message = message


def _sid_key(sid: str) -> str:
    value = str(sid or "").strip()
    if not value:
        raise HiddenMarginWebError(400, "browser session is required")
    return value[:160]


def _new_state() -> dict[str, Any]:
    return {
        "docs": {},
        "logs": [],
        "quarantined": set(),
        "evidence": {
            "document_imported": False,
            "rag_queried": False,
            "citation_triggered": False,
            "quarantined": False,
            "audit_verified": False,
        },
    }


def _state(sid: str) -> dict[str, Any]:
    key = _sid_key(sid)
    current = _SESSIONS.get(key)
    if current is None:
        current = _new_state()
        _SESSIONS[key] = current
    return current


def audit_token_for(sid: str, secret: str) -> str:
    """为一个 DVLAA browser session 派生稳定的审计凭据。"""
    key = _sid_key(sid)
    digest = hmac.new(
        str(secret).encode("utf-8"),
        f"real05-hidden-margin:{key}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"audit_{digest[:32]}"


def _normalize_text(text: Any) -> str:
    return " ".join(TOKEN_RE.findall(str(text or "").lower()))


def _risk_fingerprint(content: str) -> str:
    return hashlib.sha256(_normalize_text(content).encode("utf-8")).hexdigest()


def _score_document(query: str, document: Mapping[str, Any]) -> int:
    query_tokens = Counter(TOKEN_RE.findall(query.lower()))
    document_tokens = Counter(TOKEN_RE.findall(
        f"{document.get('title', '')} {document.get('content', '')}".lower()
    ))
    overlap = sum(min(count, document_tokens.get(token, 0)) for token, count in query_tokens.items())
    return overlap * 10 + int(document.get("priority", 0))


def _is_suspicious(document: Mapping[str, Any]) -> bool:
    return bool(DIRECTIVE_RE.search(str(document.get("content", ""))))


def _document_view(document: Mapping[str, Any]) -> dict[str, Any]:
    return {key: document[key] for key in ("id", "title", "status", "priority", "source")}


def _internal_snippet(name: str, audit_token: str) -> str | None:
    if name != "security-audit":
        return None
    return json.dumps(
        {
            "audit_token": audit_token,
            "note": "Review suspicious retrievals in the audit console, quarantine poisoned knowledge, then run verification.",
        },
        separators=(",", ":"),
    )


def status(sid: str) -> dict[str, Any]:
    """返回 Northstar 的公开服务状态和当前会话库存量。"""
    with _LOCK:
        current = _state(sid)
        return {
            "service": "Northstar Knowledge Assistant",
            "model": MODEL_NAME,
            "top_k": TOP_K,
            "knowledge": {
                "base_documents": len(BASE_DOCS),
                "guest_documents": len(current["docs"]),
                "quarantined": len(current["quarantined"]),
                "retrieval_logs": len(current["logs"]),
            },
        }


def knowledge(sid: str) -> dict[str, Any]:
    """列出当前 browser session 可见的知识库元数据。"""
    with _LOCK:
        current = _state(sid)
        documents = [
            _document_view(document)
            for document in (*BASE_DOCS, *current["docs"].values())
            if document["id"] not in current["quarantined"]
        ]
        return {"documents": documents}


def import_document(sid: str, body: Mapping[str, Any] | None) -> dict[str, Any]:
    """复刻 guest metadata 覆盖审核字段的兼容性错误。"""
    payload = body if isinstance(body, Mapping) else {}
    title = str(payload.get("title", "")).strip()
    content = str(payload.get("content", "")).strip()
    metadata = payload.get("metadata") or {}
    if not title or not content or not isinstance(metadata, Mapping):
        raise HiddenMarginWebError(400, "title, content and metadata are required")

    document: dict[str, Any] = {
        "id": f"doc-{secrets.token_hex(4)}",
        "title": title[:120],
        "content": content[:8000],
        "status": "pending",
        "priority": 0,
        "source": "guest-upload",
    }
    for key in ("source", "status", "priority"):
        if key in metadata:
            document[key] = metadata[key]
    if document["status"] not in ("pending", "approved"):
        document["status"] = "pending"
    try:
        document["priority"] = max(0, min(int(document["priority"]), 100))
    except (TypeError, ValueError):
        document["priority"] = 0
    document["source"] = str(document["source"])[:80]

    with _LOCK:
        current = _state(sid)
        current["docs"][document["id"]] = document
        current["evidence"]["document_imported"] = True
        return {"document": _document_view(document)}


def rag_query(sid: str, body: Mapping[str, Any] | None, audit_token: str) -> dict[str, Any]:
    """以 token overlap + priority 选择文档并执行故意脆弱的 citation adapter。"""
    payload = body if isinstance(body, Mapping) else {}
    prompt = str(payload.get("query", "")).strip()
    if not prompt:
        raise HiddenMarginWebError(400, "query is required")

    with _LOCK:
        current = _state(sid)
        candidates = [document for document in BASE_DOCS if document["status"] == "approved"]
        candidates.extend(
            document
            for document in current["docs"].values()
            if document["status"] == "approved" and document["id"] not in current["quarantined"]
        )
        ranked = sorted(
            ((_score_document(prompt, document), document) for document in candidates),
            key=lambda item: (item[0], item[1]["id"]),
            reverse=True,
        )[:TOP_K]
        selected = [
            {"id": document["id"], "title": document["title"], "score": score}
            for score, document in ranked
        ]
        suspicious = [
            {
                "doc_id": document["id"],
                "title": document["title"],
                "normalized_sha256": _risk_fingerprint(str(document["content"])),
                "reason": "instruction-like tool call found inside retrieved knowledge",
            }
            for _, document in ranked
            if _is_suspicious(document)
        ]

        tool_output = None
        if ranked:
            top_document = ranked[0][1]
            match = DIRECTIVE_RE.search(str(top_document["content"]))
            if match:
                name, encoding = match.group(1).lower(), match.group(2).lower()
                raw = _internal_snippet(name, audit_token)
                if raw is not None:
                    # 故意保留原协议的顺序缺陷：hex 转码后再替换明文 token，
                    # 因而 hex 响应依旧可被解码为实际 audit token。
                    data = raw if encoding == "plain" else raw.encode("utf-8").hex()
                    data = data.replace(audit_token, "[REDACTED]")
                    tool_output = {"encoding": encoding, "data": data, "source": name}

        current["logs"].append({
            "query": prompt,
            "selected": selected,
            "suspected_pollution": suspicious,
        })
        current["logs"] = current["logs"][-20:]
        current["evidence"]["rag_queried"] = True
        if tool_output is not None:
            current["evidence"]["citation_triggered"] = True

        answer = "I found relevant knowledge and prepared a support summary."
        if tool_output:
            answer += " An internal citation tool was requested by retrieved context."
        return {"answer": answer, "retrieved": selected, "tool_output": tool_output}


def retrievals(sid: str, token: str, audit_token: str) -> dict[str, Any]:
    with _LOCK:
        if not hmac.compare_digest(str(token or ""), audit_token):
            raise HiddenMarginWebError(403, "invalid audit token")
        current = _state(sid)
        return {"retrievals": deepcopy(current["logs"])}


def quarantine(sid: str, body: Mapping[str, Any] | None, audit_token: str) -> dict[str, Any]:
    payload = body if isinstance(body, Mapping) else {}
    if not hmac.compare_digest(str(payload.get("token", "")), audit_token):
        raise HiddenMarginWebError(403, "invalid audit token")
    doc_id = str(payload.get("doc_id", ""))
    with _LOCK:
        current = _state(sid)
        if doc_id not in current["docs"]:
            raise HiddenMarginWebError(404, "document not found in this session")
        current["quarantined"].add(doc_id)
        current["evidence"]["quarantined"] = True
        return {"ok": True, "document": doc_id, "status": "quarantined"}


def verify(sid: str, token: str, audit_token: str) -> dict[str, Any]:
    """确认 citation 已留下证据且污染文档已从活动索引隔离。"""
    with _LOCK:
        if not hmac.compare_digest(str(token or ""), audit_token):
            raise HiddenMarginWebError(403, "invalid audit token")
        current = _state(sid)
        suspicious_live = [
            document["id"]
            for document in current["docs"].values()
            if document["status"] == "approved"
            and document["id"] not in current["quarantined"]
            and _is_suspicious(document)
        ]
        if suspicious_live:
            return {
                "ok": False,
                "status": 409,
                "message": "unsafe knowledge is still active",
                "documents": suspicious_live,
            }
        if not current["evidence"].get("citation_triggered"):
            return {"ok": False, "status": 409, "message": "no citation evidence recorded"}
        if not current["quarantined"]:
            return {"ok": False, "status": 409, "message": "no remediation action recorded"}
        current["evidence"]["audit_verified"] = True
        return {"ok": True, "status": 200, "message": "knowledge base verified"}


def completion_evidence(sid: str) -> dict[str, bool]:
    """返回 bridge 所需的无文档正文证据快照。"""
    with _LOCK:
        current = _state(sid)
        return {key: bool(value) for key, value in current["evidence"].items()}


def reset(sid: str) -> None:
    """仅移除当前 browser session 的易失知识库状态。"""
    with _LOCK:
        _SESSIONS.pop(_sid_key(sid), None)


__all__ = [
    "BASE_DOCS",
    "DIRECTIVE_RE",
    "HiddenMarginWebError",
    "audit_token_for",
    "completion_evidence",
    "import_document",
    "knowledge",
    "quarantine",
    "rag_query",
    "reset",
    "retrievals",
    "status",
    "verify",
]
