#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse


HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH", "/tmp/starling_audit.db")
FLAG = os.environ.get("FLAG", "flag{starling_audit_webhook_chain}")
_signing_secret = os.environ.get("SIGNING_SECRET", "").strip()
if not _signing_secret:
    _signing_secret = hashlib.sha256(os.urandom(32)).hexdigest()
SIGNING_SECRET = _signing_secret.encode("utf-8")
if FLAG == "flag{starling_audit_webhook_chain}":
    print("[starling-audit] using built-in default FLAG; override FLAG in deployment", flush=True)

USERS = {
    "alice": {
        "password": "alicepass",
        "token": "demo-audit-user-token",
        "tenant_id": "acme",
        "user_id": "alice",
        "role": "analyst",
    }
}
TOKENS = {item["token"]: item for item in USERS.values()}
_check_token = os.environ.get("CHECK_TOKEN", "").strip()
if not _check_token:
    _check_token = hmac.new(SIGNING_SECRET, b"starling-audit-check", hashlib.sha256).hexdigest()
TOKENS[_check_token] = {
    "token": _check_token,
    "tenant_id": "security-internal",
    "user_id": "checker",
    "role": "auditor",
}


def is_integrity_auditor(actor: dict[str, str]) -> bool:
    return actor.get("user_id") == "checker" and actor.get("role") == "auditor"


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def authenticate(username: str, password: str) -> Optional[dict[str, str]]:
    account = USERS.get(username)
    if account is None or account["password"] != password:
        return None
    return {
        "token": str(account["token"]),
        "tenant_id": str(account["tenant_id"]),
        "user_id": str(account["user_id"]),
        "role": str(account["role"]),
    }


def canonical_for_signature(event: dict[str, Any]) -> bytes:
    """Build the canonical webhook signature input."""

    fields = {
        "event_id": event.get("event_id"),
        "source": event.get("source"),
        "event_type": event.get("event_type"),
        "message": event.get("message"),
        "timestamp": event.get("timestamp"),
        "sig_version": event.get("sig_version", 1),
    }
    return json_text(fields).encode("utf-8")


def event_signature(event: dict[str, Any]) -> str:
    return hmac.new(SIGNING_SECRET, canonical_for_signature(event), hashlib.sha256).hexdigest()


class Store:
    def __init__(self, path: str) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self._init_schema()
        self._seed_internal_event()

    def _init_schema(self) -> None:
        with self.lock, self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    status TEXT NOT NULL,
                    claims_json TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    ingest_method TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS export_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    dataset TEXT NOT NULL,
                    approval_event_id TEXT NOT NULL,
                    fields_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )

    def _seed_internal_event(self) -> None:
        with self.lock, self.conn:
            row = self.conn.execute(
                "SELECT event_id FROM audit_events WHERE event_id = 'SEC-9001'"
            ).fetchone()
            if row is not None:
                return
            details = {
                "service": "starling-security-gateway",
                "classification": "internal",
                "review_ticket": "SEC-RPT-2026-0719",
                "credential_hint": "rotate-after-incident",
                "flag": FLAG,
            }
            event = {
                "event_id": "SEC-9001",
                "tenant_id": "security-internal",
                "source": "security-gateway",
                "event_type": "credential-rotation",
                "message": "Internal security gateway credential rotation audit record",
                "timestamp": 1763462400.0,
                "status": "approved",
                "claims": ["internal.audit.read"],
                "details": details,
                "sig_version": 1,
            }
            self.conn.execute(
                """
                INSERT INTO audit_events
                    (event_id, tenant_id, source, event_type, message, timestamp,
                     status, claims_json, details_json, signature, ingest_method, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_id"],
                    event["tenant_id"],
                    event["source"],
                    event["event_type"],
                    event["message"],
                    event["timestamp"],
                    event["status"],
                    json_text(event["claims"]),
                    json_text(event["details"]),
                    event_signature(event),
                    "seed",
                    time.time(),
                ),
            )

    def _row_to_event(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "event_id": str(row["event_id"]),
            "tenant_id": str(row["tenant_id"]),
            "source": str(row["source"]),
            "event_type": str(row["event_type"]),
            "message": str(row["message"]),
            "timestamp": float(row["timestamp"]),
            "status": str(row["status"]),
            "claims": json.loads(str(row["claims_json"])),
            "details": json.loads(str(row["details_json"])),
            "signature": str(row["signature"]),
            "ingest_method": str(row["ingest_method"]),
        }

    def create_signed_report(
        self,
        tenant_id: str,
        event_type: str,
        message: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        event = {
            "event_id": "USR-" + uuid.uuid4().hex[:12].upper(),
            "tenant_id": tenant_id,
            "source": "security-gateway",
            "event_type": event_type,
            "message": message,
            "timestamp": round(time.time(), 3),
            "status": "pending",
            "claims": [],
            "details": details,
            "sig_version": 1,
        }
        event["signature"] = event_signature(event)
        self.upsert_event(event, "report")
        return event

    def upsert_event(self, event: dict[str, Any], ingest_method: str) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO audit_events
                    (event_id, tenant_id, source, event_type, message, timestamp,
                     status, claims_json, details_json, signature, ingest_method, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    source = excluded.source,
                    event_type = excluded.event_type,
                    message = excluded.message,
                    timestamp = excluded.timestamp,
                    status = excluded.status,
                    claims_json = excluded.claims_json,
                    details_json = excluded.details_json,
                    signature = excluded.signature,
                    ingest_method = excluded.ingest_method,
                    created_at = excluded.created_at
                """,
                (
                    str(event["event_id"]),
                    str(event["tenant_id"]),
                    str(event["source"]),
                    str(event["event_type"]),
                    str(event["message"]),
                    float(event["timestamp"]),
                    str(event["status"]),
                    json_text(event.get("claims", [])),
                    json_text(event.get("details", {})),
                    str(event["signature"]),
                    ingest_method,
                    time.time(),
                ),
            )

    def search_events(self, tenant_id: str, query: str) -> list[dict[str, Any]]:
        with self.lock:
            if query:
                rows = self.conn.execute(
                    """
                    SELECT * FROM audit_events
                    WHERE tenant_id = ? AND (message LIKE ? OR event_type LIKE ?)
                    ORDER BY timestamp DESC LIMIT 50
                    """,
                    (tenant_id, f"%{query}%", f"%{query}%"),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    """
                    SELECT * FROM audit_events
                    WHERE tenant_id = ?
                    ORDER BY timestamp DESC LIMIT 50
                    """,
                    (tenant_id,),
                ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def get_event(self, event_id: str) -> Optional[dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM audit_events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return self._row_to_event(row) if row else None

    def internal_events(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT * FROM audit_events
                WHERE tenant_id = 'security-internal'
                ORDER BY timestamp DESC
                """
            ).fetchall()
        events = [self._row_to_event(row) for row in rows]
        for event in events:
            if event.get("event_id") == "SEC-9001":
                details = dict(event.get("details") or {})
                details["flag"] = FLAG
                event["details"] = details
        return events

    def record_export(
        self,
        tenant_id: str,
        user_id: str,
        dataset: str,
        approval_event_id: str,
        fields: list[str],
    ) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO export_audit
                    (tenant_id, user_id, dataset, approval_event_id, fields_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    user_id,
                    dataset,
                    approval_event_id,
                    json_text(fields),
                    time.time(),
                ),
            )


class AuditAgent:
    def __init__(self, store: Store) -> None:
        self.store = store

    def normal_summary(self, actor: dict[str, str]) -> dict[str, Any]:
        events = self.store.search_events(actor["tenant_id"], "")
        return {
            "ok": True,
            "reply": f"Summarized {len(events)} current-tenant audit events. Events pending manual review remain in the queue.",
            "tool_calls": [
                {
                    "name": "audit.search",
                    "args": {"tenant_id": actor["tenant_id"], "limit": 50},
                }
            ],
        }


class Handler(BaseHTTPRequestHandler):
    server_version = "StarlingAudit/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def require_actor(self) -> dict[str, str]:
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            raise PermissionError("authorization_required")
        actor = TOKENS.get(header[len(prefix) :].strip())
        if actor is None:
            raise PermissionError("invalid_token")
        return {
            "tenant_id": str(actor["tenant_id"]),
            "user_id": str(actor["user_id"]),
            "role": str(actor["role"]),
        }


def json_response(
    handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]
) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    if length > 128 * 1024:
        raise ValueError("request_too_large")
    raw = handler.rfile.read(length)
    if not raw:
        return {}
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("json_object_required")
    return data


def public_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event["event_id"],
        "tenant_id": event["tenant_id"],
        "source": event["source"],
        "event_type": event["event_type"],
        "message": event["message"],
        "timestamp": event["timestamp"],
        "status": event["status"],
        "claims": event["claims"],
        "details": event["details"],
        "sig_version": event["sig_version"],
        "signature": event["signature"],
    }


def export_records(
    events: list[dict[str, Any]], fields: list[str], include_sensitive: bool
) -> list[dict[str, Any]]:
    default_fields = ["event_id", "event_type", "message", "status", "timestamp"]
    requested = fields or default_fields
    allowed = {
        "event_id",
        "tenant_id",
        "source",
        "event_type",
        "message",
        "timestamp",
        "status",
        "claims",
        "details",
    }
    if not include_sensitive:
        allowed -= {"tenant_id", "claims", "details"}
    selected = [field for field in requested if field in allowed]
    return [{field: event.get(field) for field in selected} for event in events]


class AuditHandler(Handler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            json_response(
                self,
                200,
                {
                    "status": "ok",
                    "service": "starling-audit",
                    "agent": "deterministic-audit",
                },
            )
            return

        try:
            actor = self.require_actor()
        except PermissionError as exc:
            json_response(self, 401, {"ok": False, "error": str(exc)})
            return

        if parsed.path == "/api/audit/search":
            query = parse_qs(parsed.query).get("q", [""])[0]
            events = STORE.search_events(actor["tenant_id"], query)
            safe = export_records(events, [], include_sensitive=False)
            json_response(self, 200, {"ok": True, "events": safe})
            return
        json_response(self, 404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            data = read_json(self)
        except (ValueError, json.JSONDecodeError) as exc:
            json_response(self, 400, {"ok": False, "error": str(exc)})
            return

        if parsed.path == "/api/login":
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", "")).strip()
            tenant = str(data.get("tenant", "")).strip()
            if not username or not password:
                json_response(self, 400, {"ok": False, "error": "credentials_required"})
                return
            session = authenticate(username, password)
            if session is None:
                json_response(self, 401, {"ok": False, "error": "invalid_credentials"})
                return
            if tenant and tenant != session["tenant_id"]:
                json_response(self, 403, {"ok": False, "error": "tenant_mismatch"})
                return
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "token": session["token"],
                    "tenant_id": session["tenant_id"],
                    "user_id": session["user_id"],
                    "role": session["role"],
                },
            )
            return

        if parsed.path == "/api/audit/webhook":
            self.handle_webhook(data)
            return

        try:
            actor = self.require_actor()
        except PermissionError as exc:
            json_response(self, 401, {"ok": False, "error": str(exc)})
            return

        if parsed.path == "/api/audit/report":
            event_type = str(data.get("event_type", "")).strip()
            message = str(data.get("message", "")).strip()
            details = data.get("details", {})
            if not event_type or not message:
                json_response(self, 400, {"ok": False, "error": "event_fields_required"})
                return
            if not isinstance(details, dict):
                json_response(self, 400, {"ok": False, "error": "details_object_required"})
                return
            if len(event_type) > 80 or len(message) > 1000:
                json_response(self, 400, {"ok": False, "error": "event_too_large"})
                return
            event = STORE.create_signed_report(
                actor["tenant_id"], event_type, message, details
            )
            json_response(
                self,
                201,
                {"ok": True, "signed_event": public_event(event)},
            )
            return

        if parsed.path == "/api/audit/search":
            query = str(data.get("q", "")).strip()
            events = STORE.search_events(actor["tenant_id"], query)
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "events": export_records(events, [], include_sensitive=False),
                    "tool_calls": [{"name": "audit.search", "args": {"query": query}}],
                },
            )
            return

        if parsed.path == "/api/audit/chat":
            message = str(data.get("message", "")).strip()
            if not message:
                json_response(self, 400, {"ok": False, "error": "message_required"})
                return
            if any(word in message.lower() for word in ("audit", "summary", "search", "event", "alert")):
                json_response(self, 200, AGENT.normal_summary(actor))
            else:
                json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "reply": "I can summarize current-tenant audit events and generate a pending-review summary.",
                        "tool_calls": [],
                    },
                )
            return

        if parsed.path == "/api/audit/export":
            dataset = str(data.get("dataset", "")).strip()
            approval_event_id = str(data.get("approval_event_id", "")).strip()
            fields = data.get("fields", [])
            if not isinstance(fields, list) or not all(
                isinstance(field, str) for field in fields
            ):
                json_response(self, 400, {"ok": False, "error": "fields_list_required"})
                return
            if dataset == "my-events":
                events = STORE.search_events(actor["tenant_id"], "")
                records = export_records(events, fields, include_sensitive=False)
                STORE.record_export(
                    actor["tenant_id"],
                    actor["user_id"],
                    dataset,
                    approval_event_id,
                    fields,
                )
                json_response(
                    self,
                    200,
                    {"ok": True, "dataset": dataset, "records": records},
                )
                return

            if dataset == "security-events" and is_integrity_auditor(actor):
                events = STORE.internal_events()
                records = export_records(events, fields, include_sensitive=True)
                STORE.record_export(
                    actor["tenant_id"],
                    actor["user_id"],
                    dataset,
                    approval_event_id,
                    fields,
                )
                json_response(
                    self,
                    200,
                    {"ok": True, "dataset": dataset, "records": records},
                )
                return

            if dataset != "security-events":
                json_response(self, 400, {"ok": False, "error": "unknown_dataset"})
                return
            approval = STORE.get_event(approval_event_id)
            if approval is None:
                json_response(self, 404, {"ok": False, "error": "approval_not_found"})
                return

            has_claim = "audit.export.internal" in approval.get("claims", [])
            approved = approval.get("status") == "approved"
            if not approved or not has_claim:
                json_response(self, 403, {"ok": False, "error": "approval_required"})
                return

            if (
                approval["tenant_id"] != "security-internal"
                or approval["ingest_method"] != "webhook"
                or approval.get("details", {}).get("decision") != "approved"
            ):
                json_response(self, 403, {"ok": False, "error": "approval_required"})
                return

            events = STORE.internal_events()
            records = export_records(events, fields, include_sensitive=True)
            STORE.record_export(
                actor["tenant_id"],
                actor["user_id"],
                dataset,
                approval_event_id,
                fields,
            )
            json_response(
                self,
                200,
                {"ok": True, "dataset": dataset, "records": records},
            )
            return

        json_response(self, 404, {"ok": False, "error": "not_found"})

    def handle_webhook(self, data: dict[str, Any]) -> None:
        required = (
            "event_id",
            "tenant_id",
            "source",
            "event_type",
            "message",
            "timestamp",
            "status",
            "claims",
            "details",
            "signature",
        )
        if any(field not in data for field in required):
            json_response(self, 400, {"ok": False, "error": "event_schema_required"})
            return
        if not isinstance(data["claims"], list) or not isinstance(data["details"], dict):
            json_response(self, 400, {"ok": False, "error": "event_schema_invalid"})
            return
        expected = event_signature(data)
        provided = str(data.get("signature", ""))
        if not hmac.compare_digest(expected, provided):
            json_response(self, 401, {"ok": False, "error": "invalid_signature"})
            return
        STORE.upsert_event(data, "webhook")
        json_response(
            self,
            202,
            {
                "ok": True,
                "event_id": data["event_id"],
                "ingest": "accepted",
                "signature": "verified",
            },
        )


STORE = Store(DB_PATH)
AGENT = AuditAgent(STORE)


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), AuditHandler)
    print(f"[starling-audit] listen on {HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
