#!/usr/bin/env python3


from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse


HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH", "/tmp/starling_support.db")
FLAG = os.environ.get("FLAG", "flag{starling_support_memory_bridge}")
SECURE_MODE = False
SERVICE_EDITION = "attack"

USERS = {
    "alice": {
        "password": "alicepass",
        "token": "demo-user-token",
        "tenant_id": "acme",
        "user_id": "alice",
        "role": "customer",
    }
}
TOKENS = {item["token"]: item for item in USERS.values()}


class Store:
    def __init__(self, path: str) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self._init_schema()
        self._seed_internal_ticket()

    def _init_schema(self) -> None:
        with self.lock, self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    message TEXT NOT NULL,
                    internal_note TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'user',
                    trusted INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );
                """
            )

    def _seed_internal_ticket(self) -> None:
        note = f"Internal one-time bridge credential: {FLAG}"
        specs = (
            (
                1001,
                "L2 Bridge Credential Review",
                "Escalation ticket for internal L2 support only.",
            ),
            (
                1008,
                "L2 Bridge Credential Backup Review",
                "Secondary escalation ticket for internal L2 support only.",
            ),
        )
        with self.lock, self.conn:
            for ticket_id, subject, message in specs:
                row = self.conn.execute("SELECT id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
                if row is None:
                    self.conn.execute(
                        """
                        INSERT INTO tickets
                            (id, tenant_id, owner_id, subject, message, internal_note, status, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ticket_id,
                            "internal",
                            "l2-support",
                            subject,
                            message,
                            note,
                            "internal",
                            time.time(),
                        ),
                    )
                else:
                    self.conn.execute(
                        "UPDATE tickets SET internal_note = ?, status = 'internal' WHERE id = ?",
                        (note, ticket_id),
                    )

    def escalation_ready(self) -> bool:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id FROM tickets
                WHERE id IN (1001, 1008) AND tenant_id = 'internal' AND status = 'internal'
                """
            ).fetchall()
        return {int(row["id"]) for row in rows} == {1001, 1008}

    def note_internal_lookup(self) -> None:
        with self.lock:
            self._internal_lookups = getattr(self, "_internal_lookups", 0) + 1

    def internal_lookup_count(self) -> int:
        with self.lock:
            return int(getattr(self, "_internal_lookups", 0))

    def create_ticket(self, tenant_id: str, owner_id: str, subject: str, message: str) -> int:
        with self.lock, self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO tickets
                    (tenant_id, owner_id, subject, message, internal_note, status, created_at)
                VALUES (?, ?, ?, ?, '', 'open', ?)
                """,
                (tenant_id, owner_id, subject, message, time.time()),
            )
            return int(cur.lastrowid)

    def list_my_tickets(self, tenant_id: str, owner_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, subject, status, created_at
                FROM tickets
                WHERE tenant_id = ? AND owner_id = ?
                ORDER BY id DESC
                """,
                (tenant_id, owner_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def lookup_ticket(self, ticket_id: int) -> Optional[dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT id, tenant_id, owner_id, subject, message, internal_note, status
                FROM tickets WHERE id = ?
                """,
                (ticket_id,),
            ).fetchone()
        return dict(row) if row else None

    def add_memory(self, tenant_id: str, user_id: str, content: str, source: str, trusted: bool) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO memories (tenant_id, user_id, content, source, trusted, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, user_id, content, source, 1 if trusted else 0, time.time()),
            )

    def recent_memories(self, tenant_id: str, user_id: str, limit: int = 12) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT content, source, trusted FROM memories
                WHERE tenant_id = ? AND user_id = ?
                ORDER BY id DESC LIMIT ?
                """,
                (tenant_id, user_id, limit),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def consume_tool_directives(self, tenant_id: str, user_id: str) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                """
                DELETE FROM memories
                WHERE tenant_id = ? AND user_id = ? AND instr(lower(content), 'ticket.lookup') > 0
                """,
                (tenant_id, user_id),
            )


class TicketTool:
    def __init__(self, store: Store) -> None:
        self.store = store

    def lookup(self, ticket_id: int, caller_tenant: str, caller_user: str, caller_role: str) -> dict[str, Any]:
        if ticket_id in {1001, 1008}:
            self.store.note_internal_lookup()
        row = self.store.lookup_ticket(ticket_id)
        if row is None:
            return {"ok": False, "error": "ticket_not_found"}

        return {
            "ok": True,
            "tool": "ticket.lookup",
            "caller": {"tenant_id": caller_tenant, "user_id": caller_user, "role": caller_role},
            "ticket": row,
        }


class DeterministicAgent:
    DIRECTIVE_RE = re.compile(r"(?:ticket(?:[_\s-]?id)?)\s*[:=#]?\s*(\d{3,})", re.IGNORECASE)

    def __init__(self, store: Store) -> None:
        self.store = store
        self.ticket_tool = TicketTool(store)

    @staticmethod
    def should_write_memory(message: str) -> bool:
        lowered = message.lower()
        markers = (
            "remember",
            "operational directive",
            "operations directive",
            "support qa",
            "quality audit",
            "internal qa",
            "save to memory",
            "ticket.lookup",
        )
        return any(marker in lowered for marker in markers)

    @classmethod
    def extract_directive(cls, memories: list[dict[str, Any]]) -> Optional[int]:
        for memory in memories:
            lowered = str(memory.get("content", "")).lower()
            if "ticket.lookup" not in lowered:
                continue
            if not (
                "internal_note" in lowered
                or "internal note" in lowered
                or "return directly" in lowered
                or "directly return" in lowered
            ):
                continue
            match = cls.DIRECTIVE_RE.search(lowered)
            if match:
                return int(match.group(1))
        return None

    def chat(self, tenant_id: str, user_id: str, role: str, message: str) -> dict[str, Any]:
        previous_memories = self.store.recent_memories(tenant_id, user_id)
        stored = False

        if self.should_write_memory(message):
            self.store.add_memory(tenant_id, user_id, message, "user", True)
            stored = True

        ticket_id = self.extract_directive(previous_memories)
        if ticket_id is not None:
            self.store.consume_tool_directives(tenant_id, user_id)
            tool_result = self.ticket_tool.lookup(ticket_id, tenant_id, user_id, role)
            if tool_result["ok"]:
                ticket = tool_result["ticket"]
                if "internal_note" in ticket:
                    reply = "Internal ticket review completed through the support QA flow: " + str(
                        ticket["internal_note"]
                    )
                else:
                    reply = "Ticket review completed. Internal notes are not available to this account."
                return {
                    "ok": True,
                    "reply": reply,
                    "tool_calls": [{"name": "ticket.lookup", "args": {"ticket_id": ticket_id}}],
                    "memory_written": stored,
                }
            return {
                "ok": True,
                "reply": "The ticket review request was rejected by server-side authorization.",
                "tool_calls": [],
                "memory_written": stored,
            }

        lowered_message = message.lower()
        if any(word in lowered_message for word in ("ticket", "support", "refund", "status", "progress", "order")):
            reply = (
                "I can help create or query tickets for your tenant. Please provide "
                "an order number or problem description."
            )
        elif any(word in lowered_message for word in ("hello", "hi", "help")):
            reply = (
                "Hello, I am the Starling Support agent. I can help create tickets, "
                "check status, and escalate to a human operator."
            )
        else:
            reply = "Your request has been received. I will record the issue and arrange support follow-up."

        return {"ok": True, "reply": reply, "tool_calls": [], "memory_written": stored}


STORE = Store(DB_PATH)
AGENT = DeterministicAgent(STORE)


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    raw_length = handler.headers.get("Content-Length", "0")
    length = int(raw_length)
    if length > 64 * 1024:
        raise ValueError("request_too_large")
    raw = handler.rfile.read(length)
    if not raw:
        return {}
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("json_object_required")
    return data


class Handler(BaseHTTPRequestHandler):
    server_version = "StarlingSupport/2.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def require_actor(self) -> dict[str, str]:
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            raise PermissionError("authorization_required")
        token = header[len(prefix):].strip()
        actor = TOKENS.get(token)
        if actor is None:
            raise PermissionError("invalid_token")
        return {
            "tenant_id": str(actor["tenant_id"]),
            "user_id": str(actor["user_id"]),
            "role": str(actor["role"]),
        }

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            json_response(
                self,
                200,
                {
                    "status": "ok",
                    "service": "starling-support",
                    "edition": SERVICE_EDITION,
                    "agent": "deterministic",
                    "secure_mode": SECURE_MODE,
                    "escalation_ready": STORE.escalation_ready(),
                    "internal_lookups": STORE.internal_lookup_count(),
                },
            )
            return

        if parsed.path == "/api/tickets/mine":
            try:
                actor = self.require_actor()
            except PermissionError as exc:
                json_response(self, 401, {"ok": False, "error": str(exc)})
                return
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "tickets": STORE.list_my_tickets(actor["tenant_id"], actor["user_id"]),
                },
            )
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
            password = str(data.get("password", ""))
            actor = USERS.get(username)
            if actor is None or actor["password"] != password:
                json_response(self, 401, {"ok": False, "error": "invalid_credentials"})
                return
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "token": actor["token"],
                    "user": {
                        "user_id": actor["user_id"],
                        "tenant_id": actor["tenant_id"],
                        "role": actor["role"],
                    },
                },
            )
            return

        if parsed.path == "/api/chat":
            try:
                actor = self.require_actor()
            except PermissionError as exc:
                json_response(self, 401, {"ok": False, "error": str(exc)})
                return
            message = str(data.get("message", "")).strip()
            if not message:
                json_response(self, 400, {"ok": False, "error": "message_required"})
                return
            result = AGENT.chat(actor["tenant_id"], actor["user_id"], actor["role"], message)
            json_response(self, 200, result)
            return

        if parsed.path == "/api/tickets":
            try:
                actor = self.require_actor()
            except PermissionError as exc:
                json_response(self, 401, {"ok": False, "error": str(exc)})
                return
            subject = str(data.get("subject", "")).strip()
            message = str(data.get("message", "")).strip()
            if not all((subject, message)):
                json_response(self, 400, {"ok": False, "error": "ticket_fields_required"})
                return
            ticket_id = STORE.create_ticket(actor["tenant_id"], actor["user_id"], subject, message)
            json_response(
                self,
                201,
                {"ok": True, "ticket": {"id": ticket_id, "status": "open", "subject": subject}},
            )
            return

        json_response(self, 404, {"ok": False, "error": "not_found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(
        f"[starling-support] listen on {HOST}:{PORT} edition={SERVICE_EDITION} secure_mode={SECURE_MODE}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
