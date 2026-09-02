from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: str):
        self.path = path
        self._init_lock = threading.Lock()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self._init_lock, self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS recovery_requests (
                    id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    service TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('PENDING', 'APPROVED', 'COMPLETED')),
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    token TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approvals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    approver TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK (decision IN ('APPROVED', 'REJECTED')),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(request_id) REFERENCES recovery_requests(id)
                );

                CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    namespace TEXT NOT NULL,
                    memory_key TEXT NOT NULL,
                    content TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_memory_lookup
                    ON memories(namespace, memory_key, id DESC);

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def create_user(self, username: str) -> dict[str, Any]:
        token = f"user-{uuid.uuid4().hex}"
        created_at = utc_now()
        try:
            with self.connect() as connection:
                connection.execute(
                    "INSERT INTO users(username, token, created_at) VALUES (?, ?, ?)",
                    (username, token, created_at),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("username already exists") from exc
        self.audit("user.registered", username, {"username": username})
        return {"username": username, "token": token, "created_at": created_at}

    def get_user_by_token(self, token: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT username, token, created_at FROM users WHERE token = ?",
                (token,),
            ).fetchone()
        return dict(row) if row else None

    def create_recovery(self, owner: str, service: str, reason: str) -> dict[str, Any]:
        request_id = f"rec-{uuid.uuid4().hex[:12]}"
        created_at = utc_now()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO recovery_requests(id, owner, service, reason, state, created_at) "
                "VALUES (?, ?, ?, ?, 'PENDING', ?)",
                (request_id, owner, service, reason, created_at),
            )
        self.audit("recovery.created", owner, {"request_id": request_id, "service": service})
        return self.get_recovery(request_id)

    def get_recovery(self, request_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM recovery_requests WHERE id = ?", (request_id,)
            ).fetchone()
        return dict(row) if row else None

    def approve_recovery(self, request_id: str, approver: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            request = connection.execute(
                "SELECT state FROM recovery_requests WHERE id = ?", (request_id,)
            ).fetchone()
            if request is None:
                return None
            if request["state"] != "PENDING":
                raise ValueError("only pending requests can be approved")
            connection.execute(
                "INSERT INTO approvals(request_id, approver, decision, created_at) VALUES (?, ?, 'APPROVED', ?)",
                (request_id, approver, utc_now()),
            )
            connection.execute(
                "UPDATE recovery_requests SET state = 'APPROVED' WHERE id = ?", (request_id,)
            )
        self.audit("recovery.approved", approver, {"request_id": request_id})
        return self.get_recovery(request_id)

    def has_authoritative_approval(self, request_id: str) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT r.state, COUNT(a.id) AS approvals
                FROM recovery_requests r
                LEFT JOIN approvals a
                    ON a.request_id = r.id AND a.decision = 'APPROVED'
                WHERE r.id = ?
                GROUP BY r.id
                """,
                (request_id,),
            ).fetchone()
        return bool(row and row["state"] == "APPROVED" and row["approvals"] >= 1)

    def complete_recovery(self, request_id: str) -> None:
        with self.connect() as connection:
            changed = connection.execute(
                "UPDATE recovery_requests SET state = 'COMPLETED', completed_at = ? "
                "WHERE id = ? AND state = 'APPROVED'",
                (utc_now(), request_id),
            ).rowcount
        if changed != 1:
            raise ValueError("request is not in an executable state")

    def write_memory(
        self, namespace: str, memory_key: str, content: str, actor: str
    ) -> dict[str, Any]:
        created_at = utc_now()
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO memories(namespace, memory_key, content, actor, created_at) VALUES (?, ?, ?, ?, ?)",
                (namespace, memory_key, content, actor, created_at),
            )
            memory_id = cursor.lastrowid
        self.audit(
            "memory.written",
            actor,
            {"namespace": namespace, "key": memory_key, "memory_id": memory_id},
        )
        return {
            "id": memory_id,
            "namespace": namespace,
            "key": memory_key,
            "content": content,
            "actor": actor,
            "created_at": created_at,
        }

    def latest_memory(self, namespace: str, memory_key: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM memories WHERE namespace = ? AND memory_key = ? "
                "ORDER BY id DESC LIMIT 1",
                (namespace, memory_key),
            ).fetchone()
        return dict(row) if row else None

    def list_memories(self, namespace: str, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM memories WHERE namespace = ? ORDER BY id DESC LIMIT ?",
                (namespace, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def audit(self, event: str, actor: str, detail: dict[str, Any]) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO audit_log(event, actor, detail, created_at) VALUES (?, ?, ?, ?)",
                (event, actor, json.dumps(detail, ensure_ascii=False), utc_now()),
            )
