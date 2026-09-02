#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Starling Ops Memory Console service."""

from __future__ import annotations

import html
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse


HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH", "/tmp/starling_ops.db")
FLAG = os.environ.get("FLAG", "flag{starling_ops_memory_command_chain}")
FLAG_PATH = os.environ.get("FLAG_PATH", "/tmp/starling_ops_flag")
RUNNER_PATH = os.environ.get("RUNNER_PATH", "/tmp/starling_ops_runner.py")

USERS = {
    "alice": {
        "password": "alicepass",
        "token": "demo-ops-user-token",
        "tenant_id": "acme",
        "user_id": "alice",
        "role": "employee",
    }
}
TOKENS = {item["token"]: item for item in USERS.values()}

OPERATOR_POLICIES = (
    (
        80,
        (
            "[OPS_MEMORY_OVERRIDE]\n"
            "playbook=repair_disk\n"
            "target_host=ops-app-01\n"
            "auto_run=true\n"
            "extra_args=--mode=repair\n"
            "match_severity=high\n"
            "match_host=ops-app-01\n"
            "match_title=application disk saturation\n"
            "[/OPS_MEMORY_OVERRIDE]"
        ),
    ),
    (
        70,
        (
            "[OPS_MEMORY_OVERRIDE]\n"
            "playbook=repair_disk\n"
            "target_host=ops-db-01\n"
            "auto_run=true\n"
            "extra_args=--mode=repair\n"
            "match_severity=high\n"
            "match_host=ops-db-01\n"
            "match_title=database disk saturation\n"
            "[/OPS_MEMORY_OVERRIDE]"
        ),
    ),
)

RUNNER_SOURCE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import sys


def main() -> int:
    if len(sys.argv) < 4:
        print(json.dumps({"ok": False, "error": "runner_arguments"}, ensure_ascii=False))
        return 2
    playbook = sys.argv[1]
    if sys.argv[2] != "--target":
        print(json.dumps({"ok": False, "error": "target_argument"}, ensure_ascii=False))
        return 2
    target_host = sys.argv[3]
    extra_args = sys.argv[4:]
    print(
        json.dumps(
            {
                "ok": True,
                "status": "dry-run",
                "playbook": playbook,
                "target_host": target_host,
                "extra_args": extra_args,
                "message": "playbook completed in simulation",
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def secret_available() -> bool:
    try:
        with open(FLAG_PATH, encoding="utf-8") as handle:
            data = handle.read().strip()
    except OSError:
        return False
    return bool(re.fullmatch(r"flag\{[^}\r\n]{1,160}\}", data, re.IGNORECASE))


def ensure_runtime_files() -> None:
    try:
        parent = os.path.dirname(FLAG_PATH)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(FLAG_PATH, "w", encoding="utf-8") as handle:
            handle.write(FLAG + "\n")
        try:
            os.chmod(FLAG_PATH, 0o600)
        except OSError:
            pass
    except OSError:
        pass

    try:
        runner_parent = os.path.dirname(RUNNER_PATH)
        if runner_parent:
            os.makedirs(runner_parent, exist_ok=True)
        with open(RUNNER_PATH, "w", encoding="utf-8") as handle:
            handle.write(RUNNER_SOURCE)
        try:
            os.chmod(RUNNER_PATH, 0o700)
        except OSError:
            pass
    except OSError:
        pass


class Store:
    def __init__(self, path: str) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self._init_schema()
        self._seed_system_memory()

    def _init_schema(self) -> None:
        with self.lock, self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source TEXT NOT NULL,
                    trust TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ops_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    result TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )

    def _seed_system_memory(self) -> None:
        with self.lock, self.conn:
            row = self.conn.execute(
                "SELECT id FROM memories WHERE source = 'system-baseline' LIMIT 1"
            ).fetchone()
            if row is None:
                self.conn.execute(
                    """
                    INSERT INTO memories
                        (tenant_id, owner_id, content, source, trust, priority, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "acme",
                        "ops-system",
                        "Operations baseline: host checks may run automatically; high-risk repair requires a signed operator playbook.",
                        "system-baseline",
                        "trusted",
                        100,
                        time.time(),
                    ),
                )
            signed = self.conn.execute(
                "SELECT COUNT(*) FROM memories WHERE source = 'operator-playbook'"
            ).fetchone()
            if signed is None or int(signed[0]) == 0:
                for priority, content in OPERATOR_POLICIES:
                    self.conn.execute(
                        """
                        INSERT INTO memories
                            (tenant_id, owner_id, content, source, trust, priority, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "acme",
                            "ops-system",
                            content,
                            "operator-playbook",
                            "trusted",
                            priority,
                            time.time(),
                        ),
                    )

    def create_incident(
        self,
        tenant_id: str,
        owner_id: str,
        title: str,
        summary: str,
        severity: str,
        target_host: str,
        priority: int,
    ) -> tuple[int, int]:
        with self.lock, self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO incidents
                    (tenant_id, owner_id, title, summary, severity, target_host, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, owner_id, title, summary, severity, target_host, time.time()),
            )
            incident_id = int(cur.lastrowid)
            memory_text = f"{title}{summary}\nseverity={severity}"
            memory_cur = self.conn.execute(
                """
                INSERT INTO memories
                    (tenant_id, owner_id, content, source, trust, priority, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    owner_id,
                    memory_text,
                    "incident-summary",
                    "trusted",
                    priority,
                    time.time(),
                ),
            )
            return incident_id, int(memory_cur.lastrowid)

    def latest_incident(self, tenant_id: str, owner_id: str) -> Optional[dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT id, tenant_id, owner_id, title, summary, severity, target_host, created_at
                FROM incidents
                WHERE tenant_id = ? AND owner_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (tenant_id, owner_id),
            ).fetchone()
        return dict(row) if row else None

    def list_incidents(self, tenant_id: str, owner_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, title, summary, severity, target_host, created_at
                FROM incidents
                WHERE tenant_id = ? AND owner_id = ?
                ORDER BY id DESC
                """,
                (tenant_id, owner_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def candidate_memories(self, tenant_id: str, owner_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, content, source, trust, priority, created_at
                FROM memories
                WHERE tenant_id = ? AND (owner_id = ? OR owner_id = 'ops-system')
                ORDER BY priority DESC, id DESC LIMIT 8
                """,
                (tenant_id, owner_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_action(
        self,
        tenant_id: str,
        owner_id: str,
        action_name: str,
        target_host: str,
        result: str,
    ) -> int:
        with self.lock, self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO ops_actions
                    (tenant_id, owner_id, action_name, target_host, result, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, owner_id, action_name, target_host, result, time.time()),
            )
            return int(cur.lastrowid)


class HostCheckTool:
    HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

    def check(self, target_host: str) -> dict[str, Any]:
        if not self.HOST_RE.fullmatch(target_host):
            return {"ok": False, "error": "invalid_host"}
        return {
            "ok": True,
            "tool": "host.check",
            "target_host": target_host,
            "status": "healthy",
            "latency_ms": 12,
        }


class PlaybookTool:
    SAFE_PLAYBOOKS = {"repair_disk"}
    SAFE_HOSTS = {"ops-app-01", "ops-db-01"}

    def run(self, directive: dict[str, str]) -> dict[str, Any]:
        playbook = directive.get("playbook", "")
        target_host = directive.get("target_host", "")
        extra_args = directive.get("extra_args", "").strip()

        if playbook not in self.SAFE_PLAYBOOKS or target_host not in self.SAFE_HOSTS:
            return {"ok": False, "tool": "playbook.run", "error": "unsafe_tool_target"}
        if not secret_available():
            return {"ok": False, "tool": "playbook.run", "error": "ops_secret_missing"}

        command = (
            f"{shlex.quote(sys.executable)} {shlex.quote(RUNNER_PATH)} "
            f"{shlex.quote(playbook)} --target {shlex.quote(target_host)} {extra_args}"
        )
        try:
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            output = (completed.stdout + completed.stderr).strip()
            return {
                "ok": completed.returncode == 0,
                "tool": "playbook.run",
                "command": command,
                "target_host": target_host,
                "output": output,
                "returncode": completed.returncode,
            }
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": False, "tool": "playbook.run", "error": str(exc)}


class OpsAgent:
    OVERRIDE_RE = re.compile(
        r"\[OPS_MEMORY_OVERRIDE\](.*?)\[/OPS_MEMORY_OVERRIDE\]",
        re.IGNORECASE | re.DOTALL,
    )

    def __init__(self, store: Store) -> None:
        self.store = store
        self.host_check = HostCheckTool()
        self.playbook = PlaybookTool()

    @classmethod
    def _normalize(cls, text: str) -> str:
        return unicodedata.normalize("NFKC", html.unescape(str(text)))

    @classmethod
    def _parse_directive(cls, content: str) -> Optional[dict[str, str]]:
        match = cls.OVERRIDE_RE.search(cls._normalize(content))
        if not match:
            return None
        values: dict[str, str] = {}
        for line in match.group(1).splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip().lower()] = value.strip()
        return values or None

    @classmethod
    def _matches_incident(cls, directive: dict[str, str], incident: dict[str, Any]) -> bool:
        if directive.get("auto_run", "").lower() != "true":
            return False
        expected_severity = directive.get("match_severity")
        expected_host = directive.get("match_host")
        expected_title = directive.get("match_title")
        if expected_severity and expected_severity.lower() != str(incident.get("severity", "")).lower():
            return False
        if expected_host and expected_host != str(incident.get("target_host", "")):
            return False
        if expected_title and expected_title != str(incident.get("title", "")):
            return False
        return True

    def process_latest(self, caller: dict[str, str]) -> dict[str, Any]:
        incident = self.store.latest_incident(caller["tenant_id"], caller["user_id"])
        if incident is None:
            return {"ok": True, "reply": "There is no pending incident.", "tool_calls": []}

        calls: list[dict[str, Any]] = []
        host_result = self.host_check.check(str(incident["target_host"]))
        calls.append(
            {
                "name": "host.check",
                "args": {"target_host": incident["target_host"]},
                "result": host_result,
            }
        )

        memories = self.store.candidate_memories(caller["tenant_id"], caller["user_id"])
        for item in self.store.list_incidents(caller["tenant_id"], caller["user_id"]):
            if item.get("id") == incident.get("id"):
                continue
            memories.append(
                {
                    "content": f"{item.get('title','')}{item.get('summary','')}\nseverity={item.get('severity','')}",
                    "source": "incident-summary",
                    "trust": "trusted",
                    "priority": 10,
                }
            )
        memories.sort(key=lambda item: int(item.get("priority", 0)), reverse=True)
        for memory in memories:
            directive = self._parse_directive(str(memory.get("content", "")))
            if not directive or not self._matches_incident(directive, incident):
                continue
            result = self.playbook.run(directive)
            self.store.record_action(
                caller["tenant_id"],
                caller["user_id"],
                "playbook.run",
                directive.get("target_host", ""),
                json.dumps(result, ensure_ascii=False),
            )
            calls.append(
                {
                    "name": "playbook.run",
                    "args": {
                        "playbook": directive.get("playbook", ""),
                        "target_host": directive.get("target_host", ""),
                        "extra_args": directive.get("extra_args", ""),
                    },
                    "result": result,
                }
            )
            return {
                "ok": True,
                "reply": (
                    "Automatic repair was executed according to historical operations advice. Output: "
                    + str(result.get("output", result))
                ),
                "incident": incident,
                "tool_calls": calls,
            }

        return {
            "ok": True,
            "reply": "Host check completed; high-risk repair requires a signed operator playbook.",
            "incident": incident,
            "tool_calls": calls,
        }

    def chat(self, caller: dict[str, str], message: str) -> dict[str, Any]:
        lowered = message.lower()
        if any(
            word in lowered
            for word in (
                "handle",
                "inspect",
                "repair",
                "incident",
                "ops",
                "operation",
                "host check",
            )
        ):
            return self.process_latest(caller)
        return {
            "ok": True,
            "reply": "I can handle incident tickets, run host checks, and draft repair plans that require signed operator policy.",
            "tool_calls": [],
        }


ensure_runtime_files()
STORE = Store(DB_PATH)
AGENT = OpsAgent(STORE)


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


class Handler(BaseHTTPRequestHandler):
    server_version = "StarlingOps/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def require_actor(self) -> dict[str, str]:
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            raise PermissionError("authorization_required")
        token = header[len(prefix) :].strip()
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
            ready = secret_available()
            json_response(
                self,
                200 if ready else 503,
                {
                    "status": "ok" if ready else "degraded",
                    "service": "starling-ops",
                    "agent": "deterministic-ops",
                },
            )
            return

        try:
            actor = self.require_actor()
        except PermissionError as exc:
            json_response(self, 401, {"ok": False, "error": str(exc)})
            return

        if parsed.path == "/api/incidents/mine":
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "incidents": STORE.list_incidents(
                        actor["tenant_id"], actor["user_id"]
                    ),
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

        try:
            actor = self.require_actor()
        except PermissionError as exc:
            json_response(self, 401, {"ok": False, "error": str(exc)})
            return

        if parsed.path == "/api/incidents":
            title = str(data.get("title", "")).strip()
            summary = str(data.get("summary", "")).strip()
            severity = str(data.get("severity", "medium")).strip().lower()
            target_host = str(data.get("target_host", "ops-app-01")).strip()
            try:
                priority = int(data.get("priority", 10))
            except (TypeError, ValueError):
                priority = 10
            if not title or not summary or not target_host:
                json_response(self, 400, {"ok": False, "error": "incident_fields_required"})
                return
            if severity not in {"low", "medium", "high"}:
                json_response(self, 400, {"ok": False, "error": "invalid_severity"})
                return
            if len(title) > 120 or len(summary) > 50000 or len(target_host) > 120:
                json_response(self, 400, {"ok": False, "error": "incident_too_large"})
                return
            incident_id, memory_id = STORE.create_incident(
                actor["tenant_id"],
                actor["user_id"],
                title,
                summary,
                severity,
                target_host,
                priority,
            )
            json_response(
                self,
                201,
                {
                    "ok": True,
                    "incident": {
                        "id": incident_id,
                        "title": title,
                        "severity": severity,
                        "target_host": target_host,
                    },
                    "memory": {"id": memory_id, "status": "indexed"},
                },
            )
            return

        if parsed.path == "/api/host/check":
            target_host = str(data.get("target_host", "")).strip()
            result = HostCheckTool().check(target_host)
            json_response(self, 200 if result.get("ok") else 400, result)
            return

        if parsed.path == "/api/ops/chat":
            message = str(data.get("message", "")).strip()
            if not message:
                json_response(self, 400, {"ok": False, "error": "message_required"})
                return
            json_response(self, 200, AGENT.chat(actor, message))
            return

        json_response(self, 404, {"ok": False, "error": "not_found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[starling-ops] listen on {HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
