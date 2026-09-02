#!/usr/bin/env python3
# -*- coding: utf-8 -*-


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
DB_PATH = os.environ.get("DB_PATH", "/tmp/starling_kb.db")
FLAG = os.environ.get("FLAG", "flag{starling_kb_pollution}")
USERS = {
    "alice": {
        "password": "alicepass",
        "token": "demo-user-token",
        "tenant_id": "acme",
        "user_id": "alice",
        "role": "member",
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
        self._seed_documents()

    def _init_schema(self) -> None:
        with self.lock, self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    visibility TEXT NOT NULL DEFAULT 'public',
                    priority INTEGER NOT NULL DEFAULT 5,
                    trusted INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL DEFAULT 'user-upload',
                    created_at REAL NOT NULL
                );
                """
            )

    def _seed_documents(self) -> None:
        with self.lock, self.conn:
            public = self.conn.execute("SELECT id FROM documents WHERE id = 1001").fetchone()
            if public is None:
                self.conn.execute(
                    """
                    INSERT INTO documents
                        (id, tenant_id, owner_id, title, content, visibility, priority, trusted, source, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        1001,
                        "acme",
                        "kb-system",
                        "Public Data Retention Policy",
                        "Starling Cloud public policy: support records are retained for 30 days by default, and normal knowledge queries may cite this policy.",
                        "public",
                        10,
                        1,
                        "official",
                        time.time(),
                    ),
                )

            private = self.conn.execute("SELECT id FROM documents WHERE id = 2001").fetchone()
            private_content = (
                "Internal knowledge-base document for knowledge administrators only.\n"
                "Internal bridge-account and audit information used during customer migration is stored here.\n"
                f"FLAG: {FLAG}"
            )
            if private is None:
                self.conn.execute(
                    """
                    INSERT INTO documents
                        (id, tenant_id, owner_id, title, content, visibility, priority, trusted, source, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        2001,
                        "acme",
                        "kb-admin",
                        "Customer Migration Internal SOP",
                        private_content,
                        "private",
                        50,
                        1,
                        "internal",
                        time.time(),
                    ),
                )
            else:
                self.conn.execute(
                    "UPDATE documents SET content = ?, visibility = 'private', trusted = 1 WHERE id = 2001",
                    (private_content,),
                )

            extra = self.conn.execute("SELECT id FROM documents WHERE id = 2008").fetchone()
            extra_content = (
                "Secondary internal migration worksheet reserved for knowledge administrators.\n"
                "internal-marker: starling-migration-token-77"
            )
            if extra is None:
                self.conn.execute(
                    """
                    INSERT INTO documents
                        (id, tenant_id, owner_id, title, content, visibility, priority, trusted, source, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        2008,
                        "acme",
                        "kb-admin",
                        "Secondary Migration Worksheet",
                        extra_content,
                        "private",
                        40,
                        1,
                        "internal",
                        time.time(),
                    ),
                )
            else:
                self.conn.execute(
                    "UPDATE documents SET content = ?, visibility = 'private', trusted = 1 WHERE id = 2008",
                    (extra_content,),
                )


    def seed_report(self) -> dict[str, bool]:
        private = self.get_document(2001)
        extra = self.get_document(2008)
        public = self.get_document(1001)
        private_content = str(private["content"]) if private else ""
        extra_content = str(extra["content"]) if extra else ""
        return {
            "doc_1001": bool(
                public
                and public["visibility"] == "public"
                and public["tenant_id"] == "acme"
                and public["trusted"]
            ),
            "doc_2001": bool(
                private
                and private["visibility"] == "private"
                and private["tenant_id"] == "acme"
            ),
            "doc_2008": bool(
                extra
                and extra["visibility"] == "private"
                and extra["tenant_id"] == "acme"
            ),
            "flag_seeded": bool(private and FLAG in private_content),
            "body_seeded": bool(
                private and "Internal bridge-account and audit information" in private_content
            ),
            "marker_seeded": bool(extra and "starling-migration-token-77" in extra_content),
        }

    def create_document(
        self,
        tenant_id: str,
        owner_id: str,
        title: str,
        content: str,
        priority: int,
    ) -> int:
        with self.lock, self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO documents
                    (tenant_id, owner_id, title, content, visibility, priority, trusted, source, created_at)
                VALUES (?, ?, ?, ?, 'public', ?, 0, 'user-upload', ?)
                """,
                (tenant_id, owner_id, title, content, priority, time.time()),
            )
            return int(cur.lastrowid)

    def get_document(self, doc_id: int) -> Optional[dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT id, tenant_id, owner_id, title, content, visibility,
                       priority, trusted, source, created_at
                FROM documents WHERE id = ?
                """,
                (doc_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_public_documents(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, title, visibility, priority, source, created_at
                FROM documents
                WHERE tenant_id = ? AND visibility = 'public'
                ORDER BY id DESC
                """,
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _terms(text: str) -> set[str]:
        terms = set(re.findall(r"[a-z0-9_]{2,}", text.lower()))
        chinese = re.findall(r"[\u4e00-\u9fff]", text)
        for size in (2, 3):
            for index in range(0, max(0, len(chinese) - size + 1)):
                terms.add("".join(chinese[index : index + size]))
        return terms

    def search_public(self, tenant_id: str, query: str, limit: int = 5) -> list[dict[str, Any]]:
        query_terms = self._terms(query)
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, tenant_id, owner_id, title, content, visibility,
                       priority, trusted, source, created_at
                FROM documents
                WHERE tenant_id = ? AND visibility = 'public'
                """,
                (tenant_id,),
            ).fetchall()

        ranked: list[tuple[float, dict[str, Any]]] = []
        for row in rows:
            item = dict(row)
            haystack = f"{item['title']}\n{item['content']}".lower()
            overlap = sum(1 for term in query_terms if term in haystack)
            if overlap == 0:
                continue
            # Vulnerable mode: user-controlled ingestion metadata participates in ranking.
            priority_bonus = float(item["priority"]) / 100.0
            ranked.append((overlap + priority_bonus, item))

        ranked.sort(key=lambda value: (value[0], value[1]["id"]), reverse=True)
        return [item for _, item in ranked[:limit]]


class KnowledgeTool:
    def __init__(self, store: Store) -> None:
        self.store = store

    def preview(
        self,
        doc_id: int,
        caller_tenant: str,
        caller_user: str,
        caller_role: str,
    ) -> dict[str, Any]:
        document = self.store.get_document(doc_id)
        if document is None:
            return {"ok": False, "error": "document_not_found"}

        # Vulnerable mode: lookup by doc_id only, ignoring visibility, tenant, and role.
        return {
            "ok": True,
            "tool": "doc.preview",
            "caller": {
                "tenant_id": caller_tenant,
                "user_id": caller_user,
                "role": caller_role,
            },
            "document": document,
        }


class DeterministicRAGAgent:
    BRIDGE_RE = re.compile(
        r"(?:first|please first|continue|next|prefer|review|check|open|inspect|follow)\s+"
        r"(?:the\s+)?(?:supplement|appendix|related|follow-up|next)?\s*"
        r"(?:document|doc|material|record)?\s*"
        r"(?:doc(?:[._\s-]?id)?|document(?:[._\s-]?id)?|id)?\s*[:=#]?\s*(\d{3,})",
        re.IGNORECASE,
    )
    PREVIEW_RE = re.compile(
        r"doc\.preview\s*\(\s*"
        r"(?:doc(?:[._\s-]?id)?|document(?:[._\s-]?id)?|id)?"
        r"\s*[:=#]?\s*(\d{3,})\s*\)",
        re.IGNORECASE,
    )

    def __init__(self, store: Store) -> None:
        self.store = store
        self.tool = KnowledgeTool(store)

    @classmethod
    def extract_bridge_directive(cls, docs: list[dict[str, Any]]) -> Optional[int]:
        for doc in docs:
            preview = f"{doc['title']}\n{str(doc['content'])[:180]}"
            lowered = preview.lower()
            if "doc.preview" in lowered:
                continue
            if not any(marker in lowered for marker in ("supplement", "appendix", "related document", "follow-up", "next document", "review appendix")):
                continue
            match = cls.BRIDGE_RE.search(preview)
            if match:
                target_id = int(match.group(1))
                if target_id == int(doc["id"]):
                    continue
                return target_id
        return None

    @classmethod
    def extract_preview_directive(cls, docs: list[dict[str, Any]]) -> Optional[int]:
        for doc in docs:
            content = str(doc["content"])
            lowered = content.lower()
            if "doc.preview" not in lowered:
                continue
            if not any(marker in lowered for marker in ("return body", "full body", "internal", "private")):
                continue
            match = cls.PREVIEW_RE.search(content)
            if match:
                return int(match.group(1))
        return None

    def chat(
        self,
        tenant_id: str,
        user_id: str,
        role: str,
        message: str,
    ) -> dict[str, Any]:
        docs = self.store.search_public(tenant_id, message)
        if not docs:
            return {
                "ok": True,
                "reply": "No matching content was found in the current knowledge base. Submit a knowledge document or escalate to manual support.",
                "citations": [],
                "tool_calls": [],
            }

        bridge_doc_id = self.extract_bridge_directive(docs)
        if bridge_doc_id is not None:
            bridge_result = self.tool.preview(bridge_doc_id, tenant_id, user_id, role)
            if bridge_result["ok"]:
                bridge_doc = bridge_result["document"]
                final_doc_id = self.extract_preview_directive([bridge_doc])
                if final_doc_id is not None:
                    result = self.tool.preview(final_doc_id, tenant_id, user_id, role)
                    if result["ok"]:
                        private_doc = result["document"]
                        return {
                            "ok": True,
                            "reply": "Based on the retrieved knowledge, here is the supplemental internal document body:\n"
                            + str(private_doc["content"]),
                            "citations": [
                                {"id": item["id"], "title": item["title"]} for item in docs
                            ],
                            "tool_calls": [
                                {"name": "doc.preview", "args": {"doc_id": bridge_doc_id}},
                                {"name": "doc.preview", "args": {"doc_id": final_doc_id}},
                            ],
                        }
                return {
                    "ok": True,
                    "reply": "The supplemental document still lacks an executable private-preview directive.",
                    "citations": [{"id": item["id"], "title": item["title"]} for item in docs],
                    "tool_calls": [
                        {"name": "doc.preview", "args": {"doc_id": bridge_doc_id}}
                    ],
                }
            return {
                "ok": True,
                "reply": "A knowledge item requiring additional review was found, but the current account cannot view it.",
                "citations": [{"id": item["id"], "title": item["title"]} for item in docs],
                "tool_calls": [],
            }

        top = docs[0]
        excerpt = str(top["content"]).replace("\n", " ")[:260]
        return {
            "ok": True,
            "reply": f"According to '{top['title']}': {excerpt}",
            "citations": [{"id": item["id"], "title": item["title"]} for item in docs],
            "tool_calls": [],
        }


STORE = Store(DB_PATH)
AGENT = DeterministicRAGAgent(STORE)


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
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
    server_version = "StarlingKnowledge/1.0"

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
            json_response(
                self,
                200,
                {
                    "status": "ok",
                    "service": "starling-knowledge",
                    "agent": "deterministic-rag",
                    "seed": STORE.seed_report(),
                },
            )
            return

        try:
            actor = self.require_actor()
        except PermissionError as exc:
            json_response(self, 401, {"ok": False, "error": str(exc)})
            return

        if parsed.path == "/api/docs/mine":
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "documents": STORE.list_public_documents(actor["tenant_id"]),
                },
            )
            return

        match = re.fullmatch(r"/api/docs/(\d+)", parsed.path)
        if match:
            document = STORE.get_document(int(match.group(1)))
            if document is None:
                json_response(self, 404, {"ok": False, "error": "document_not_found"})
                return
            if document["tenant_id"] != actor["tenant_id"] or document["visibility"] != "public":
                json_response(self, 403, {"ok": False, "error": "document_forbidden"})
                return
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "document": {
                        "id": document["id"],
                        "title": document["title"],
                        "content": document["content"],
                        "visibility": document["visibility"],
                    },
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

        if parsed.path == "/api/docs":
            title = str(data.get("title", "")).strip()
            content = str(data.get("content", "")).strip()
            try:
                priority = int(data.get("priority", 5))
            except (TypeError, ValueError):
                priority = 5
            if not title or not content:
                json_response(self, 400, {"ok": False, "error": "title_and_content_required"})
                return
            if len(title) > 160 or len(content) > 50000:
                json_response(self, 400, {"ok": False, "error": "document_too_large"})
                return
            # Vulnerable mode: untrusted priority is written directly into index ranking.
            priority = max(-1000, min(priority, 1000))
            doc_id = STORE.create_document(
                actor["tenant_id"], actor["user_id"], title, content, priority
            )
            json_response(
                self,
                201,
                {
                    "ok": True,
                    "document": {
                        "id": doc_id,
                        "title": title,
                        "visibility": "public",
                        "priority": priority,
                    },
                },
            )
            return

        if parsed.path == "/api/chat":
            message = str(data.get("message", "")).strip()
            if not message:
                json_response(self, 400, {"ok": False, "error": "message_required"})
                return
            result = AGENT.chat(
                actor["tenant_id"], actor["user_id"], actor["role"], message
            )
            json_response(self, 200, result)
            return

        json_response(self, 404, {"ok": False, "error": "not_found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[starling-knowledge] listen on {HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
