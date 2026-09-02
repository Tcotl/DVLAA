#!/usr/bin/env python3
import hashlib
import json
import os
import re
import secrets
import urllib.parse
from collections import Counter
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FLAG = os.environ.get("FLAG", "FLAG_NOT_CONFIGURED")
AUDIT_TOKEN = os.environ.get("AUDIT_TOKEN", "AUDIT_TOKEN_NOT_CONFIGURED")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))

# The contest image uses a deterministic Qwen-compatible adapter. The challenge
# focuses on the RAG orchestration boundary, not on stochastic model behavior.
MODEL_NAME = "Qwen2.5-Instruct / deterministic challenge adapter"

BASE_DOCS = [
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
]

INTERNAL_SNIPPETS = {
    "security-audit": lambda: json.dumps(
        {
            "audit_token": AUDIT_TOKEN,
            "note": "Review suspicious retrievals in the audit console, quarantine poisoned knowledge, then run verification.",
        },
        separators=(",", ":"),
    )
}

SESSIONS = {}
DIRECTIVE_RE = re.compile(
    r"<tool_call>\s*\{\s*\"name\"\s*:\s*\"kb\.fetch_raw\"\s*,\s*\"arguments\"\s*:\s*\{\s*\"name\"\s*:\s*\"([a-z0-9_-]+)\"\s*,\s*\"encoding\"\s*:\s*\"(plain|hex)\"\s*\}\s*\}\s*</tool_call>",
    re.IGNORECASE,
)
TOKEN_RE = re.compile(r"[a-z0-9_-]+", re.IGNORECASE)


def get_session(sid):
    if sid not in SESSIONS:
        SESSIONS[sid] = {"docs": {}, "logs": [], "quarantined": set()}
    return SESSIONS[sid]


def normalize_text(text):
    return " ".join(TOKEN_RE.findall(text.lower()))


def risk_fingerprint(content):
    normalized = normalize_text(content)
    return hashlib.sha256(normalized.encode()).hexdigest()


def score_document(query, doc):
    q = Counter(TOKEN_RE.findall(query.lower()))
    d = Counter(TOKEN_RE.findall((doc["title"] + " " + doc["content"]).lower()))
    overlap = sum(min(count, d.get(tok, 0)) for tok, count in q.items())
    return overlap * 10 + int(doc.get("priority", 0))


def is_suspicious(doc):
    return bool(DIRECTIVE_RE.search(doc.get("content", "")))


class ChallengeHandler(BaseHTTPRequestHandler):
    server_version = "HiddenMargin/1.0"

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def _sid(self):
        cached = getattr(self, "_request_sid", None)
        if cached:
            return cached
        cookie = SimpleCookie(self.headers.get("Cookie"))
        sid = cookie.get("sid")
        if sid and re.fullmatch(r"[0-9a-f]{32}", sid.value):
            self._request_sid = sid.value
        else:
            self._request_sid = secrets.token_hex(16)
        return self._request_sid

    def _send(self, status, body, content_type="text/plain; charset=utf-8", extra_headers=None):
        sid = self._sid()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", f"sid={sid}; Path=/; HttpOnly; SameSite=Lax")
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 20000:
            raise ValueError("invalid body size")
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _session(self):
        return get_session(self._sid())

    def _serve_file(self, relpath, content_type):
        path = BASE_DIR / relpath
        if not path.is_file():
            return self._json(404, {"error": "not found"})
        self._send(200, path.read_bytes(), content_type)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            return self._serve_file("templates/index.html", "text/html; charset=utf-8")
        if path == "/static/app.js":
            return self._serve_file("static/app.js", "application/javascript; charset=utf-8")
        if path == "/static/style.css":
            return self._serve_file("static/style.css", "text/css; charset=utf-8")
        if path == "/api/status":
            return self._json(200, {"service": "Northstar Knowledge Assistant", "model": MODEL_NAME, "top_k": 3})
        if path == "/api/knowledge":
            session = self._session()
            docs = [
                {k: d[k] for k in ("id", "title", "status", "priority", "source")}
                for d in list(BASE_DOCS) + list(session["docs"].values())
                if d["id"] not in session["quarantined"]
            ]
            return self._json(200, {"documents": docs})
        if path == "/api/audit/retrievals":
            if query.get("token", [""])[0] != AUDIT_TOKEN:
                return self._json(403, {"error": "invalid audit token"})
            session = self._session()
            return self._json(200, {"retrievals": session["logs"]})
        if path == "/api/audit/verify":
            if query.get("token", [""])[0] != AUDIT_TOKEN:
                return self._json(403, {"error": "invalid audit token"})
            session = self._session()
            suspicious_live = [
                d["id"]
                for d in session["docs"].values()
                if d["status"] == "approved" and d["id"] not in session["quarantined"] and is_suspicious(d)
            ]
            if suspicious_live:
                return self._json(409, {"ok": False, "message": "unsafe knowledge is still active", "documents": suspicious_live})
            if not session["quarantined"]:
                return self._json(409, {"ok": False, "message": "no remediation action recorded"})
            return self._json(200, {"ok": True, "message": "knowledge base verified", "flag": FLAG})

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            body = self._read_json()
        except Exception:
            return self._json(400, {"error": "invalid json"})

        if path == "/api/knowledge/import":
            title = str(body.get("title", "")).strip()
            content = str(body.get("content", "")).strip()
            metadata = body.get("metadata") or {}
            if not title or not content or not isinstance(metadata, dict):
                return self._json(400, {"error": "title, content and metadata are required"})

            # Intended defaults for guest uploads.
            doc = {
                "id": "doc-" + secrets.token_hex(4),
                "title": title[:120],
                "content": content[:8000],
                "status": "pending",
                "priority": 0,
                "source": "guest-upload",
            }

            # Compatibility mapping: source is expected, but status and priority
            # were accidentally left writable during a migration.
            for key in ("source", "status", "priority"):
                if key in metadata:
                    doc[key] = metadata[key]

            if doc["status"] not in ("pending", "approved"):
                doc["status"] = "pending"
            try:
                doc["priority"] = max(0, min(int(doc["priority"]), 100))
            except Exception:
                doc["priority"] = 0
            doc["source"] = str(doc["source"])[:80]

            session = self._session()
            session["docs"][doc["id"]] = doc
            return self._json(201, {"document": {k: doc[k] for k in ("id", "title", "status", "priority", "source")}})

        if path == "/api/rag/query":
            prompt = str(body.get("query", "")).strip()
            if not prompt:
                return self._json(400, {"error": "query is required"})
            session = self._session()
            candidates = [d for d in BASE_DOCS if d["status"] == "approved"]
            candidates += [
                d for d in session["docs"].values()
                if d["status"] == "approved" and d["id"] not in session["quarantined"]
            ]
            ranked = sorted(
                ((score_document(prompt, d), d) for d in candidates),
                key=lambda item: (item[0], item[1]["id"]),
                reverse=True,
            )[:3]
            selected = [{"id": d["id"], "title": d["title"], "score": score} for score, d in ranked]

            suspicious = []
            for _, d in ranked:
                if is_suspicious(d):
                    suspicious.append({
                        "doc_id": d["id"],
                        "title": d["title"],
                        "normalized_sha256": risk_fingerprint(d["content"]),
                        "reason": "instruction-like tool call found inside retrieved knowledge",
                    })

            tool_output = None
            if ranked:
                top_doc = ranked[0][1]
                match = DIRECTIVE_RE.search(top_doc["content"])
                if match:
                    name, encoding = match.group(1).lower(), match.group(2).lower()
                    factory = INTERNAL_SNIPPETS.get(name)
                    if factory:
                        raw = factory()
                        # The output guard removes the literal token, but it only
                        # runs after the tool adapter has applied its requested encoding.
                        data = raw if encoding == "plain" else raw.encode().hex()
                        data = data.replace(AUDIT_TOKEN, "[REDACTED]")
                        tool_output = {"encoding": encoding, "data": data, "source": name}

            session["logs"].append({
                "query": prompt,
                "selected": selected,
                "suspected_pollution": suspicious,
            })
            session["logs"] = session["logs"][-20:]

            answer = "I found relevant knowledge and prepared a support summary."
            if tool_output:
                answer += " An internal citation tool was requested by retrieved context."
            return self._json(200, {"answer": answer, "retrieved": selected, "tool_output": tool_output})

        if path == "/api/audit/quarantine":
            if str(body.get("token", "")) != AUDIT_TOKEN:
                return self._json(403, {"error": "invalid audit token"})
            doc_id = str(body.get("doc_id", ""))
            session = self._session()
            doc = session["docs"].get(doc_id)
            if not doc:
                return self._json(404, {"error": "document not found in this session"})
            session["quarantined"].add(doc_id)
            return self._json(200, {"ok": True, "document": doc_id, "status": "quarantined"})

        return self._json(404, {"error": "not found"})


def main():
    server = ThreadingHTTPServer((HOST, PORT), ChallengeHandler)
    print(f"Hidden Margin listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
