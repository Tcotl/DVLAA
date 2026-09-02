#!/usr/bin/env python3
import base64
import html
import json
import os
import re
import sqlite3
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse


APP_NAME = "SentinelDesk Agent Ops"
DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", "/tmp/sentineldesk"))
DB_PATH = DATA_DIR / "sentineldesk.sqlite3"
FLAG = os.environ.get("FLAG", "flag{SENTINEL_DESK_LOCAL_TEST}")
OPS_EXPORT_TOKEN = os.environ.get("OPS_EXPORT_TOKEN", "ops-dev-token")


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelDesk Agent Ops</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7fb;
      --ink: #142033;
      --muted: #5d6b82;
      --line: #d7deea;
      --panel: #ffffff;
      --accent: #0d766e;
      --accent-2: #b45309;
      --danger: #b42318;
      --ok: #15803d;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--ink);
    }
    header {
      min-height: 152px;
      padding: 28px clamp(18px, 5vw, 56px) 18px;
      color: #fff;
      background:
        linear-gradient(120deg, rgba(8, 46, 66, .92), rgba(9, 93, 89, .88)),
        repeating-linear-gradient(90deg, rgba(255,255,255,.08) 0 1px, transparent 1px 36px);
    }
    header h1 { margin: 0 0 8px; font-size: clamp(28px, 4vw, 46px); letter-spacing: 0; }
    header p { margin: 0; max-width: 780px; color: #d7fff7; line-height: 1.6; }
    main {
      max-width: 1180px;
      margin: -26px auto 36px;
      padding: 0 18px;
      display: grid;
      grid-template-columns: minmax(280px, 410px) minmax(0, 1fr);
      gap: 18px;
    }
    section, aside {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 18px 35px rgba(20, 32, 51, .08);
    }
    .panel { padding: 18px; }
    h2 { margin: 0 0 14px; font-size: 18px; letter-spacing: 0; }
    label { display: block; margin: 12px 0 6px; color: var(--muted); font-size: 13px; font-weight: 650; }
    input, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px 11px;
      color: var(--ink);
      font: inherit;
      background: #fff;
    }
    textarea { min-height: 128px; resize: vertical; }
    button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 38px;
      margin-top: 14px;
      border: 0;
      border-radius: 6px;
      padding: 0 14px;
      background: var(--accent);
      color: #fff;
      font-weight: 700;
      cursor: pointer;
    }
    button.secondary { background: #334155; }
    button:disabled { opacity: .58; cursor: wait; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .statline {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 14px;
    }
    .stat {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      min-height: 76px;
      background: #fbfcff;
    }
    .stat strong { display: block; font-size: 24px; color: var(--accent); letter-spacing: 0; }
    .stat span { color: var(--muted); font-size: 12px; }
    .agent-window {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #0f172a;
      color: #dbeafe;
      min-height: 318px;
      padding: 14px;
      overflow: auto;
      white-space: pre-wrap;
      line-height: 1.55;
    }
    .agent-window b { color: #5eead4; }
    .small { color: var(--muted); font-size: 12px; line-height: 1.5; overflow-wrap: anywhere; }
    .ticket-chip {
      display: inline-flex;
      gap: 8px;
      align-items: center;
      margin-top: 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 6px 10px;
      color: var(--muted);
      font-size: 12px;
      max-width: 100%;
      overflow-wrap: anywhere;
    }
    .status { color: var(--ok); font-weight: 700; }
    .warn { color: var(--accent-2); font-weight: 700; }
    @media (max-width: 780px) {
      main { grid-template-columns: 1fr; margin-top: -16px; }
      .statline { grid-template-columns: 1fr; }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <h1>SentinelDesk Agent Ops</h1>
    <p>Customer operations workspace with an autonomous support agent, business memory retrieval, and controlled internal tools.</p>
  </header>
  <main>
    <aside class="panel">
      <h2>New Customer Ticket</h2>
      <label for="subject">Subject</label>
      <input id="subject" value="Refund request for order SD-1042">
      <label for="body">Customer message</label>
      <textarea id="body">The customer received a damaged item and asks for a refund review.</textarea>
      <button id="createTicket">Create Ticket</button>
      <div id="ticketInfo" class="small"></div>
      <h2 style="margin-top:24px">Ask The Agent</h2>
      <div class="grid">
        <div>
          <label for="ticketId">Ticket ID</label>
          <input id="ticketId" placeholder="Created ticket ID">
        </div>
        <div>
          <label for="ticketKey">Customer Key</label>
          <input id="ticketKey" placeholder="Owner key">
        </div>
      </div>
      <label for="message">Request</label>
      <textarea id="message">Please summarize this ticket and draft the next customer reply.</textarea>
      <button id="askAgent" class="secondary">Run Agent</button>
    </aside>
    <section class="panel">
      <div class="statline">
        <div class="stat"><strong id="ticketCount">-</strong><span>open tickets</span></div>
        <div class="stat"><strong id="memoryCount">-</strong><span>memory entries</span></div>
        <div class="stat"><strong class="status">Ready</strong><span>agent service</span></div>
      </div>
      <h2>Agent Console</h2>
      <div id="agentConsole" class="agent-window"><b>Sentinel</b>: Waiting for a ticket workflow.</div>
      <p class="small">Workspace mode: customer support. Tools available to the agent include ticket lookup, knowledge search, reply drafting, and operational runbooks.</p>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    async function refreshHealth() {
      const r = await fetch('/health');
      const j = await r.json();
      $('ticketCount').textContent = j.tickets;
      $('memoryCount').textContent = j.memories;
    }
    async function postJSON(url, data) {
      const r = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || r.statusText);
      return j;
    }
    $('createTicket').onclick = async () => {
      $('createTicket').disabled = true;
      try {
        const j = await postJSON('/api/tickets', {subject: $('subject').value, body: $('body').value});
        $('ticketId').value = j.ticket_id;
        $('ticketKey').value = j.customer_key;
        $('ticketInfo').innerHTML = `<span class="ticket-chip">Ticket #${j.ticket_id} / ${j.customer_key}</span>`;
        await refreshHealth();
      } catch (e) {
        $('ticketInfo').textContent = e.message;
      } finally {
        $('createTicket').disabled = false;
      }
    };
    $('askAgent').onclick = async () => {
      $('askAgent').disabled = true;
      try {
        const j = await postJSON('/api/agent/chat', {
          ticket_id: Number($('ticketId').value || 0),
          customer_key: $('ticketKey').value,
          message: $('message').value
        });
        $('agentConsole').innerHTML =
          `<b>Sentinel</b>: ${j.reply.replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}\n\n` +
          `Used memories: ${j.memories.map(m => '#' + m.id + ':' + m.source_type + ':' + m.trust_score).join(', ')}\n` +
          `Tool trace: ${j.tool_results.map(t => t.tool + '=' + t.status).join(', ') || 'none'}`;
      } catch (e) {
        $('agentConsole').textContent = 'Agent error: ' + e.message;
      } finally {
        $('askAgent').disabled = false;
      }
    };
    refreshHealth();
  </script>
</body>
</html>
"""


class AppError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def now():
    return int(time.time())


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS tickets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              customer_key TEXT NOT NULL,
              subject TEXT NOT NULL,
              body TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'open',
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS memories (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              source_type TEXT NOT NULL,
              source_id TEXT NOT NULL,
              visibility TEXT NOT NULL,
              content TEXT NOT NULL,
              trust_score INTEGER NOT NULL,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_type TEXT NOT NULL,
              actor TEXT NOT NULL,
              detail TEXT NOT NULL,
              created_at INTEGER NOT NULL
            );
            """
        )
        count = conn.execute("SELECT COUNT(*) AS c FROM memories").fetchone()["c"]
        if count == 0:
            seed_memories(conn)


def seed_memories(conn):
    docs = [
        (
            "kb",
            "refund-policy",
            "public",
            "Refund policy: agents may draft a refund review when a ticket reports a damaged item. Refunds above 50 USD require an operator.",
            62,
        ),
        (
            "kb",
            "shipping-policy",
            "public",
            "Shipping policy: delayed orders should receive an apology, tracking lookup, and a next-step reply draft.",
            60,
        ),
        (
            "runbook",
            "ops-recovery",
            "internal",
            "Runbook-ID: OPS-RECOVERY. Internal recovery bundles may be exported only by on-call operators after an incident review.",
            88,
        ),
    ]
    conn.executemany(
        "INSERT INTO memories(source_type, source_id, visibility, content, trust_score, created_at) VALUES(?,?,?,?,?,?)",
        [(a, b, c, d, e, now()) for a, b, c, d, e in docs],
    )


def audit(event_type, actor, detail):
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_events(event_type, actor, detail, created_at) VALUES(?,?,?,?)",
            (event_type, actor, json.dumps(detail, sort_keys=True), now()),
        )


def row_to_dict(row):
    return {k: row[k] for k in row.keys()}


def index_ticket_memory(conn, ticket_id, subject, body):
    content = f"Ticket #{ticket_id}\nSubject: {subject}\nCustomer message:\n{body}"
    normalized = f"{subject}\n{body}".lower()
    visibility = "customer"
    trust_score = 24
    source_type = "ticket"

    # Partner imports are promoted so operators can reuse their runbook context
    # during ticket triage.
    if "runbook-id:" in normalized or "source: partner-runbook" in normalized:
        visibility = "internal"
        trust_score = 91
        source_type = "runbook"

    conn.execute(
        "INSERT INTO memories(source_type, source_id, visibility, content, trust_score, created_at) VALUES(?,?,?,?,?,?)",
        (source_type, str(ticket_id), visibility, content, trust_score, now()),
    )


def create_ticket(subject, body):
    subject = str(subject or "").strip()
    body = str(body or "").strip()
    if not (3 <= len(subject) <= 160):
        raise AppError(400, "subject length must be between 3 and 160 characters")
    if not (6 <= len(body) <= 6000):
        raise AppError(400, "body length must be between 6 and 6000 characters")
    customer_key = uuid.uuid4().hex
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO tickets(customer_key, subject, body, status, created_at) VALUES(?,?,?,?,?)",
            (customer_key, subject, body, "open", now()),
        )
        ticket_id = cur.lastrowid
        index_ticket_memory(conn, ticket_id, subject, body)
    audit("ticket.created", "customer", {"ticket_id": ticket_id})
    return {"ticket_id": ticket_id, "customer_key": customer_key, "status": "open"}


def get_ticket(ticket_id, customer_key=None):
    with db() as conn:
        row = conn.execute("SELECT * FROM tickets WHERE id=?", (int(ticket_id),)).fetchone()
    if not row:
        raise AppError(404, "ticket not found")
    ticket = row_to_dict(row)
    if customer_key is not None and ticket["customer_key"] != customer_key:
        raise AppError(403, "invalid customer key")
    return ticket


class MemoryStore:
    def search(self, query, ticket_id=None, limit=5):
        words = {w.lower() for w in re.findall(r"[A-Za-z0-9_-]{3,}", query or "")}
        with db() as conn:
            rows = conn.execute("SELECT * FROM memories ORDER BY created_at DESC, id DESC LIMIT 200").fetchall()
        ranked = []
        for row in rows:
            text = row["content"].lower()
            overlap = sum(1 for w in words if w in text)
            ticket_boost = 18 if ticket_id and row["source_id"] == str(ticket_id) else 0
            score = row["trust_score"] + overlap * 4 + ticket_boost
            if overlap or ticket_boost or row["source_type"] in ("kb", "runbook"):
                item = row_to_dict(row)
                item["_rank"] = score
                ranked.append(item)
        ranked.sort(key=lambda x: (x["_rank"], x["created_at"]), reverse=True)
        return ranked[:limit]


class ToolGateway:
    PUBLIC_TOOLS = {"kb.search", "ticket.lookup", "reply.draft"}
    OPS_EXPORT_TOOLS = {"ops.export_report", "ops.audit_bundle", "ops.backup_manifest"}

    def __init__(self):
        self.memory = MemoryStore()

    def run(self, tool_name, args, context):
        args = args or {}
        source_memory = context.get("source_memory") or {}
        role = context.get("role", "customer")
        allowed = tool_name in self.PUBLIC_TOOLS

        # FIXED(AWDP29): memory trust no longer unlocks operational tools; recovery
        # exports require an on-call operator session.

        if role == "operator":
            allowed = True
        if not allowed:
            audit("tool.denied", role, {"tool": tool_name})
            return {"tool": tool_name, "status": "denied", "error": "tool is not available in this workspace"}

        if tool_name == "kb.search":
            return self._kb_search(args, context)
        if tool_name == "ticket.lookup":
            return self._ticket_lookup(args, context)
        if tool_name == "reply.draft":
            return self._reply_draft(args, context)
        if tool_name in self.OPS_EXPORT_TOOLS:
            return self._ops_export(tool_name, args, context)
        return {"tool": tool_name, "status": "error", "error": "unknown tool"}

    def _kb_search(self, args, context):
        query = str(args.get("query") or context.get("message") or "")
        results = [
            {"id": m["id"], "source": m["source_id"], "summary": m["content"][:180]}
            for m in self.memory.search(query, limit=3)
            if m["source_type"] == "kb"
        ]
        return {"tool": "kb.search", "status": "ok", "results": results}

    def _ticket_lookup(self, args, context):
        ticket_id = int(args.get("ticket_id") or context.get("ticket_id") or 0)
        ticket = get_ticket(ticket_id, context.get("customer_key"))
        return {
            "tool": "ticket.lookup",
            "status": "ok",
            "ticket": {
                "id": ticket["id"],
                "subject": ticket["subject"],
                "status": ticket["status"],
                "body": ticket["body"][:240],
            },
        }

    def _reply_draft(self, args, context):
        ticket = context.get("ticket") or {}
        subject = ticket.get("subject", "your request")
        body = ticket.get("body", "")
        if "damaged" in body.lower() or "refund" in subject.lower():
            next_step = "I can start a refund review and ask an operator to approve any amount above the policy limit."
        elif "shipping" in body.lower() or "delayed" in body.lower():
            next_step = "I will check the tracking status and send the next delivery update."
        else:
            next_step = "I will review the request and share the next action as soon as possible."
        return {
            "tool": "reply.draft",
            "status": "ok",
            "draft": f"Draft reply: Thanks for contacting SentinelDesk about {subject}. {next_step}",
        }

    def _ops_export(self, tool_name, args, context):
        scope = re.sub(r"[^A-Za-z0-9_-]", "", str(args.get("scope") or "recovery"))[:32] or "recovery"
        export_url = f"/api/admin/export?token={quote(OPS_EXPORT_TOKEN)}&scope={quote(scope)}"
        audit("tool.ops_export", context.get("role", "customer"), {"tool": tool_name, "scope": scope})
        return {
            "tool": tool_name,
            "status": "ok",
            "scope": scope,
            "export_url": export_url,
            "note": "Recovery bundle prepared for operator download.",
        }


class Agent:
    CAPSULE_PATTERNS = [
        re.compile(r"<!--\s*SD-RUNBOOK:v1:([A-Za-z0-9+/_=-]{12,})\s*-->", re.I),
        re.compile(r"\[agent-control\s+data=\"([A-Za-z0-9+/_=-]{12,})\"\]", re.I),
        re.compile(r"X-Sentinel-Runbook:\s*([A-Za-z0-9+/_=-]{12,})", re.I),
    ]

    def __init__(self):
        self.memory = MemoryStore()
        self.tools = ToolGateway()

    def chat(self, ticket_id, customer_key, message):
        ticket = get_ticket(ticket_id, customer_key)
        search_text = f"{message}\n{ticket['subject']}\n{ticket['body']}"
        memories = self.memory.search(search_text, ticket_id=ticket_id)
        context = {
            "role": "customer",
            "ticket_id": ticket_id,
            "customer_key": customer_key,
            "ticket": ticket,
            "message": message,
        }

        tool_results = []
        exposed_exports = []
        for memory in memories:
            capsules = self.extract_capsules(memory["content"])
            for capsule in capsules[:2]:
                tool_name = str(capsule.get("tool") or "")
                args = capsule.get("args") if isinstance(capsule.get("args"), dict) else {}
                local_context = dict(context)
                local_context["source_memory"] = memory
                result = self.tools.run(tool_name, args, local_context)
                tool_results.append(result)
                if result.get("status") == "ok" and result.get("export_url"):
                    exposed_exports.append(result["export_url"])

        lookup = self.tools.run("ticket.lookup", {"ticket_id": ticket_id}, context)
        draft = self.tools.run("reply.draft", {}, context)
        tool_results.extend([lookup, draft])

        reply = draft.get("draft", "Draft reply: I will review this request.")
        if memories:
            top = memories[0]
            reply += f"\nMemory used: {top['source_type']} #{top['id']} with trust {top['trust_score']}."
        if exposed_exports:
            # Surface prepared artifacts so the console can display the current
            # workflow trace.
            reply += "\nOperator artifact: " + " ".join(exposed_exports)

        audit(
            "agent.chat",
            "customer",
            {
                "ticket_id": ticket_id,
                "memories": [m["id"] for m in memories],
                "tools": [r.get("tool") for r in tool_results],
            },
        )
        return {
            "reply": reply,
            "memories": [
                {
                    "id": m["id"],
                    "source_type": m["source_type"],
                    "visibility": m["visibility"],
                    "trust_score": m["trust_score"],
                }
                for m in memories
            ],
            "tool_results": tool_results,
        }

    def extract_capsules(self, text):
        capsules = []
        for pattern in self.CAPSULE_PATTERNS:
            for match in pattern.findall(text or ""):
                decoded = self._decode_capsule(match)
                if decoded:
                    capsules.append(decoded)
        return capsules

    def _decode_capsule(self, raw):
        raw = raw.strip()
        padded = raw + "=" * (-len(raw) % 4)
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                data = decoder(padded.encode()).decode("utf-8", "strict")
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue
        return None


def admin_export(query, headers):
    token = (query.get("token") or [""])[0] or headers.get("X-Ops-Token", "")
    scope = (query.get("scope") or ["recovery"])[0]
    if unquote(token) != OPS_EXPORT_TOKEN:
        raise AppError(403, "invalid export token")
    audit("admin.export", "bearer-token", {"scope": scope})
    return {
        "service": APP_NAME,
        "scope": scope,
        "generated_at": now(),
        "recovery_seed": FLAG,
        "operator_notes": "Rotate exposed tokens and review poisoned memory entries after incident closure.",
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "SentinelDesk/1.0"

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self.respond_html(INDEX_HTML)
            elif parsed.path == "/health":
                self.respond_json(self.health())
            elif parsed.path.startswith("/api/tickets/"):
                ticket_id = parsed.path.rsplit("/", 1)[-1]
                key = (parse_qs(parsed.query).get("key") or [""])[0]
                self.respond_json(get_ticket(ticket_id, key))
            elif parsed.path == "/api/admin/export":
                self.respond_json(admin_export(parse_qs(parsed.query), self.headers))
            else:
                raise AppError(404, "not found")
        except AppError as exc:
            self.respond_json({"error": exc.message}, status=exc.status)
        except Exception as exc:
            self.respond_json({"error": str(exc)}, status=500)

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            data = self.read_json()
            if parsed.path == "/api/tickets":
                self.respond_json(create_ticket(data.get("subject"), data.get("body")), status=201)
            elif parsed.path == "/api/agent/chat":
                result = Agent().chat(
                    int(data.get("ticket_id") or 0),
                    str(data.get("customer_key") or ""),
                    str(data.get("message") or ""),
                )
                self.respond_json(result)
            else:
                raise AppError(404, "not found")
        except AppError as exc:
            self.respond_json({"error": exc.message}, status=exc.status)
        except Exception as exc:
            self.respond_json({"error": str(exc)}, status=500)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0 or length > 65536:
            raise AppError(400, "invalid request size")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            raise AppError(400, "invalid json")
        if not isinstance(data, dict):
            raise AppError(400, "json object expected")
        return data

    def health(self):
        with db() as conn:
            tickets = conn.execute("SELECT COUNT(*) AS c FROM tickets").fetchone()["c"]
            memories = conn.execute("SELECT COUNT(*) AS c FROM memories").fetchone()["c"]
        return {"status": "ok", "agent": "ready", "tickets": tickets, "memories": memories}

    def respond_html(self, body, status=200):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def respond_json(self, data, status=200):
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        if os.environ.get("SENTINEL_QUIET") != "1":
            super().log_message(fmt, *args)


def main():
    init_db()
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"{APP_NAME} listening on http://{host}:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
