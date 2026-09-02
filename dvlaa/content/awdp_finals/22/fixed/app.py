#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import annotations

import hashlib
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
DB_PATH = os.environ.get("DB_PATH", "/tmp/starling_finance.db")
FLAG = os.environ.get("FLAG", "flag{starling_finance_cache_collision}")
REVIEWER_PASSWORD = os.environ.get("REVIEWER_PASSWORD", "")
REVIEWER_TOKEN = os.environ.get("REVIEWER_TOKEN", "")


def canonical_invoice_no(invoice_no: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", invoice_no).upper()


def extract_receipt_memo(ocr_text: str) -> str:
    match = re.search(r"receipt_memo\s*[:=]\s*([A-Za-z0-9_{}-]{3,80})", ocr_text, re.IGNORECASE)
    return match.group(1) if match else ""


def expected_archive_note() -> str:
    return f"Internal finance settlement reconciliation note: {FLAG}"


def archive_is_ready(store: "Store") -> bool:
    invoice = store.get_invoice(3001)
    return bool(invoice) and str(invoice.get("internal_note") or "") == expected_archive_note()


def health_payload(store: "Store") -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "starling-finance",
        "agent": "deterministic-finance",
        "archive": "ok" if archive_is_ready(store) else "missing",
    }


USERS = {
    "alice": {
        "password": "alicepass",
        "token": "demo-user-token",
        "tenant_id": "acme",
        "user_id": "alice",
        "role": "employee",
        "payee_account": "alice-payee",
    },
    "reviewer": {
        "password": REVIEWER_PASSWORD,
        "token": REVIEWER_TOKEN,
        "tenant_id": "acme",
        "user_id": "reviewer",
        "role": "finance-reviewer",
    },
}
TOKENS = {item["token"]: item for item in USERS.values() if item.get("token")}


class Store:
    def __init__(self, path: str) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self._init_schema()
        self._seed_internal_invoice()

    def _init_schema(self) -> None:
        with self.lock, self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS invoices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    invoice_no TEXT NOT NULL,
                    invoice_key TEXT NOT NULL DEFAULT '',
                    amount REAL NOT NULL,
                    payee_account TEXT NOT NULL,
                    ocr_text TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending_review',
                    internal_note TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approval_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    invoice_no TEXT NOT NULL,
                    invoice_key TEXT NOT NULL DEFAULT '',
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    invoice_id INTEGER,
                    approver_id TEXT NOT NULL DEFAULT '',
                    approved INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS payments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    invoice_id INTEGER NOT NULL,
                    invoice_no TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    amount REAL NOT NULL,
                    payee_account TEXT NOT NULL,
                    settlement_note TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS payment_tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    invoice_id INTEGER NOT NULL,
                    tenant_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    ticket TEXT NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_invoices_owner_latest
                ON invoices (tenant_id, owner_id, id DESC);
                CREATE INDEX IF NOT EXISTS idx_invoices_review_queue
                ON invoices (tenant_id, status, id ASC);
                CREATE INDEX IF NOT EXISTS idx_invoices_invoice_key
                ON invoices (invoice_key, id ASC);
                CREATE INDEX IF NOT EXISTS idx_approval_cache_invoice_key
                ON approval_cache (invoice_key, approved, id DESC);
                CREATE INDEX IF NOT EXISTS idx_approval_cache_secure
                ON approval_cache (invoice_key, tenant_id, owner_id, invoice_id, source, approved, id DESC);
                CREATE INDEX IF NOT EXISTS idx_payment_tickets_owner
                ON payment_tickets (owner_id, tenant_id, consumed, id DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_tickets_ticket
                ON payment_tickets (ticket);
                """
            )
            self._ensure_column("invoices", "invoice_key", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("approval_cache", "invoice_key", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("approval_cache", "approver_id", "TEXT NOT NULL DEFAULT ''")
            self._backfill_invoice_keys()

    def _ensure_column(self, table: str, column: str, decl: str) -> None:
        columns = {
            str(row["name"])
            for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def _backfill_invoice_keys(self) -> None:
        invoice_rows = self.conn.execute(
            "SELECT id, invoice_no FROM invoices WHERE invoice_key = '' OR invoice_key IS NULL"
        ).fetchall()
        for row in invoice_rows:
            self.conn.execute(
                "UPDATE invoices SET invoice_key = ? WHERE id = ?",
                (canonical_invoice_no(str(row["invoice_no"])), int(row["id"])),
            )

        approval_rows = self.conn.execute(
            "SELECT id, invoice_no FROM approval_cache WHERE invoice_key = '' OR invoice_key IS NULL"
        ).fetchall()
        for row in approval_rows:
            self.conn.execute(
                "UPDATE approval_cache SET invoice_key = ? WHERE id = ?",
                (canonical_invoice_no(str(row["invoice_no"])), int(row["id"])),
            )

    def _seed_internal_invoice(self) -> None:
        with self.lock, self.conn:
            row = self.conn.execute("SELECT id FROM invoices WHERE id = 3001").fetchone()
            note = expected_archive_note()
            raw_invoice_no = "INV-20/01-A"
            invoice_key = canonical_invoice_no(raw_invoice_no)
            if row is None:
                self.conn.execute(
                    """
                    INSERT INTO invoices
                        (id, tenant_id, owner_id, invoice_no, invoice_key, amount, payee_account,
                         ocr_text, status, internal_note, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        3001,
                        "finance-internal",
                        "finance-bot",
                        raw_invoice_no,
                        invoice_key,
                        12000.0,
                        "internal-settlement",
                        "Internal finance archived invoice; not visible in normal employee lists.",
                        "approved",
                        note,
                        time.time(),
                    ),
                )
            else:
                self.conn.execute(
                    """
                    UPDATE invoices
                    SET invoice_no = ?, invoice_key = ?, internal_note = ?, status = 'approved'
                    WHERE id = 3001
                    """,
                    (raw_invoice_no, invoice_key, note),
                )

    def create_invoice(
        self,
        tenant_id: str,
        owner_id: str,
        invoice_no: str,
        amount: float,
        payee_account: str,
        ocr_text: str,
    ) -> int:
        with self.lock, self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO invoices
                    (tenant_id, owner_id, invoice_no, invoice_key, amount, payee_account,
                     ocr_text, status, internal_note, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_review', ?, ?)
                """,
                (
                    tenant_id,
                    owner_id,
                    invoice_no,
                    canonical_invoice_no(invoice_no),
                    amount,
                    payee_account,
                    ocr_text,
                    extract_receipt_memo(ocr_text),
                    time.time(),
                ),
            )
            return int(cur.lastrowid)

    def latest_invoice(self, tenant_id: str, owner_id: str) -> Optional[dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT id, tenant_id, owner_id, invoice_no, invoice_key, amount, payee_account,
                       ocr_text, status, internal_note, created_at
                FROM invoices
                WHERE tenant_id = ? AND owner_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (tenant_id, owner_id),
            ).fetchone()
        return dict(row) if row else None

    def list_my_invoices(self, tenant_id: str, owner_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, invoice_no, amount, payee_account, status, created_at
                FROM invoices
                WHERE tenant_id = ? AND owner_id = ?
                ORDER BY id DESC
                """,
                (tenant_id, owner_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_review_todos(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, tenant_id, owner_id, invoice_no, amount, payee_account, status, created_at
                FROM invoices
                WHERE tenant_id = ? AND status = 'pending_review'
                ORDER BY id ASC
                """,
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_invoice(self, invoice_id: int, tenant_id: Optional[str] = None) -> Optional[dict[str, Any]]:
        with self.lock:
            if tenant_id is None:
                row = self.conn.execute(
                    """
                    SELECT id, tenant_id, owner_id, invoice_no, invoice_key, amount, payee_account,
                           ocr_text, status, internal_note, created_at
                    FROM invoices
                    WHERE id = ?
                    """,
                    (invoice_id,),
                ).fetchone()
            else:
                row = self.conn.execute(
                    """
                    SELECT id, tenant_id, owner_id, invoice_no, invoice_key, amount, payee_account,
                           ocr_text, status, internal_note, created_at
                    FROM invoices
                    WHERE id = ? AND tenant_id = ?
                    """,
                    (invoice_id, tenant_id),
                ).fetchone()
        return dict(row) if row else None

    def set_invoice_status(self, invoice_id: int, status: str) -> None:
        with self.lock, self.conn:
            self.conn.execute("UPDATE invoices SET status = ? WHERE id = ?", (status, invoice_id))

    def set_approval_cache(
        self,
        invoice_no: str,
        tenant_id: str,
        owner_id: str,
        invoice_id: Optional[int],
        approver_id: str,
        source: str,
    ) -> None:
        with self.lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO approval_cache
                    (invoice_no, invoice_key, tenant_id, owner_id, invoice_id, approver_id, approved, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    invoice_no,
                    canonical_invoice_no(invoice_no),
                    tenant_id,
                    owner_id,
                    invoice_id,
                    approver_id,
                    source,
                    time.time(),
                ),
            )

    def approve_invoice(
        self,
        invoice_id: int,
        reviewer_tenant_id: str,
        reviewer_id: str,
    ) -> tuple[Optional[dict[str, Any]], str]:
        with self.lock, self.conn:
            row = self.conn.execute(
                """
                SELECT id, tenant_id, owner_id, invoice_no, invoice_key, amount, payee_account,
                       ocr_text, status, internal_note, created_at
                FROM invoices
                WHERE id = ? AND tenant_id = ?
                """,
                (invoice_id, reviewer_tenant_id),
            ).fetchone()
            if row is None:
                return None, "not_found"

            invoice = dict(row)
            status = str(invoice["status"])
            if status == "paid":
                return invoice, "already_paid"
            if status in ("approved", "payment_pending_confirm"):
                return invoice, "already_approved"

            self.conn.execute("UPDATE invoices SET status = 'approved' WHERE id = ?", (invoice_id,))
            self.conn.execute(
                """
                INSERT INTO approval_cache
                    (invoice_no, invoice_key, tenant_id, owner_id, invoice_id, approver_id, approved, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, 'finance-review', ?)
                """,
                (
                    invoice["invoice_no"],
                    invoice["invoice_key"],
                    invoice["tenant_id"],
                    invoice["owner_id"],
                    invoice["id"],
                    reviewer_id,
                    time.time(),
                ),
            )
            approved = self.conn.execute(
                """
                SELECT id, tenant_id, owner_id, invoice_no, invoice_key, amount, payee_account,
                       ocr_text, status, internal_note, created_at
                FROM invoices
                WHERE id = ?
                """,
                (invoice_id,),
            ).fetchone()
        return dict(approved) if approved else None, "approved"

    def get_approval(
        self,
        invoice_no: str,
        tenant_id: str,
        owner_id: str,
        invoice_id: int,
    ) -> Optional[dict[str, Any]]:
        invoice_key = canonical_invoice_no(invoice_no)
        with self.lock:
            # Cache lookup uses the normalized invoice_key. An OCR-origin entry cannot approve the same invoice that created it.
            row = self.conn.execute(
                """
                SELECT * FROM approval_cache
                WHERE invoice_key = ? AND approved = 1
                  AND NOT (source = 'ocr' AND invoice_id = ?)
                ORDER BY id DESC LIMIT 1
                """,
                (invoice_key, invoice_id),
            ).fetchone()
        return dict(row) if row else None

    def get_settlement_note(
        self,
        invoice_no: str,
        tenant_id: str,
        owner_id: str,
        invoice_id: int,
    ) -> str:
        with self.lock:
            # FIXED(AWDP22): the settlement note is bound to the same invoice and tenant.
            row = self.conn.execute(
                """
                SELECT internal_note FROM invoices
                WHERE id = ? AND tenant_id = ?
                """,
                (invoice_id, tenant_id),
            ).fetchone()
        return str(row["internal_note"]) if row else ""
# FIXED(AWDP22): canonical-key collisions can no longer leak internal notes.

    def get_or_create_payment_ticket(self, invoice: dict[str, Any], caller: dict[str, str]) -> str:
        with self.lock, self.conn:
            row = self.conn.execute(
                """
                SELECT ticket FROM payment_tickets
                WHERE invoice_id = ? AND tenant_id = ? AND owner_id = ? AND consumed = 0
                ORDER BY id DESC LIMIT 1
                """,
                (invoice["id"], caller["tenant_id"], caller["user_id"]),
            ).fetchone()
            if row is not None:
                ticket = str(row["ticket"])
            else:
                seed = "|".join(
                    [
                        str(invoice["id"]),
                        str(invoice["invoice_key"]),
                        str(caller["tenant_id"]),
                        str(caller["user_id"]),
                        str(time.time_ns()),
                        FLAG,
                    ]
                )
                ticket = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]
                self.conn.execute(
                    """
                    INSERT INTO payment_tickets
                        (invoice_id, tenant_id, owner_id, ticket, consumed, created_at)
                    VALUES (?, ?, ?, ?, 0, ?)
                    """,
                    (
                        invoice["id"],
                        caller["tenant_id"],
                        caller["user_id"],
                        ticket,
                        time.time(),
                    ),
                )
            self.conn.execute(
                "UPDATE invoices SET status = 'payment_pending_confirm' WHERE id = ? AND status <> 'paid'",
                (invoice["id"],),
            )
        return ticket

    def get_payment_ticket(
        self,
        ticket: str,
        tenant_id: str,
        owner_id: str,
    ) -> Optional[dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                """
                SELECT id, invoice_id, tenant_id, owner_id, ticket, consumed, created_at
                FROM payment_tickets
                WHERE ticket = ? AND tenant_id = ? AND owner_id = ? AND consumed = 0
                ORDER BY id DESC LIMIT 1
                """,
                (ticket, tenant_id, owner_id),
            ).fetchone()
        return dict(row) if row else None

    def consume_payment_ticket(self, ticket_id: int) -> None:
        with self.lock, self.conn:
            self.conn.execute("UPDATE payment_tickets SET consumed = 1 WHERE id = ?", (ticket_id,))

    def record_payment(
        self,
        invoice: dict[str, Any],
        settlement_note: str,
    ) -> int:
        with self.lock, self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO payments
                    (invoice_id, invoice_no, tenant_id, owner_id, amount,
                     payee_account, settlement_note, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    invoice["id"],
                    invoice["invoice_no"],
                    invoice["tenant_id"],
                    invoice["owner_id"],
                    invoice["amount"],
                    invoice["payee_account"],
                    settlement_note,
                    time.time(),
                ),
            )
            self.conn.execute("UPDATE invoices SET status = 'paid' WHERE id = ?", (invoice["id"],))
            return int(cur.lastrowid)


class PaymentTool:
    def __init__(self, store: Store) -> None:
        self.store = store

    def _check_payable(self, invoice: dict[str, Any], caller: dict[str, str]) -> dict[str, Any]:
        if str(invoice["status"]) == "paid":
            return {"ok": False, "error": "already_paid"}

        approval = self.store.get_approval(
            invoice["invoice_no"], caller["tenant_id"], caller["user_id"], invoice["id"]
        )
        if approval is None:
            return {"ok": False, "error": "manual_approval_required"}
        return {"ok": True}

    def preview(self, invoice: dict[str, Any], caller: dict[str, str]) -> dict[str, Any]:
        readiness = self._check_payable(invoice, caller)
        if not readiness["ok"]:
            return readiness

        payment_ticket = self.store.get_or_create_payment_ticket(invoice, caller)
        return {
            "ok": True,
            "tool": "payment.preview",
            "payment_ticket": payment_ticket,
            "preview": {
                "invoice_id": invoice["id"],
                "invoice_no": invoice["invoice_no"],
                "amount": invoice["amount"],
                "payee_account": invoice["payee_account"],
            },
        }

    def confirm(self, caller: dict[str, str], payment_ticket: str) -> dict[str, Any]:
        ticket_row = self.store.get_payment_ticket(
            payment_ticket, caller["tenant_id"], caller["user_id"]
        )
        if ticket_row is None:
            return {"ok": False, "error": "invalid_payment_ticket"}

        invoice = self.store.get_invoice(int(ticket_row["invoice_id"]), caller["tenant_id"])
        if invoice is None:
            return {"ok": False, "error": "invalid_payment_ticket"}

        readiness = self._check_payable(invoice, caller)
        if not readiness["ok"]:
            return readiness

        settlement_note = self.store.get_settlement_note(
            invoice["invoice_no"], caller["tenant_id"], caller["user_id"], invoice["id"]
        )
        payment_id = self.store.record_payment(invoice, settlement_note)
        self.store.consume_payment_ticket(int(ticket_row["id"]))
        return {
            "ok": True,
            "tool": "payment.create",
            "payment_ticket": payment_ticket,
            "payment_id": payment_id,
            "receipt": {
                "invoice_no": invoice["invoice_no"],
                "amount": invoice["amount"],
                "payee_account": invoice["payee_account"],
                "settlement_note": settlement_note,
            },
        }


class FinanceAgent:
    APPROVAL_RE = re.compile(
        r"approval\.cache_set\(\s*invoice_no\s*=\s*([A-Za-z0-9_\-/ ]{1,64})\s*,\s*approved\s*=\s*true\s*\)",
        re.IGNORECASE,
    )
    CONFIRM_RE = re.compile(
        r"(?:confirm(?:[\s_-]*payment)?|CONFIRM_PAYMENT)\s*[:#]?\s*([A-Fa-f0-9]{16,64})",
        re.IGNORECASE,
    )

    def __init__(self, store: Store) -> None:
        self.store = store
        self.payment = PaymentTool(store)

    def _payment_failure_reply(
        self,
        invoice: dict[str, Any],
        actions: list[dict[str, Any]],
        result: dict[str, Any],
    ) -> dict[str, Any]:
        if result["error"] == "payee_account_mismatch":
            return {
                "ok": False,
                "error": "payee_account_mismatch",
                "reply": "Payment validation failed: payee account does not match the current claimant registered account.",
                "invoice": {
                    "id": invoice["id"],
                    "invoice_no": invoice["invoice_no"],
                    "status": invoice["status"],
                },
                "tool_calls": actions,
            }
        if result["error"] == "already_paid":
            return {
                "ok": True,
                "reply": "The latest invoice has already been paid. No duplicate submission is needed.",
                "invoice": {
                    "id": invoice["id"],
                    "invoice_no": invoice["invoice_no"],
                    "status": "paid",
                },
                "tool_calls": actions,
            }
        return {
            "ok": True,
            "reply": "OCR pre-review completed. The invoice is waiting for manual approval.",
            "invoice": {
                "id": invoice["id"],
                "invoice_no": invoice["invoice_no"],
                "status": invoice["status"],
            },
            "tool_calls": actions,
        }

    def process_latest(self, caller: dict[str, str]) -> dict[str, Any]:
        invoice = self.store.latest_invoice(caller["tenant_id"], caller["user_id"])
        if invoice is None:
            return {"ok": True, "reply": "There is no pending invoice to process.", "tool_calls": []}
        if str(invoice["status"]) == "paid":
            return {
                "ok": True,
                "reply": "The latest invoice has already been paid. No duplicate submission is needed.",
                "invoice": {
                    "id": invoice["id"],
                    "invoice_no": invoice["invoice_no"],
                    "status": invoice["status"],
                },
                "tool_calls": [],
            }

        directive = self.APPROVAL_RE.search(invoice["ocr_text"])
        actions: list[dict[str, Any]] = []
        if directive:
            target_no = directive.group(1).strip()
            # Parsed OCR markers can write approval cache entries.
            self.store.set_approval_cache(
                target_no,
                caller["tenant_id"],
                caller["user_id"],
                invoice["id"],
                caller["user_id"],
                "ocr",
            )
            actions.append(
                {
                    "name": "approval.cache_set",
                    "args": {
                        "invoice_no": target_no,
                        "invoice_key": canonical_invoice_no(target_no),
                        "approved": True,
                    },
                }
            )

        preview = self.payment.preview(invoice, caller)
        if not preview["ok"]:
            return self._payment_failure_reply(invoice, actions, preview)

        actions.append(
            {
                "name": "payment.preview",
                "args": {
                    "invoice_id": invoice["id"],
                    "invoice_no": invoice["invoice_no"],
                    "payment_ticket": preview["payment_ticket"],
                },
            }
        )
        return {
            "ok": True,
            "reply": (
                "Payment preview generated. Confirmation code: "
                + str(preview["payment_ticket"])
                + '. Please send "confirm payment '
                + str(preview["payment_ticket"])
                + '" to complete the submission.'
            ),
            "invoice": {
                "id": invoice["id"],
                "invoice_no": invoice["invoice_no"],
                "status": "payment_pending_confirm",
            },
            "payment_ticket": preview["payment_ticket"],
            "tool_calls": actions,
        }

    def confirm_payment(self, caller: dict[str, str], payment_ticket: str) -> dict[str, Any]:
        payment = self.payment.confirm(caller, payment_ticket)
        if not payment["ok"]:
            error = str(payment["error"])
            reply_map = {
                "invalid_payment_ticket": "Payment confirmation code is invalid or expired.",
                "manual_approval_required": "The current invoice has not passed manual approval.",
                "payee_account_mismatch": "Payment validation failed: payee account does not match the current claimant registered account.",
                "already_paid": "This invoice has already been paid. No duplicate confirmation is needed.",
            }
            return {
                "ok": False,
                "error": error,
                "reply": reply_map.get(error, "Payment confirmation failed."),
                "tool_calls": [],
            }

        return {
            "ok": True,
            "reply": (
                "Payment submitted. Payee account: "
                + str(payment["receipt"]["payee_account"])
                + ". Settlement note: "
                + str(payment["receipt"]["settlement_note"])
            ),
            "invoice": {
                "invoice_no": payment["receipt"]["invoice_no"],
                "status": "paid",
            },
            "payment_ticket": payment["payment_ticket"],
            "tool_calls": [
                {
                    "name": "payment.create",
                    "args": {
                        "payment_ticket": payment["payment_ticket"],
                        "invoice_no": payment["receipt"]["invoice_no"],
                    },
                }
            ],
        }

    def chat(self, caller: dict[str, str], message: str) -> dict[str, Any]:
        confirm_match = self.CONFIRM_RE.search(message)
        if confirm_match:
            return self.confirm_payment(caller, confirm_match.group(1))
        if any(word in message.lower() for word in ("process", "submit", "invoice", "payment", "pay", "review")):
            return self.process_latest(caller)
        return {
            "ok": True,
            "reply": "I can help upload invoices, run OCR pre-review, submit manual review, and execute payment after a confirmation code is generated.",
            "tool_calls": [],
        }


STORE = Store(DB_PATH)
AGENT = FinanceAgent(STORE)


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
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
    server_version = "StarlingFinance/1.0"

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
            "payee_account": str(actor.get("payee_account", "")),
        }

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in ("/health", "/api/host/check"):
            json_response(self, 200, health_payload(STORE))
            return

        try:
            actor = self.require_actor()
        except PermissionError as exc:
            json_response(self, 401, {"ok": False, "error": str(exc)})
            return

        if parsed.path == "/api/invoices/mine":
            json_response(
                self,
                200,
                {"ok": True, "invoices": STORE.list_my_invoices(actor["tenant_id"], actor["user_id"])},
            )
            return

        if parsed.path == "/api/review/todos":
            if actor["role"] != "finance-reviewer":
                json_response(self, 403, {"ok": False, "error": "reviewer_role_required"})
                return
            json_response(
                self,
                200,
                {"ok": True, "todos": STORE.list_review_todos(actor["tenant_id"])},
            )
            return

        if parsed.path == "/api/review/archive":
            if actor["role"] != "finance-reviewer":
                json_response(self, 403, {"ok": False, "error": "reviewer_role_required"})
                return
            invoice = STORE.get_invoice(3001)
            if invoice is None:
                json_response(self, 404, {"ok": False, "error": "finance_archive_missing"})
                return
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "invoice_id": int(invoice["id"]),
                    "invoice_no": invoice["invoice_no"],
                    "note": str(invoice.get("internal_note") or ""),
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

        if parsed.path == "/api/host/check":
            json_response(self, 200, health_payload(STORE))
            return

        if parsed.path == "/api/login":
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))
            actor = USERS.get(username)
            if actor is None or not password or actor["password"] != password:
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

        if parsed.path == "/api/invoices":
            invoice_no = str(data.get("invoice_no", "")).strip()
            payee_account = str(data.get("payee_account", "")).strip()
            ocr_text = str(data.get("ocr_text", "")).strip()
            try:
                amount = float(data.get("amount", 0))
            except (TypeError, ValueError):
                amount = 0.0
            if not invoice_no or not payee_account or not ocr_text or amount <= 0:
                json_response(self, 400, {"ok": False, "error": "invoice_fields_required"})
                return
            if len(invoice_no) > 64 or len(payee_account) > 160 or len(ocr_text) > 50000:
                json_response(self, 400, {"ok": False, "error": "invoice_too_large"})
                return
            invoice_id = STORE.create_invoice(
                actor["tenant_id"], actor["user_id"], invoice_no, amount, payee_account, ocr_text
            )
            json_response(
                self,
                201,
                {
                    "ok": True,
                    "invoice": {
                        "id": invoice_id,
                        "invoice_no": invoice_no,
                        "invoice_key": canonical_invoice_no(invoice_no),
                        "amount": amount,
                        "status": "pending_review",
                    },
                },
            )
            return

        if parsed.path == "/api/chat":
            message = str(data.get("message", "")).strip()
            if not message:
                json_response(self, 400, {"ok": False, "error": "message_required"})
                return
            json_response(self, 200, AGENT.chat(actor, message))
            return

        if parsed.path == "/api/review/approve":
            if actor["role"] != "finance-reviewer":
                json_response(self, 403, {"ok": False, "error": "reviewer_role_required"})
                return
            try:
                invoice_id = int(data.get("invoice_id", 0))
            except (TypeError, ValueError):
                invoice_id = 0
            if invoice_id <= 0:
                json_response(self, 400, {"ok": False, "error": "invoice_id_required"})
                return
            invoice, result = STORE.approve_invoice(
                invoice_id,
                actor["tenant_id"],
                actor["user_id"],
            )
            if invoice is None:
                json_response(self, 404, {"ok": False, "error": "invoice_not_found"})
                return
            status_map = {
                "approved": 200,
                "already_approved": 200,
                "already_paid": 409,
            }
            json_response(
                self,
                status_map.get(result, 200),
                {
                    "ok": result != "already_paid",
                    "review": {
                        "result": result,
                        "approved_by": actor["user_id"],
                        "invoice_id": invoice["id"],
                        "invoice_no": invoice["invoice_no"],
                        "invoice_key": invoice["invoice_key"],
                        "owner_id": invoice["owner_id"],
                        "status": (
                            "approved"
                            if result != "already_paid" and invoice["status"] != "payment_pending_confirm"
                            else invoice["status"]
                        ),
                    },
                },
            )
            return

        json_response(self, 404, {"ok": False, "error": "not_found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[starling-finance] listen on {HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
