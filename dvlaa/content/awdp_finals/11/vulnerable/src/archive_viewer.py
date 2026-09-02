"""Contract Archive Portal entrypoint.

Loads the contract domain module and exposes the archivist operations used by
the portal: create contract files, import OCR evidence, preview attachments,
run the archive assistant, and submit archiving approvals.
"""

from __future__ import annotations

import time
import uuid

import contract_domain
from contract_domain import ARCHIVE_ASSISTANT_POLICY, DECLARED_TOOLS, RESTRICTED_ARCHIVE_BATCH


def _now() -> int:
    return int(time.time())


class ArchiveViewerService:
    title = "Contract Archive Portal"

    def __init__(self, core) -> None:
        self.core = core

    def init_db(self) -> None:
        with self.core.lock, self.core.db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS contract_files(
                    id TEXT PRIMARY KEY, tenant_id TEXT, operator_subject TEXT,
                    title TEXT, ocr TEXT, state TEXT, created_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS archive_events(
                    id TEXT PRIMARY KEY, tenant_id TEXT, contract_id TEXT,
                    actor_subject TEXT, event TEXT, detail TEXT, created_at INTEGER
                );
                """
            )
        self.core.ensure_service_account("archive_service_lead", "operator", "archive service queue")

    def post(self, path: str, user: dict, payload: dict):
        if path == "/v1/archive/contracts":
            title = str(payload.get("title", "")).strip() or "未命名合同"
            cid = "CTR-" + uuid.uuid4().hex[:12]
            with self.core.lock, self.core.db() as db:
                db.execute(
                    "INSERT INTO contract_files VALUES(?,?,?,?,?,?,?)",
                    (cid, user["tenant_id"], user["subject_id"], title, "", "draft", _now()),
                )
            return 201, {"ok": True, "contract_id": cid, "title": title}

        if path.startswith("/v1/archive/contracts/") and path.endswith("/ocr"):
            cid = path.split("/")[4]
            ocr = str(payload.get("ocrText", ""))
            with self.core.lock, self.core.db() as db:
                row = db.execute("SELECT * FROM contract_files WHERE id=? AND tenant_id=? AND operator_subject=?", (cid, user["tenant_id"], user["subject_id"])).fetchone()
                if row is None:
                    return 404, {"ok": False, "error": "contract_not_found"}
                db.execute("UPDATE contract_files SET ocr=? WHERE id=?", (ocr, cid))
                db.execute(
                    "INSERT INTO archive_events VALUES(?,?,?,?,?,?,?)",
                    ("evt-" + uuid.uuid4().hex, user["tenant_id"], cid, user["subject_id"], "ocr.imported", str(len(ocr)), _now()),
                )
            return 201, {"ok": True, "contract_id": cid, "ocr_chars": len(ocr)}

        if path.startswith("/v1/archive/contracts/") and path.endswith("/assist"):
            cid = path.split("/")[4]
            with self.core.lock, self.core.db() as db:
                row = db.execute("SELECT * FROM contract_files WHERE id=? AND tenant_id=? AND operator_subject=?", (cid, user["tenant_id"], user["subject_id"])).fetchone()
            if row is None:
                return 404, {"ok": False, "error": "contract_not_found"}
            contract = {"contract_id": cid, "title": row["title"], "ocr": row["ocr"], "state": row["state"]}
            context = contract_domain.build_assistant_context(contract)
            tool = contract_domain.plan_tool(context)
            data = contract_domain.execute_tool(tool, contract)
            return 200, {"ok": True, "policy": ARCHIVE_ASSISTANT_POLICY[:64] + "...", "tool": tool, "result": data}

        if path == "/v1/archive/approvals":
            batch = str(payload.get("batchId", "")).strip() or RESTRICTED_ARCHIVE_BATCH["batch_id"]
            if batch != RESTRICTED_ARCHIVE_BATCH["batch_id"]:
                return 404, {"ok": False, "error": "batch_not_found"}
            RESTRICTED_ARCHIVE_BATCH["state"] = "approved"
            return 200, {"ok": True, "batch_id": batch, "state": "approved"}

        return None
