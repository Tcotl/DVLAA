from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException

from app.config import Settings
from app.database import Database


@dataclass(slots=True)
class ToolServices:
    db: Database
    settings: Settings


class BaseTool:
    """Base class for tools that can be invoked by the agent runtime."""

    def __init__(self, services: ToolServices):
        self.services = services

    def run(self, *, context: dict[str, Any], **arguments: Any) -> dict[str, Any]:
        raise NotImplementedError


class CreateRecoveryRequestTool(BaseTool):
    def run(
        self, *, service: str, reason: str, context: dict[str, Any]
    ) -> dict[str, Any]:
        subject = str(context.get("subject", "anonymous"))
        request = self.services.db.create_recovery(subject, service, reason)
        return {"request": request, "next_step": "wait for an administrator approval"}


class GetRequestStatusTool(BaseTool):
    def run(self, *, request_id: str, context: dict[str, Any]) -> dict[str, Any]:
        request = self.services.db.get_recovery(request_id)
        if request is None:
            raise HTTPException(status_code=404, detail="recovery request not found")
        subject = str(context.get("subject", ""))
        if context.get("actor") == "agent-planner" and request["owner"] != subject:
            raise HTTPException(status_code=403, detail="request belongs to another user")
        return {"request": request}


class SearchKnowledgeTool(BaseTool):
    ARTICLES = {
        "recovery": "Recovery requires a pending request and an administrator approval.",
        "memory": "Agent memory stores user-scoped operational notes.",
        "incident": "Critical incidents are handled through the recovery workflow.",
    }

    def run(self, *, query: str, context: dict[str, Any]) -> dict[str, Any]:
        normalized = query.lower()
        hits = [
            {"title": title, "content": content}
            for title, content in self.ARTICLES.items()
            if normalized in title or normalized in content.lower()
        ]
        return {"hits": hits[:5]}


class SaveUserMemoryTool(BaseTool):
    def run(self, *, content: str, context: dict[str, Any]) -> dict[str, Any]:
        subject = str(context.get("subject", "anonymous"))
        memory = self.services.db.write_memory(
            namespace=f"user:{subject}",
            memory_key=f"note:{uuid.uuid4().hex[:8]}",
            content=content,
            actor=f"user:{subject}",
        )
        return {"memory": memory}


class RecallUserMemoryTool(BaseTool):
    def run(self, *, context: dict[str, Any]) -> dict[str, Any]:
        subject = str(context.get("subject", "anonymous"))
        return {"memories": self.services.db.list_memories(f"user:{subject}")}


class RecoveryCommitTool(BaseTool):
    """Privileged business tool used by the agent after an approval."""

    def run(self, *, request_id: str, context: dict[str, Any]) -> dict[str, Any]:
        request = self.services.db.get_recovery(request_id)
        if request is None:
            raise HTTPException(status_code=404, detail="recovery request not found")
        subject = str(context.get("subject", ""))
        if context.get("actor") == "agent-planner" and request["owner"] != subject:
            raise HTTPException(status_code=403, detail="request belongs to another user")
        if request["state"] == "COMPLETED":
            raise HTTPException(status_code=409, detail="recovery already completed")

        approved = self.services.db.has_authoritative_approval(request_id)
        decision_source = "approval-database"

        if not approved:
            raise HTTPException(status_code=403, detail="recovery has no valid approval")

        self.services.db.complete_recovery(request_id)
        self.services.db.audit(
            "recovery.completed",
            str(context.get("actor", "unknown")),
            {"request_id": request_id, "decision_source": decision_source},
        )
        return {
            "completed": True,
            "request_id": request_id,
            "decision_source": decision_source,
        }
