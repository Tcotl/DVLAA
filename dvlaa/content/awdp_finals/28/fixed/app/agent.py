from __future__ import annotations

import re
import uuid
from typing import Any

from fastapi import HTTPException

from app.router import ToolRouter
from app.schemas import ToolCall


class AgentService:
    """A deterministic planner keeps the CTF self-contained and reproducible."""

    CREATE_PATTERN = re.compile(
        r"^create\s+recovery\s+([a-zA-Z0-9._-]+)(?:\s*\|\s*(.+))?$", re.I
    )
    ID_PATTERN = re.compile(r"^rec-[0-9a-f]{12}$")

    def __init__(self, router: ToolRouter):
        self.router = router

    def run(self, subject: str, message: str) -> dict[str, Any]:
        trace_id = f"trace-{uuid.uuid4().hex[:12]}"
        normalized = message.strip()
        plan: list[str]
        tool: str
        arguments: dict[str, Any]

        create = self.CREATE_PATTERN.match(normalized)
        if create:
            service, reason = create.groups()
            plan = ["validate service name", "create recovery request", "wait for approval"]
            tool = "CreateRecoveryRequestTool"
            arguments = {
                "service": service,
                "reason": reason or "operator requested recovery through the agent",
            }
        elif normalized.lower().startswith("status "):
            request_id = normalized.split(maxsplit=1)[1]
            self._validate_request_id(request_id)
            plan = ["identify request", "retrieve current workflow state"]
            tool = "GetRequestStatusTool"
            arguments = {"request_id": request_id}
        elif normalized.lower().startswith("recover "):
            request_id = normalized.split(maxsplit=1)[1]
            self._validate_request_id(request_id)
            plan = ["identify request", "verify approval", "execute recovery"]
            tool = "RecoveryCommitTool"
            arguments = {"request_id": request_id}
        elif normalized.lower().startswith("remember "):
            content = normalized.split(maxsplit=1)[1]
            plan = ["scope memory to current user", "store note"]
            tool = "SaveUserMemoryTool"
            arguments = {"content": content}
        elif normalized.lower() == "recall":
            plan = ["scope memory to current user", "retrieve recent notes"]
            tool = "RecallUserMemoryTool"
            arguments = {}
        elif normalized.lower().startswith("search "):
            query = normalized.split(maxsplit=1)[1]
            plan = ["search operational knowledge", "return relevant guidance"]
            tool = "SearchKnowledgeTool"
            arguments = {"query": query}
        else:
            return {
                "trace_id": trace_id,
                "decision": "ask_for_clarification",
                "supported_commands": [
                    "create recovery <service> | <reason>",
                    "status <request_id>",
                    "recover <request_id>",
                    "remember <text>",
                    "recall",
                    "search <query>",
                ],
            }

        call = ToolCall(tool=tool, arguments=arguments, trace_id=trace_id)
        result = self.router.dispatch_agent(call, subject=subject, trace_id=trace_id)
        return {
            "trace_id": trace_id,
            "decision": "execute_tool",
            "plan": plan,
            "tool_call": {"tool": tool, "arguments": arguments},
            "tool_result": result["result"],
        }

    def _validate_request_id(self, request_id: str) -> None:
        if not self.ID_PATTERN.fullmatch(request_id):
            raise HTTPException(status_code=422, detail="invalid recovery request id")

