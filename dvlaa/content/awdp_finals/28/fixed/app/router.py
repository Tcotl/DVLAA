from __future__ import annotations

import hmac
import importlib
import inspect
from typing import Any

from fastapi import HTTPException

from app import tool_catalog
from app.config import Settings
from app.schemas import ToolCall
from app.tool_catalog import BaseTool, ToolServices


class ToolRouter:
    def __init__(self, services: ToolServices, settings: Settings):
        self.services = services
        self.settings = settings

    def dispatch_http(self, call: ToolCall, supplied_key: str | None) -> dict[str, Any]:
        return self._dispatch(call, supplied_key)

    def dispatch_agent(
        self, call: ToolCall, *, subject: str, trace_id: str
    ) -> dict[str, Any]:
        internal = call.model_copy(
            update={"context": {"actor": "agent-planner", "subject": subject}, "trace_id": trace_id}
        )
        return self._dispatch(internal, self.settings.executor_key)

    def _dispatch(self, call: ToolCall, supplied_key: str | None) -> dict[str, Any]:
        if supplied_key is not None and not hmac.compare_digest(
            supplied_key, self.settings.executor_key
        ):
            raise HTTPException(status_code=401, detail="invalid executor key")

        tool_class = getattr(tool_catalog, call.tool, None)
        if inspect.isclass(tool_class) and issubclass(tool_class, BaseTool) and tool_class is not BaseTool:
            try:
                result = tool_class(self.services).run(context=call.context, **call.arguments)
            except TypeError as exc:
                raise HTTPException(status_code=422, detail=f"invalid tool arguments: {exc}") from exc
        else:
            # FIXED(AWDP28): arbitrary python callables are never resolved or executed.
            raise HTTPException(status_code=404, detail="tool not found")
        self.services.db.audit(
            "tool.dispatched",
            str(call.context.get("actor", "anonymous")),
            {"tool": call.tool, "trace_id": call.trace_id},
        )
        return {"ok": True, "tool": call.tool, "result": result}

    # FIXED(AWDP28): the legacy module-path resolver was removed; the registry is the only dispatch target.
