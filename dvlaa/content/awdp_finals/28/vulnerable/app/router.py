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
            callable_object = self._resolve_python_callable(call.tool)
            if callable_object is None:
                raise HTTPException(status_code=404, detail="tool not found")
            arguments = dict(call.arguments)
            request_id = arguments.pop("request_id", None)
            if not isinstance(request_id, str):
                raise HTTPException(status_code=422, detail="request_id is required")
            if self.services.db.get_recovery(request_id) is None:
                raise HTTPException(status_code=404, detail="recovery request not found")
            positional = arguments.pop("args", [])
            if not isinstance(positional, list):
                raise HTTPException(status_code=422, detail="args must be a list")
            try:
                result = callable_object(*positional, **arguments)
            except TypeError as exc:
                raise HTTPException(status_code=422, detail=f"invalid callable arguments: {exc}") from exc
            if not isinstance(result, dict):
                result = {"value": result}
        self.services.db.audit(
            "tool.dispatched",
            str(call.context.get("actor", "anonymous")),
            {"tool": call.tool, "trace_id": call.trace_id},
        )
        return {"ok": True, "tool": call.tool, "result": result}

    def _resolve_python_callable(self, name: str) -> Any | None:
        if "." not in name:
            return None
        module_name, attribute = name.rsplit(".", 1)
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            return None
        candidate = getattr(module, attribute, None)
        return candidate if callable(candidate) else None
