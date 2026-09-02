from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AgentRequest(BaseModel):
    message: str = Field(min_length=1, max_length=500)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_-]+$")


class ToolCall(BaseModel):
    message_type: Literal["tool_call"] = "tool_call"
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    trace_id: str | None = Field(default=None, max_length=80)


class CreateRecoveryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: str = Field(min_length=2, max_length=80, pattern=r"^[a-zA-Z0-9._-]+$")
    reason: str = Field(min_length=3, max_length=240)


class RequestIdArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(pattern=r"^rec-[0-9a-f]{12}$")


class KnowledgeArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=100)


class UserMemoryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(min_length=1, max_length=300)


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
