from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.agent import AgentService
from app.config import Settings
from app.database import Database
from app.router import ToolRouter
from app.schemas import AgentRequest, RegisterRequest, ToolCall
from app.tool_catalog import ToolServices


bearer = HTTPBearer(auto_error=False)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    database = Database(settings.database_path)
    services = ToolServices(database, settings)
    router = ToolRouter(services, settings)
    agent = AgentService(router)

    app = FastAPI(
        title="Sentinel AgentOps",
        version="1.0.0",
        description="A self-contained autonomous operations agent challenge.",
    )
    app.state.settings = settings
    app.state.database = database
    app.state.router = router

    def require_user(
        credentials: Annotated[
            HTTPAuthorizationCredentials | None, Depends(bearer)
        ],
    ) -> str:
        if not credentials:
            raise HTTPException(status_code=401, detail="invalid user token")
        user = database.get_user_by_token(credentials.credentials)
        if user is None:
            raise HTTPException(status_code=401, detail="invalid user token")
        return str(user["username"])

    def require_admin(
        credentials: Annotated[
            HTTPAuthorizationCredentials | None, Depends(bearer)
        ],
    ) -> str:
        if not credentials or not hmac.compare_digest(
            credentials.credentials, settings.admin_token
        ):
            raise HTTPException(status_code=401, detail="invalid admin token")
        return "ops-manager"

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/agent/tools")
    def public_tools() -> dict[str, list[str]]:
        return {
            "tools": [
                "create_recovery_request",
                "get_request_status",
                "search_knowledge",
                "save_user_memory",
                "recall_user_memory",
            ]
        }

    @app.post("/api/v1/auth/register")
    def register(payload: RegisterRequest) -> dict[str, str]:
        try:
            user = database.create_user(payload.username)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "username": user["username"],
            "access_token": user["token"],
            "token_type": "bearer",
        }

    @app.post("/api/v1/agent/run")
    def run_agent(payload: AgentRequest, subject: str = Depends(require_user)):
        return agent.run(subject, payload.message)

    @app.post("/api/v1/internal/tools/execute")
    def execute_tool(
        call: ToolCall,
        x_agent_key: Annotated[str | None, Header(alias="X-Agent-Key")] = None,
    ):
        return router.dispatch_http(call, x_agent_key)

    @app.post("/api/v1/admin/recovery/{request_id}/approve")
    def approve_recovery(
        request_id: str, approver: str = Depends(require_admin)
    ):
        try:
            request = database.approve_recovery(request_id, approver)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if request is None:
            raise HTTPException(status_code=404, detail="recovery request not found")

        return {"approved": True, "request": request}

    return app


app = create_app()
