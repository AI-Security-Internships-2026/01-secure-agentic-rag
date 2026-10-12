"""Browser playground for AuthInject-RAG: upload files live and query them with every defense switchable.

    ./run.sh ui              # offline, http://127.0.0.1:8501
    ./run.sh ui --services   # against SpiceDB and Qdrant from docker compose

It exposes research modes (post, none) and admin actions, so it refuses to start with APP_ENV=production.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from secure_rag.api.auth import Principal, create_token, get_principal
from secure_rag.authz.client import AuthorizationError, OverwriteDeniedError
from secure_rag.playground import workspace
from secure_rag.playground.workspace import PlaygroundError
from secure_rag.settings import get_settings

STATIC = Path(__file__).parent / "static"
NAME = r"^[A-Za-z0-9_.@-]{1,64}$"
CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


class SessionRequest(BaseModel):
    user_id: str = Field(pattern=NAME)
    tenant_id: str = Field(pattern=NAME)


class UploadRequest(BaseModel):
    filename: str = Field(default="", max_length=200)
    content_base64: str = ""
    text: str = Field(default="", max_length=200_000)
    document_id: str = Field(default="", pattern=r"^[A-Za-z0-9_.-]{0,80}$")
    viewers: list[str] = Field(default_factory=list)
    redact_pii: bool = True


class ViewerRequest(BaseModel):
    user_id: str = Field(pattern=NAME)


class ToolRequest(BaseModel):
    allowed: bool


class Memory(BaseModel):
    contexts: list[str] = Field(default_factory=list)
    retrieved: list[dict[str, Any]] = Field(default_factory=list)


class QueryRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    document_id: str = ""
    mode: Literal["pre", "post", "none"] = "pre"
    scan: bool = True
    isolation: bool = True
    datamarking: bool = True
    tool_guard: bool = True
    continuous_auth: bool = True
    generator: Literal["extractive", "llm"] = "extractive"
    memory: Memory | None = None


class OutageRequest(BaseModel):
    down: bool


def create_app() -> FastAPI:
    if get_settings().app_env == "production":
        raise SystemExit(
            "The playground exposes research modes and admin actions; it never runs with APP_ENV=production."
        )
    app = FastAPI(title="AuthInject-RAG playground")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.exception_handler(PlaygroundError)
    async def playground_error(request: Request, exc: PlaygroundError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content={"detail": exc.detail})

    @app.exception_handler(OverwriteDeniedError)
    async def overwrite_denied(request: Request, exc: OverwriteDeniedError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(AuthorizationError)
    async def authz_unavailable(request: Request, exc: AuthorizationError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(exc) or "authorization unavailable"})

    @app.exception_handler(ValueError)
    async def bad_input(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/state")
    def read_state() -> dict:
        return workspace.state()

    @app.post("/api/session")
    def session(body: SessionRequest) -> dict:
        return {
            "token": create_token(body.user_id, body.tenant_id),
            "user_id": body.user_id,
            "tenant_id": body.tenant_id,
        }

    @app.get("/api/documents")
    def documents(principal: CurrentPrincipal) -> list[dict]:
        return workspace.list_documents(principal.user_id, principal.tenant_id)

    @app.post("/api/documents")
    def upload(body: UploadRequest, principal: CurrentPrincipal) -> dict:
        return workspace.upload(principal.user_id, principal.tenant_id, body)

    @app.post("/api/documents/{document_id}/viewers")
    def share(document_id: str, body: ViewerRequest, principal: CurrentPrincipal) -> dict:
        return workspace.share(principal.user_id, principal.tenant_id, document_id, body.user_id)

    @app.delete("/api/documents/{document_id}/viewers/{user_id}")
    def revoke(document_id: str, user_id: str, principal: CurrentPrincipal) -> dict:
        return workspace.revoke(principal.user_id, principal.tenant_id, document_id, user_id)

    @app.delete("/api/documents/{document_id}")
    def delete(document_id: str, principal: CurrentPrincipal) -> dict:
        workspace.delete_document(principal.user_id, principal.tenant_id, document_id)

        return {"deleted": document_id}

    @app.get("/api/tools")
    def tools(principal: CurrentPrincipal) -> dict[str, bool]:
        return workspace.tool_permissions(principal.user_id)

    @app.put("/api/tools/{tool}")
    def set_tool(tool: str, body: ToolRequest, principal: CurrentPrincipal) -> dict[str, bool]:
        return workspace.set_tool_permission(principal.user_id, principal.tenant_id, tool, body.allowed)

    @app.post("/api/query")
    def query(body: QueryRequest, principal: CurrentPrincipal) -> dict:
        return workspace.run_query(principal.user_id, principal.tenant_id, body)

    @app.post("/api/compare")
    def compare(body: QueryRequest, principal: CurrentPrincipal) -> list[dict]:
        return workspace.compare_modes(principal.user_id, principal.tenant_id, body)

    @app.put("/api/outage")
    def outage(body: OutageRequest) -> dict:
        return {"outage": workspace.set_outage(body.down)}

    @app.get("/api/audit")
    def audit(since: int = 0) -> dict:
        return workspace.audit_events(max(0, since))

    @app.get("/api/audit/verify")
    def verify() -> dict:
        return workspace.verify_audit()

    @app.post("/api/reset")
    def reset() -> dict:
        workspace.reset()

        return workspace.state()

    return app


app = create_app()
