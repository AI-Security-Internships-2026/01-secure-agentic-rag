from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from secure_rag.api.routes import router
from secure_rag.audit.otel import configure_telemetry
from secure_rag.logging import configure_logging
from secure_rag.settings import get_settings

limiter = Limiter(key_func=get_remote_address)
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def _cors_origins(raw: str) -> list[str]:
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    configure_telemetry()
    application = FastAPI(
        title="AuthInject-RAG",
        version="0.2.0",
        description="Authorization-first RAG chatbot you can embed on a website or drive from the CLI.",
    )
    application.state.limiter = limiter
    origins = _cors_origins(settings.cors_origins)
    if origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Site-Key", "X-Request-Id"],
        )
    application.include_router(router)

    if STATIC_DIR.is_dir():
        application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

        @application.get("/")
        def demo_console():
            return FileResponse(STATIC_DIR / "index.html")

    @application.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request_id = request.headers.get("x-request-id", str(uuid4()))
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response

    @application.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})

    return application


app = create_app()


def serve() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run("secure_rag.api.app:app", host=settings.api_host, port=settings.api_port, reload=False)
