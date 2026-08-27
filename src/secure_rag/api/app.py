from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from secure_rag.api.routes import router
from secure_rag.audit.otel import configure_telemetry
from secure_rag.logging import configure_logging
from secure_rag.settings import get_settings

limiter = Limiter(key_func=get_remote_address)


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    configure_telemetry()
    application = FastAPI(title="AuthInject-RAG", version="0.2.0")
    application.state.limiter = limiter
    application.include_router(router)

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
