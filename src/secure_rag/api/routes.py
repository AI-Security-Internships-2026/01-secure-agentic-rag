from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from secure_rag.agent.graph import query_rag_system
from secure_rag.api.auth import Principal, create_token, get_chat_principal, get_principal
from secure_rag.api.schemas import ChatRequest, IngestRequest, QueryRequest, TokenRequest
from secure_rag.authz.client import AuthorizationError, get_authz_client
from secure_rag.retrieval.ingest import ingest_texts
from secure_rag.retrieval.qdrant_store import get_vector_store
from secure_rag.settings import get_settings

router = APIRouter()


@router.post("/token")
def issue_token(body: TokenRequest):
    settings = get_settings()
    if settings.app_env == "production":
        raise HTTPException(status_code=403, detail="token minting disabled in production; use your IdP")
    return {"access_token": create_token(body.user_id, body.tenant_id, body.roles), "token_type": "bearer"}


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/ready")
def ready():
    settings = get_settings()
    checks = {"qdrant": False, "spicedb": False}
    try:
        get_vector_store(settings).count()
        checks["qdrant"] = True
    except Exception:
        pass
    try:
        get_authz_client(settings)
        checks["spicedb"] = True
    except Exception:
        pass
    ok = all(checks.values()) or settings.app_env == "test"
    return {"ready": ok, "checks": checks}


@router.post("/query")
def query(body: QueryRequest, principal: Principal = Depends(get_principal)):
    result = query_rag_system(
        collection_name=body.document_id,
        query=body.query,
        n_results=body.n_results,
        user_id=principal.user_id,
        filtering_mode=body.filtering_mode,
        enable_indirect_injection_scan=body.enable_indirect_injection_scan,
        enable_context_isolation=body.enable_context_isolation,
        tenant_id=principal.tenant_id,
    )
    return result


def _compose_chat_query(message: str, history: list) -> str:
    if not history:
        return message
    lines = [f"{turn.role}: {turn.content}" for turn in history]
    return "Conversation so far:\n" + "\n".join(lines) + f"\nuser: {message}"


@router.post("/chat")
def chat(body: ChatRequest, principal: Principal = Depends(get_chat_principal)):
    """Website/CLI chatbot endpoint. Guardrails and ReBAC stay on the server."""
    result = query_rag_system(
        collection_name=body.document_id,
        query=_compose_chat_query(body.message, body.history),
        n_results=body.n_results,
        user_id=principal.user_id,
        filtering_mode=body.filtering_mode,
        tenant_id=principal.tenant_id,
    )
    diagnostics = result.get("diagnostics") or {}
    citations: list[str] = []
    for item in result.get("retrieved") or []:
        doc_id = str(item.get("document_id") or "")
        if doc_id and doc_id not in citations:
            citations.append(doc_id)
    include_diag = get_settings().app_env != "production" or "widget" not in principal.roles
    return {
        "reply": result.get("answer", ""),
        "blocked": bool(diagnostics.get("error")),
        "citations": citations,
        "diagnostics": diagnostics if include_diag else None,
    }


@router.get("/widget/config")
def widget_config():
    settings = get_settings()
    return {
        "enabled": settings.widget_enabled and bool(settings.widget_site_key),
        "title": settings.widget_title,
        "welcome": settings.widget_welcome,
    }


@router.post("/ingest")
def ingest(body: IngestRequest, principal: Principal = Depends(get_principal)):
    try:
        return ingest_texts(
            body.document_id,
            body.texts,
            owner_id=principal.user_id,
            tenant_id=principal.tenant_id,
            viewers=body.viewers,
            redact_pii=body.redact_pii,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=503, detail=str(exc) or "authorization or dependency unavailable") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}") from exc


@router.get("/permissions")
def permissions(principal: Principal = Depends(get_principal)):
    docs = get_authz_client().lookup_resources("document", "view", "user", principal.user_id)
    return {"user_id": principal.user_id, "tenant_id": principal.tenant_id, "documents": docs}
