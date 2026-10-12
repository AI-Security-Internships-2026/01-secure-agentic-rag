from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from secure_rag.agent.graph import query_rag_system
from secure_rag.api.auth import Principal, create_token, get_principal
from secure_rag.api.schemas import IngestRequest, QueryRequest, TokenRequest
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
    settings = get_settings()
    if settings.app_env == "production" and settings.production_enforce_pre_auth:
        if body.filtering_mode == "post":
            raise HTTPException(
                status_code=403,
                detail="Post-filter mode is not permitted in production profile.",
            )
        if body.filtering_mode == "research_baseline_none":
            raise HTTPException(
                status_code=403,
                detail="Baseline-none mode is internal research-only; not available on production API.",
            )

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


@router.post("/ingest")
def ingest(body: IngestRequest, principal: Principal = Depends(get_principal)):
    settings = get_settings()
    authz = get_authz_client(settings)
    target_tenant_id = body.tenant_id if body.tenant_id else principal.tenant_id
    requested_owner_id = body.owner_id if body.owner_id else principal.user_id

    existing_owner = authz.get_document_owner(body.document_id)
    if existing_owner is not None:
        if not authz.check_permission("document", body.document_id, "edit", "user", principal.user_id):
            from secure_rag.audit.events import emit

            emit(
                "document.overwrite_attempt.denied",
                user_id=principal.user_id,
                document_id=body.document_id,
                tenant_id=target_tenant_id,
                extra={"reason": "caller is not owner/editor"},
            )
            raise HTTPException(
                status_code=403,
                detail=f"Cannot overwrite document '{body.document_id}': caller is not owner/editor.",
            )
        if principal.user_id == existing_owner:
            effective_owner = requested_owner_id
        else:
            effective_owner = existing_owner
    else:
        is_member = (principal.tenant_id == target_tenant_id) or authz.check_permission(
            "tenant", target_tenant_id, "view", "user", principal.user_id
        )
        if not is_member:
            from secure_rag.audit.events import emit

            emit(
                "document.overwrite_attempt.denied",
                user_id=principal.user_id,
                document_id=body.document_id,
                tenant_id=target_tenant_id,
                extra={"reason": "caller is not a member of target tenant"},
            )
            raise HTTPException(
                status_code=403,
                detail=f"Cannot create document: caller '{principal.user_id}' is not a member of tenant '{target_tenant_id}'.",
            )
        effective_owner = requested_owner_id

    try:
        return ingest_texts(
            body.document_id,
            body.texts,
            owner_id=effective_owner,
            tenant_id=target_tenant_id,
            viewers=body.viewers,
            redact_pii=body.redact_pii,
            caller_id=principal.user_id,
        )
    except AuthorizationError as exc:
        if "Cannot overwrite" in str(exc) or "not owner/editor" in str(exc):
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        raise HTTPException(status_code=503, detail=str(exc) or "authorization or dependency unavailable") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}") from exc


@router.get("/permissions")
def permissions(principal: Principal = Depends(get_principal)):
    docs = get_authz_client().lookup_resources("document", "view", "user", principal.user_id)
    return {"user_id": principal.user_id, "tenant_id": principal.tenant_id, "documents": docs}


@router.post("/authz/policy_changed")
def policy_changed():
    from secure_rag.agent.graph import bump_policy_version

    new_version = bump_policy_version()
    return {"status": "ok", "policy_version": new_version}
