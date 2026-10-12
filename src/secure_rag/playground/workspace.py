"""Operations behind the playground UI: live uploads, sharing, queries and the audit trail."""

from __future__ import annotations

import base64
import binascii
import io
import json
from pathlib import Path
from typing import Any

from secure_rag.agent import graph
from secure_rag.agent.graph import bump_policy_version, get_policy_version, query_rag_system
from secure_rag.agent.guardrails import heuristic_match
from secure_rag.agent.tools import TOOL_SCHEMAS
from secure_rag.audit.events import emit, format_tuple, hmac_secret, reset_audit_chain
from secure_rag.audit.verify import verify_files
from secure_rag.authz import client as authz_module
from secure_rag.authz.client import (
    AuthorizationError,
    authorize_or_deny,
    document_ref,
    get_authz_client,
    reset_authz_client,
)
from secure_rag.demo import UnreachableSpiceDB
from secure_rag.retrieval.ingest import _slug, ingest_texts
from secure_rag.retrieval.qdrant_store import RetrievedChunk, get_vector_store, reset_vector_store
from secure_rag.settings import get_settings

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MODES = {"pre": "pre", "post": "post", "none": "research_baseline_none"}
_saved_client: dict[str, Any] = {}


class PlaygroundError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def outage_active() -> bool:
    return isinstance(authz_module._client, UnreachableSpiceDB)


def set_outage(down: bool) -> bool:
    if down and not outage_active():
        _saved_client["client"] = get_authz_client()
        authz_module._client = UnreachableSpiceDB()
    if not down and outage_active():
        authz_module._client = _saved_client.pop("client")

    return outage_active()


def state() -> dict:
    path = audit_path_or_none()

    return {
        "mode": "offline" if get_settings().app_env == "test" else "services",
        "policy_version": get_policy_version(),
        "outage": outage_active(),
        "audit_log": str(path) if path else None,
        "tools": sorted(TOOL_SCHEMAS),
    }


def extract_texts(filename: str, content_base64: str, text: str) -> list[str]:
    if text.strip():
        return [text]
    if not content_base64:
        raise PlaygroundError(422, "Choose a file or paste some text.")
    try:
        data = base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PlaygroundError(422, "The file could not be read.") from exc
    if len(data) > MAX_UPLOAD_BYTES:
        raise PlaygroundError(413, "Files are limited to 10 MB.")
    pages = pdf_pages(data) if filename.lower().endswith(".pdf") else [data.decode("utf-8", errors="replace")]
    pages = [page for page in pages if page.strip()]
    if not pages:
        raise PlaygroundError(422, "No text found in the file. A scanned PDF needs OCR first.")

    return pages


def pdf_pages(data: bytes) -> list[str]:
    from pypdf import PdfReader

    try:
        return [page.extract_text() or "" for page in PdfReader(io.BytesIO(data)).pages]
    except Exception as exc:
        raise PlaygroundError(422, f"The PDF could not be parsed: {exc}") from exc


def chunks_of(tenant_id: str, document_id: str) -> list[RetrievedChunk]:
    found = [c for c in get_vector_store().list_chunks() if c.tenant_id == tenant_id and c.document_id == document_id]

    return sorted(found, key=lambda chunk: int(chunk.payload.get("index", 0)))


def access_of(tenant_id: str, document_id: str) -> dict:
    authz = get_authz_client()
    ref = document_ref(tenant_id, document_id)
    try:
        return {
            "owner": authz.get_document_owner(ref),
            "viewers": sorted(authz.lookup_subjects("document", ref, "viewer")),
        }
    except AuthorizationError:
        return {"owner": None, "viewers": [], "error": "SpiceDB unreachable"}


def can(user_id: str, tenant_id: str, document_id: str, permission: str) -> bool:
    ref = document_ref(tenant_id, document_id)

    return authorize_or_deny(get_authz_client(), "document", ref, permission, "user", user_id)


def upload(user_id: str, tenant_id: str, request: Any) -> dict:
    texts = extract_texts(request.filename, request.content_base64, request.text)
    document_id = request.document_id.strip() or _slug(request.filename or "pasted text")
    viewers = [viewer.strip() for viewer in request.viewers if viewer.strip()]
    result = ingest_texts(
        document_id,
        texts,
        owner_id=user_id,
        tenant_id=tenant_id,
        viewers=viewers,
        source=request.filename or "pasted text",
        redact_pii=request.redact_pii,
        caller_id=user_id,
    )
    chunks = [
        {"index": i, "text": chunk.text, "injection": heuristic_match(chunk.text)}
        for i, chunk in enumerate(chunks_of(tenant_id, document_id))
    ]

    return {
        **result,
        "tenant_id": tenant_id,
        "original": " ".join(texts)[:2000],
        "chunks": chunks,
        **access_of(tenant_id, document_id),
    }


def list_documents(user_id: str, tenant_id: str) -> list[dict]:
    grouped: dict[tuple[str, str], list[RetrievedChunk]] = {}
    for chunk in get_vector_store().list_chunks():
        grouped.setdefault((chunk.tenant_id, chunk.document_id), []).append(chunk)
    documents = []
    for (doc_tenant, doc_id), chunks in sorted(grouped.items()):
        documents.append(
            {
                "document_id": doc_id,
                "tenant_id": doc_tenant,
                "chunks": len(chunks),
                "source": str(chunks[0].payload.get("source", "")),
                "injection": any(heuristic_match(chunk.text) for chunk in chunks),
                "can_view": can(user_id, doc_tenant, doc_id, "view"),
                "can_edit": doc_tenant == tenant_id and can(user_id, doc_tenant, doc_id, "edit"),
                **access_of(doc_tenant, doc_id),
            }
        )

    return documents


def require_editor(user_id: str, tenant_id: str, document_id: str) -> str:
    if outage_active():
        raise PlaygroundError(503, "SpiceDB is unreachable, so access cannot be changed.")
    if not can(user_id, tenant_id, document_id, "edit"):
        raise PlaygroundError(
            403, f"Only the owner or an editor of '{document_id}' in tenant '{tenant_id}' can do that."
        )

    return document_ref(tenant_id, document_id)


def share(user_id: str, tenant_id: str, document_id: str, viewer: str) -> dict:
    ref = require_editor(user_id, tenant_id, document_id)
    grant = ("document", ref, "viewer", "user", viewer.strip())
    get_authz_client().write_relationships([grant])
    emit(
        "authz.spicedb_tuple.write",
        user_id=user_id,
        document_id=document_id,
        tenant_id=tenant_id,
        extra={"tuples": [format_tuple(grant)], "writer_principal": user_id},
    )

    return access_of(tenant_id, document_id)


def revoke(user_id: str, tenant_id: str, document_id: str, viewer: str) -> dict:
    ref = require_editor(user_id, tenant_id, document_id)
    grant = ("document", ref, "viewer", "user", viewer)
    get_authz_client().delete_tuples([grant])
    version = bump_policy_version()
    emit(
        "authz.spicedb_tuple.delete",
        user_id=user_id,
        document_id=document_id,
        tenant_id=tenant_id,
        extra={"tuples": [format_tuple(grant)], "deleter_principal": user_id, "reason_code": "access_revoked"},
    )

    return {**access_of(tenant_id, document_id), "policy_version": version}


def delete_document(user_id: str, tenant_id: str, document_id: str) -> None:
    ref = require_editor(user_id, tenant_id, document_id)
    get_vector_store().delete_document(tenant_id, document_id)
    get_authz_client().delete_relationships("document", ref)
    bump_policy_version()
    emit(
        "authz.spicedb_tuple.delete",
        user_id=user_id,
        document_id=document_id,
        tenant_id=tenant_id,
        extra={"tuples": [f"document:{ref}#*@*"], "deleter_principal": user_id, "reason_code": "document_deleted"},
    )


def tool_permissions(user_id: str) -> dict[str, bool]:
    authz = get_authz_client()

    return {tool: authorize_or_deny(authz, "tool", tool, "execute", "user", user_id) for tool in sorted(TOOL_SCHEMAS)}


def set_tool_permission(user_id: str, tenant_id: str, tool: str, allowed: bool) -> dict[str, bool]:
    if tool not in TOOL_SCHEMAS:
        raise PlaygroundError(404, f"Unknown tool '{tool}'.")
    if outage_active():
        raise PlaygroundError(503, "SpiceDB is unreachable, so permissions cannot be changed.")
    grant = ("tool", tool, "caller", "user", user_id)
    authz = get_authz_client()
    if allowed:
        authz.write_relationships([grant])
        emit(
            "authz.spicedb_tuple.write",
            user_id=user_id,
            tenant_id=tenant_id,
            extra={"tuples": [format_tuple(grant)], "writer_principal": "playground"},
        )
    else:
        authz.delete_tuples([grant])
        emit(
            "authz.spicedb_tuple.delete",
            user_id=user_id,
            tenant_id=tenant_id,
            extra={"tuples": [format_tuple(grant)], "deleter_principal": "playground", "reason_code": "tool_revoked"},
        )

    return tool_permissions(user_id)


def run_query(user_id: str, tenant_id: str, request: Any, mode: str | None = None, with_memory: bool = True) -> dict:
    memory = request.memory if with_memory and request.memory else None
    result = query_rag_system(
        collection_name=request.document_id,
        query=request.question,
        user_id=user_id,
        tenant_id=tenant_id,
        filtering_mode=MODES[mode or request.mode],
        enable_indirect_injection_scan=request.scan,
        enable_context_isolation=request.isolation,
        enable_datamarking=request.datamarking,
        enable_action_authz=request.tool_guard,
        enable_continuous_auth=request.continuous_auth,
        enable_llm_injection_scan=False,
        enable_agent_loop=False,
        generator=request.generator,
        prior_contexts=memory.contexts if memory else None,
        prior_retrieved=memory.retrieved if memory else None,
    )
    store = get_vector_store()
    reached = set(result.get("contexts", []))
    retrieved = []
    for item in result.get("retrieved", []):
        stored = store.get_chunk(str(item.get("tenant_id", "")), str(item.get("chunk_id", "")))
        text = stored.text if stored else ""
        retrieved.append(
            {
                **item,
                "text": text,
                "reached_model": text in reached,
                "allowed": can(user_id, str(item.get("tenant_id", "")), str(item.get("document_id", "")), "view"),
            }
        )

    return {
        "answer": result["answer"],
        "anonymized_query": result.get("anonymized_query", request.question),
        "retrieved": retrieved,
        "diagnostics": json.loads(json.dumps(result.get("diagnostics", {}), default=str)),
        "tool_results": result.get("tool_results", []),
        "memory": {"contexts": result.get("contexts", []), "retrieved": result.get("retrieved", [])},
        "policy_version": get_policy_version(),
    }


def compare_modes(user_id: str, tenant_id: str, request: Any) -> list[dict]:
    rows = []
    for mode in ("none", "post", "pre"):
        result = run_query(user_id, tenant_id, request, mode=mode, with_memory=False)
        sent = sum(1 for item in result["retrieved"] if item["reached_model"] and not item["allowed"])
        searched = {"post": result["diagnostics"].get("unauthorized_context_exposure", 0), "pre": 0}.get(mode, sent)
        rows.append(
            {
                "mode": mode,
                "answer": result["answer"],
                "forbidden_searched": searched,
                "forbidden_sent": sent,
                "documents": sorted({item["document_id"] for item in result["retrieved"]}),
            }
        )

    return rows


def audit_path_or_none() -> Path | None:
    settings = get_settings()

    return Path(settings.audit_log_path) if settings.audit_output_destination == "file" else None


def audit_events(since: int, limit: int = 200) -> dict:
    path = audit_path_or_none()
    if path is None or not path.exists():
        return {"total": 0, "events": []}
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    envelope = {"ts", "event", "user_id", "document_id", "tenant_id", "chain_hash"}
    events = []
    for number, line in enumerate(lines[since:], start=since + 1):
        record = json.loads(line)
        detail = {key: value for key, value in record.items() if key not in envelope}
        events.append(
            {
                **{key: record.get(key, "") for key in ("ts", "event", "user_id", "document_id", "tenant_id")},
                "line": number,
                "detail": json.dumps(detail, default=str)[:300],
            }
        )

    return {"total": len(lines), "events": events[-limit:]}


def verify_audit() -> dict:
    path = audit_path_or_none()
    if path is None or not path.exists():
        return {"ok": False, "message": "No audit log file yet."}
    result = verify_files([str(path)], hmac_secret())
    if result.ok:
        return {"ok": True, "message": f"OK: {result.lines} lines verified"}

    return {"ok": False, "message": f"TAMPERED: {result.error}"}


def reset() -> None:
    set_outage(False)
    if get_settings().app_env == "test":
        reset_authz_client()
        reset_vector_store()
    else:
        authz = get_authz_client()
        store = get_vector_store()
        for tenant_id, document_id in {(c.tenant_id, c.document_id) for c in store.list_chunks()}:
            store.delete_document(tenant_id, document_id)
            authz.delete_relationships("document", document_ref(tenant_id, document_id))
    path = audit_path_or_none()
    if path is not None:
        path.unlink(missing_ok=True)
    reset_audit_chain()
    graph._policy_version = 1
