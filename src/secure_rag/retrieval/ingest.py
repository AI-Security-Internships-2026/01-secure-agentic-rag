from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from pathlib import Path

from secure_rag.audit.events import emit
from secure_rag.authz.client import AuthorizationError, get_authz_client
from secure_rag.retrieval.embeddings import get_embedder
from secure_rag.retrieval.pii import anonymize_text, chunk_text
from secure_rag.retrieval.qdrant_store import get_vector_store
from secure_rag.settings import get_settings

logger = logging.getLogger("secure_rag.ingest")


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", Path(value).stem).strip("_").lower()
    return slug or "document"


def _stable_uuid(value: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, value))


def ingest_texts(
    document_id: str,
    texts: list[str],
    *,
    owner_id: str,
    tenant_id: str,
    viewers: list[str] | None = None,
    source: str = "inline",
    redact_pii: bool = True,
) -> dict:
    settings = get_settings()
    viewers = viewers or []
    store = get_vector_store(settings)
    authz = get_authz_client(settings)
    embedder = get_embedder(settings)

    chunks: list[str] = []
    for text in texts:
        cleaned = anonymize_text(text) if redact_pii else text
        chunks.extend(chunk_text(cleaned))
    if not chunks:
        raise ValueError("no chunks produced")

    provenance = hashlib.sha256("\n".join(chunks).encode("utf-8")).hexdigest()
    vectors = embedder.embed(chunks, task="retrieval_document")
    points = []
    tuples = [
        ("document", document_id, "owner", "user", owner_id),
        ("document", document_id, "tenant", "tenant", tenant_id),
        ("tenant", tenant_id, "member", "user", owner_id),
    ]
    for viewer in viewers:
        tuples.append(("document", document_id, "viewer", "user", viewer))
        tuples.append(("tenant", tenant_id, "member", "user", viewer))

    try:
        authz.write_relationships(tuples)
        chunk_tuples = []
        for idx, (chunk, vector) in enumerate(zip(chunks, vectors)):
            chunk_id = f"{document_id}__{idx}"
            chunk_tuples.append(("chunk", chunk_id, "parent_document", "document", document_id))
            points.append(
                {
                    "id": _stable_uuid(chunk_id),
                    "vector": vector,
                    "payload": {
                        "chunk_id": chunk_id,
                        "document_id": document_id,
                        "tenant_id": tenant_id,
                        "text": chunk,
                        "source": source,
                        "provenance": provenance,
                        "taint": "untrusted",
                        "index": idx,
                    },
                }
            )
        authz.write_relationships(chunk_tuples)
        store.delete_document(document_id)
        store.upsert(points)
    except Exception as exc:
        logger.exception("ingest failed; rolling back searchable vectors")
        store.delete_document(document_id)
        try:
            authz.delete_relationships("document", document_id)
        except Exception:
            logger.exception("SpiceDB rollback failed")
        raise AuthorizationError("ingestion aborted to avoid unauthorized searchable state") from exc

    emit(
        "document.ingested",
        user_id=owner_id,
        document_id=document_id,
        tenant_id=tenant_id,
        extra={"chunk_count": len(chunks), "provenance": provenance},
    )
    return {"document_id": document_id, "chunk_count": len(chunks), "provenance": provenance}


def ingest_pdf(path: str, owner_id: str, tenant_id: str, viewers: list[str] | None = None) -> dict:
    from pypdf import PdfReader

    reader = PdfReader(path)
    texts = [(page.extract_text() or "") for page in reader.pages]
    document_id = _slug(path)
    return ingest_texts(document_id, texts, owner_id=owner_id, tenant_id=tenant_id, viewers=viewers, source=path)


def migrate_chroma(chroma_dir: str) -> dict:
    """One-time Chroma -> Qdrant copy. Requires optional chromadb extra."""
    import chromadb

    client = chromadb.PersistentClient(path=chroma_dir)
    migrated = 0
    for collection in client.list_collections():
        data = collection.get(include=["documents", "metadatas", "embeddings"])
        ids = data.get("ids") or []
        docs = data.get("documents") or []
        metas = data.get("metadatas") or [{}] * len(ids)
        embs = data.get("embeddings") or []
        points = []
        for i, chunk_id in enumerate(ids):
            meta = metas[i] or {}
            document_id = str(meta.get("document_id", collection.name))
            points.append(
                {
                    "id": _stable_uuid(str(chunk_id)),
                    "vector": list(embs[i]) if embs else get_embedder().embed([docs[i]])[0],
                    "payload": {
                        "chunk_id": str(chunk_id),
                        "document_id": document_id,
                        "tenant_id": str(meta.get("tenant_id", "default")),
                        "text": docs[i],
                        "source": str(meta.get("source", "chroma")),
                        "taint": "untrusted",
                    },
                }
            )
        get_vector_store().upsert(points)
        migrated += len(points)
    return {"migrated_points": migrated, "note": json.dumps({"source": chroma_dir})}
