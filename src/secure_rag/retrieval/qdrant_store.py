from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from secure_rag.settings import Settings, get_settings


@dataclass
class RetrievedChunk:
    chunk_id: str
    document_id: str
    tenant_id: str
    text: str
    score: float
    payload: dict[str, Any] = field(default_factory=dict)
    taint: str = "untrusted"


class VectorStore(Protocol):
    def upsert(self, points: list[dict[str, Any]]) -> None: ...
    def delete_document(self, document_id: str) -> None: ...
    def search(
        self,
        vector: list[float],
        limit: int,
        allowed_document_ids: list[str] | None = None,
        tenant_id: str | None = None,
    ) -> list[RetrievedChunk]: ...
    def list_documents(self, allowed_document_ids: list[str] | None = None) -> list[str]: ...
    def count(self) -> int: ...


class QdrantStore:
    def __init__(self, settings: Settings | None = None) -> None:
        settings = settings or get_settings()
        self.collection = settings.qdrant_collection
        self.dim = settings.embed_dim
        if settings.qdrant_in_memory or settings.app_env == "test":
            self.client = QdrantClient(":memory:")
        else:
            self.client = QdrantClient(url=settings.qdrant_url, api_key=settings.qdrant_api_key or None)
        self._ensure_collection()

    def _ensure_collection(self) -> None:
        existing = {c.name for c in self.client.get_collections().collections}
        if self.collection in existing:
            return
        self.client.create_collection(
            collection_name=self.collection,
            vectors_config=qmodels.VectorParams(size=self.dim, distance=qmodels.Distance.COSINE),
        )
        for field in ("document_id", "tenant_id", "chunk_id"):
            self.client.create_payload_index(
                collection_name=self.collection,
                field_name=field,
                field_schema=qmodels.PayloadSchemaType.KEYWORD,
            )

    def upsert(self, points: list[dict[str, Any]]) -> None:
        if not points:
            return
        self.client.upsert(
            collection_name=self.collection,
            points=[
                qmodels.PointStruct(
                    id=p["id"],
                    vector=p["vector"],
                    payload=p["payload"],
                )
                for p in points
            ],
        )

    def delete_document(self, document_id: str) -> None:
        self.client.delete(
            collection_name=self.collection,
            points_selector=qmodels.FilterSelector(
                filter=qmodels.Filter(
                    must=[qmodels.FieldCondition(key="document_id", match=qmodels.MatchValue(value=document_id))]
                )
            ),
        )

    def _filter(self, allowed_document_ids: list[str] | None, tenant_id: str | None) -> qmodels.Filter | None:
        must: list[qmodels.FieldCondition] = []
        if tenant_id:
            must.append(qmodels.FieldCondition(key="tenant_id", match=qmodels.MatchValue(value=tenant_id)))
        if allowed_document_ids is not None:
            if not allowed_document_ids:
                must.append(qmodels.FieldCondition(key="document_id", match=qmodels.MatchValue(value="__none__")))
            else:
                must.append(qmodels.FieldCondition(key="document_id", match=qmodels.MatchAny(any=allowed_document_ids)))
        return qmodels.Filter(must=must) if must else None

    def search(
        self,
        vector: list[float],
        limit: int,
        allowed_document_ids: list[str] | None = None,
        tenant_id: str | None = None,
    ) -> list[RetrievedChunk]:
        query_filter = self._filter(allowed_document_ids, tenant_id)
        response = self.client.query_points(
            collection_name=self.collection,
            query=vector,
            query_filter=query_filter,
            limit=limit,
            with_payload=True,
        )
        hits = getattr(response, "points", response)
        chunks: list[RetrievedChunk] = []
        for hit in hits:
            payload = dict(hit.payload or {})
            chunks.append(
                RetrievedChunk(
                    chunk_id=str(payload.get("chunk_id", hit.id)),
                    document_id=str(payload.get("document_id", "")),
                    tenant_id=str(payload.get("tenant_id", "")),
                    text=str(payload.get("text", "")),
                    score=float(hit.score or 0.0),
                    payload=payload,
                    taint=str(payload.get("taint", "untrusted")),
                )
            )
        return chunks

    def list_documents(self, allowed_document_ids: list[str] | None = None) -> list[str]:
        ids: set[str] = set()
        records, _ = self.client.scroll(collection_name=self.collection, limit=10_000, with_payload=True)
        for rec in records:
            doc_id = str((rec.payload or {}).get("document_id", ""))
            if not doc_id:
                continue
            if allowed_document_ids is None or doc_id in allowed_document_ids:
                ids.add(doc_id)
        return sorted(ids)

    def count(self) -> int:
        return int(self.client.count(self.collection).count)


_store: QdrantStore | None = None


def get_vector_store(settings: Settings | None = None) -> QdrantStore:
    global _store
    if _store is None:
        _store = QdrantStore(settings)
    return _store


def reset_vector_store() -> None:
    global _store
    _store = None
