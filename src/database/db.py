"""Legacy Chroma helpers replaced by Qdrant. Kept for import compatibility."""

from secure_rag.retrieval.qdrant_store import get_vector_store


def get_client():
    return get_vector_store()


def query_documents(collection_name, query_embedding, n_results=5, where=None):
    allowed = None
    if where and "document_id" in where:
        allowed = [where["document_id"]]
    hits = get_vector_store().search(query_embedding, n_results, allowed_document_ids=allowed)
    return {
        "documents": [[h.text for h in hits]],
        "metadatas": [[{"document_id": h.document_id} for h in hits]],
        "ids": [[h.chunk_id for h in hits]],
    }
