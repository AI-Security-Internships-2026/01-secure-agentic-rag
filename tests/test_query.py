from secure_rag.agent.graph import query_rag_system, retrieve_authorized
from secure_rag.authz.client import reset_authz_client
from secure_rag.retrieval.ingest import ingest_texts
from secure_rag.retrieval.qdrant_store import reset_vector_store


def setup_function():
    reset_vector_store()
    reset_authz_client()
    ingest_texts(
        "cyber-policy",
        ["Database indexing in this knowledge base uses Qdrant cosine search."],
        owner_id="alice",
        tenant_id="finance",
        redact_pii=False,
    )


def test_retrieve_authorized_for_owner():
    chunks, diag = retrieve_authorized(
        "Qdrant cosine search",
        "alice",
        n_results=5,
        filtering_mode="pre",
        collection_name="cyber-policy",
        tenant_id="finance",
    )
    assert diag["filtering_mode"] == "pre"
    assert any("Qdrant" in chunk.text for chunk in chunks)


def test_query_rag_system_returns_answer():
    result = query_rag_system(
        "cyber-policy",
        "What search does the knowledge base use?",
        user_id="alice",
        tenant_id="finance",
        filtering_mode="pre",
        enable_indirect_injection_scan=False,
    )
    assert "answer" in result
    assert isinstance(result["contexts"], list)
