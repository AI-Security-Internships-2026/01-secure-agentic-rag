from unittest.mock import MagicMock, patch

from secure_rag.retrieval.ingest import ingest_pdf, ingest_texts
from secure_rag.retrieval.pii import anonymize_text, chunk_text
from secure_rag.authz.client import reset_authz_client
from secure_rag.retrieval.qdrant_store import reset_vector_store


def test_chunk_text_keeps_content():
    chunks = chunk_text("Qdrant stores vectors for authorization-first retrieval.")
    assert any("Qdrant" in chunk for chunk in chunks)


def test_anonymize_is_available():
    assert isinstance(anonymize_text("hello"), str)


@patch("pypdf.PdfReader")
def test_ingest_pdf_indexes_pages(mock_reader):
    reset_vector_store()
    reset_authz_client()
    page = MagicMock()
    page.extract_text.return_value = "Qdrant stores vectors for authorization-first retrieval."
    mock_reader.return_value.pages = [page]
    result = ingest_pdf("dummy-policy.pdf", owner_id="alice", tenant_id="finance")
    assert result["document_id"]
    assert result["chunk_count"] >= 1


def test_ingest_texts_roundtrip_count():
    reset_vector_store()
    reset_authz_client()
    result = ingest_texts(
        "roundtrip-doc",
        ["Authorization-first retrieval uses Qdrant payload filters."],
        owner_id="alice",
        tenant_id="finance",
        redact_pii=False,
    )
    assert result["chunk_count"] == 1


# --- Issue S5 Multi-Tenant Qdrant delete_document Tests ---


def test_cross_tenant_delete_document_isolation():
    """Upsert tenant_a/doc42 + tenant_b/doc42. Delete tenant_a/doc42 -> tenant_b/doc42 survives."""
    from secure_rag.retrieval.qdrant_store import get_vector_store

    reset_vector_store()
    store = get_vector_store()
    dim = store.dim

    points_a = [
        {
            "id": f"00000000-0000-0000-0000-00000000000{i}",
            "vector": [0.1] * dim,
            "payload": {"tenant_id": "tenant_a", "document_id": "doc42", "chunk_id": f"doc42__{i}", "text": f"A_{i}"},
        }
        for i in range(1, 6)
    ]
    points_b = [
        {
            "id": f"00000000-0000-0000-0000-00000000001{i}",
            "vector": [0.2] * dim,
            "payload": {"tenant_id": "tenant_b", "document_id": "doc42", "chunk_id": f"doc42__{i}", "text": f"B_{i}"},
        }
        for i in range(1, 6)
    ]

    store.upsert(points_a + points_b)
    assert store.count() == 10
    assert store.count("tenant_a", "doc42") == 5
    assert store.count("tenant_b", "doc42") == 5

    # Delete tenant_a's doc42
    store.delete_document("tenant_a", "doc42")

    # Assert tenant_a points are deleted, but tenant_b points remain intact
    assert store.count("tenant_a", "doc42") == 0
    assert store.count("tenant_b", "doc42") == 5
    assert store.count() == 5


def test_same_tenant_delete_document():
    """Deleting tenant_b/doc42 drops its count to 0."""
    from secure_rag.retrieval.qdrant_store import get_vector_store

    reset_vector_store()
    store = get_vector_store()
    dim = store.dim

    points = [
        {
            "id": f"00000000-0000-0000-0000-00000000002{i}",
            "vector": [0.1] * dim,
            "payload": {"tenant_id": "tenant_b", "document_id": "doc42", "chunk_id": f"doc42__{i}", "text": f"B_{i}"},
        }
        for i in range(5)
    ]
    store.upsert(points)
    assert store.count("tenant_b", "doc42") == 5

    store.delete_document("tenant_b", "doc42")
    assert store.count("tenant_b", "doc42") == 0
    assert store.count() == 0


def test_same_doc_id_multi_tenant_ingest_roundtrip():
    """Ingest same doc_id under two different tenants, delete one via ingest overwrite/delete, ensure other survives."""
    from secure_rag.retrieval.qdrant_store import get_vector_store

    reset_vector_store()
    reset_authz_client()
    store = get_vector_store()

    ingest_texts(
        "shared_name_doc",
        ["Startup Alpha secret information."],
        owner_id="alice",
        tenant_id="startup_alpha",
        redact_pii=False,
    )
    ingest_texts(
        "shared_name_doc",
        ["Healthcare Beta secret patient record."],
        owner_id="bob",
        tenant_id="healthcare_beta",
        redact_pii=False,
    )

    assert store.count("startup_alpha", "shared_name_doc") == 1
    assert store.count("healthcare_beta", "shared_name_doc") == 1

    # Delete startup_alpha's document
    store.delete_document("startup_alpha", "shared_name_doc")

    # Assert healthcare_beta's document survives
    assert store.count("startup_alpha", "shared_name_doc") == 0
    assert store.count("healthcare_beta", "shared_name_doc") == 1


def test_same_doc_id_across_tenants_has_separate_acls():
    """A doc id reused in another tenant is a different SpiceDB object: no shared owner, no shared view."""
    from secure_rag.agent.graph import retrieve_authorized
    from secure_rag.authz.client import document_ref, get_authz_client

    reset_vector_store()
    reset_authz_client()
    ingest_texts("shared_name_doc", ["Alpha CANARY_ALPHA"], owner_id="alice", tenant_id="startup_alpha", redact_pii=False)
    ingest_texts("shared_name_doc", ["Beta CANARY_BETA"], owner_id="bob", tenant_id="healthcare_beta", redact_pii=False)
    authz = get_authz_client()

    assert authz.get_document_owner(document_ref("startup_alpha", "shared_name_doc")) == "alice"
    assert authz.get_document_owner(document_ref("healthcare_beta", "shared_name_doc")) == "bob"
    assert not authz.check_permission("document", document_ref("startup_alpha", "shared_name_doc"), "edit", "user", "bob")

    # Without a tenant scope, pre-filtering must still match (tenant, document) pairs.
    for mode in ("pre", "post"):
        chunks, _ = retrieve_authorized("CANARY_BETA", "alice", n_results=5, filtering_mode=mode, tenant_id=None)
        texts = " ".join(c.text for c in chunks)
        assert "CANARY_BETA" not in texts
        if mode == "pre":
            assert "CANARY_ALPHA" in texts
