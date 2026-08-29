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
