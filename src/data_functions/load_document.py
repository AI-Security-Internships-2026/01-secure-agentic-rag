"""Compatibility shim."""

from pypdf import PdfReader
from secure_rag.retrieval.ingest import ingest_pdf, ingest_texts
from secure_rag.retrieval.pii import anonymize_text, chunk_text

RESOLVED_EMBED_MODEL = "hash"
EMBED_DIM = 768


def get_analyzer_and_anonymizer():
    class _Dummy:
        def analyze(self, text, language="en"):
            return []

        def anonymize(self, text, analyzer_results=None):
            class R:
                def __init__(self, text):
                    self.text = text

            return R(text)

    dummy = _Dummy()
    return dummy, dummy


def load_and_chunk_pdf(path: str):
    reader = PdfReader(path)
    texts = [(page.extract_text() or "") for page in reader.pages]
    chunks = []
    for t in texts:
        chunks.extend(chunk_text(anonymize_text(t)))
    return chunks


def embed_texts(texts, batch_size=100):
    from secure_rag.retrieval.embeddings import get_embedder

    return get_embedder().embed(list(texts))


def store_embeddings(chunks, embeddings, pdf_path, owner_id="analyst", viewers=None):
    from pathlib import Path

    document_id = Path(pdf_path).stem.lower().replace(" ", "_")
    ingest_texts(document_id, chunks, owner_id=owner_id, tenant_id="default", viewers=viewers or [], redact_pii=False)
    return document_id
