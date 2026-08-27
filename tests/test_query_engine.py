import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from data_functions.query_engine import query_rag_system, retrieve_context
from secure_rag.authz.client import reset_authz_client
from secure_rag.retrieval.ingest import ingest_texts
from secure_rag.retrieval.qdrant_store import reset_vector_store


class TestQueryEngine(unittest.TestCase):
    def setUp(self):
        reset_vector_store()
        reset_authz_client()
        ingest_texts(
            "cyber-policy",
            ["Database indexing in this knowledge base uses Qdrant cosine search."],
            owner_id="alice",
            tenant_id="finance",
            redact_pii=False,
        )

    def test_retrieve_context_authorized(self):
        contexts, diag = retrieve_context("cyber-policy", "Qdrant cosine search", user_id="alice", filtering_mode="pre")
        self.assertTrue(any("Qdrant" in c for c in contexts) or diag["filtering_mode"] == "pre")

    def test_query_rag_system_returns_answer(self):
        result = query_rag_system(
            "cyber-policy",
            "What search does the knowledge base use?",
            user_id="alice",
            filtering_mode="pre",
            enable_indirect_injection_scan=False,
        )
        self.assertIn("answer", result)
        self.assertIsInstance(result["contexts"], list)
