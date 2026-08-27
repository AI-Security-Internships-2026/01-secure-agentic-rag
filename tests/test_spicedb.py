import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from database.spicedb_client import get_spicedb_client
from data_functions.query_engine import retrieve_context
from secure_rag.authz.client import reset_authz_client
from secure_rag.retrieval.ingest import ingest_texts
from secure_rag.retrieval.qdrant_store import reset_vector_store


class TestSpiceDBAccessControl(unittest.TestCase):
    def setUp(self):
        reset_vector_store()
        reset_authz_client()
        ingest_texts(
            "test_spicedb_doc",
            ["Secret password to the server is: 12345-cyber-secure.", "Normal public notice: Scannable assets are listed in annex A."],
            owner_id="alice",
            tenant_id="finance",
            viewers=["bob"],
            redact_pii=False,
        )

    def test_simulator_permissions(self):
        spicedb = get_spicedb_client()
        self.assertTrue(spicedb.check_permission("document", "test_spicedb_doc", "view", "user", "alice"))
        self.assertTrue(spicedb.check_permission("document", "test_spicedb_doc", "view", "user", "bob"))
        self.assertFalse(spicedb.check_permission("document", "test_spicedb_doc", "view", "user", "eve"))

    def test_prefilter_denies_unrelated_user(self):
        contexts, diag = retrieve_context(
            "test_spicedb_doc",
            "password",
            user_id="eve",
            filtering_mode="pre",
        )
        self.assertEqual(contexts, [])
        self.assertNotIn("test_spicedb_doc", diag.get("allowed_documents", ["test_spicedb_doc"]))
