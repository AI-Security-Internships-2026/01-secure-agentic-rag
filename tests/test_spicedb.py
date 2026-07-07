import os
import sys
import unittest
from dotenv import load_dotenv

# Add src/ to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from database.spicedb_client import get_spicedb_client
from data_functions.load_document import store_embeddings
from data_functions.query_engine import retrieve_context

load_dotenv()

class TestSpiceDBAccessControl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # We ensure we are using the mock client by setting blank env vars if not set
        os.environ.setdefault("SPICEDB_ENDPOINT", "")
        
        cls.collection_name = "test_spicedb_doc"
        cls.chunks = [
            "Secret password to the server is: 12345-cyber-secure.",
            "Normal public notice: Scannable assets are listed in annex A."
        ]
        # 768-dim embeddings for gemini
        cls.embeddings = [
            [0.1] * 768,
            [0.2] * 768
        ]

    def test_01_simulator_permissions(self):
        """
        Verify that SpiceDBSimulator correctly resolves ownership, view permission,
        and chunk-to-document parent permission inheritance.
        """
        spicedb = get_spicedb_client()
        
        # Reset relationships
        spicedb.delete_relationships("document")
        spicedb.delete_relationships("chunk")
        
        # Register permissions
        tuples = [
            # admin is owner, alice is viewer, bob has no permission
            ("document", "doc_p", "owner", "user", "admin"),
            ("document", "doc_p", "viewer", "user", "alice"),
            
            # Chunks belong to doc_p
            ("chunk", "c0", "parent_document", "document", "doc_p"),
            ("chunk", "c1", "parent_document", "document", "doc_p"),
        ]
        spicedb.write_relationships(tuples)
        
        # Test CheckPermission on document
        self.assertTrue(spicedb.check_permission("document", "doc_p", "view", "user", "admin"))
        self.assertTrue(spicedb.check_permission("document", "doc_p", "view", "user", "alice"))
        self.assertFalse(spicedb.check_permission("document", "doc_p", "view", "user", "bob"))
        
        # Test CheckPermission on chunk
        self.assertTrue(spicedb.check_permission("chunk", "c0", "view", "user", "admin"))
        self.assertTrue(spicedb.check_permission("chunk", "c0", "view", "user", "alice"))
        self.assertFalse(spicedb.check_permission("chunk", "c0", "view", "user", "bob"))

        # Test LookupResources
        allowed_docs = spicedb.lookup_resources("document", "view", "user", "alice")
        self.assertIn("doc_p", allowed_docs)
        
        allowed_docs_bob = spicedb.lookup_resources("document", "view", "user", "bob")
        self.assertNotIn("doc_p", allowed_docs_bob)

    def test_02_integration_retrieval(self):
        """
        Store test chunks in ChromaDB and verify retrieve_context under pre-filtering,
        post-filtering, and no-filtering modes.
        """
        # Store embeddings & register relationships
        store_embeddings(
            chunks=self.chunks,
            embeddings=self.embeddings,
            file_path=self.collection_name,
            owner_id="admin",
            viewers=["alice"]
        )
        
        # Query parameters
        query = "What is the secret server password?"
        
        # Test admin access under PRE-filtering (admin defaults to bypass/access allowed)
        admin_contexts, _ = retrieve_context(
            self.collection_name, query, n_results=2, user_id="admin", filtering_mode="pre"
        )
        self.assertEqual(len(admin_contexts), 2)
        
        # Test alice access under PRE-filtering (alice is registered as viewer)
        alice_contexts, _ = retrieve_context(
            self.collection_name, query, n_results=2, user_id="alice", filtering_mode="pre"
        )
        self.assertEqual(len(alice_contexts), 2)
        
        # Test bob access under PRE-filtering (bob has no permission, should return empty)
        bob_contexts, _ = retrieve_context(
            self.collection_name, query, n_results=2, user_id="bob", filtering_mode="pre"
        )
        self.assertEqual(len(bob_contexts), 0)
        
        # Test bob access under POST-filtering (bob has no permission, should discard all chunks)
        bob_contexts_post, _ = retrieve_context(
            self.collection_name, query, n_results=2, user_id="bob", filtering_mode="post"
        )
        self.assertEqual(len(bob_contexts_post), 0)
        
        # Test bob access under NONE filtering (should leak the documents, proving security control effectiveness)
        bob_contexts_none, _ = retrieve_context(
            self.collection_name, query, n_results=2, user_id="bob", filtering_mode="none"
        )
        self.assertEqual(len(bob_contexts_none), 2)


if __name__ == "__main__":
    unittest.main()
