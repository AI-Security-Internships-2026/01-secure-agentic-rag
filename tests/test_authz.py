from secure_rag.agent.graph import retrieve_authorized
from secure_rag.authz.client import get_authz_client, reset_authz_client
from secure_rag.retrieval.ingest import ingest_texts
from secure_rag.retrieval.qdrant_store import reset_vector_store


def setup_function():
    reset_vector_store()
    reset_authz_client()
    ingest_texts(
        "test_spicedb_doc",
        [
            "Secret password to the server is: 12345-cyber-secure.",
            "Normal public notice: Scannable assets are listed in annex A.",
        ],
        owner_id="alice",
        tenant_id="finance",
        viewers=["bob"],
        redact_pii=False,
    )


def test_simulator_permissions():
    authz = get_authz_client()
    assert authz.check_permission("document", "test_spicedb_doc", "view", "user", "alice")
    assert authz.check_permission("document", "test_spicedb_doc", "view", "user", "bob")
    assert not authz.check_permission("document", "test_spicedb_doc", "view", "user", "eve")


def test_prefilter_denies_unrelated_user():
    chunks, diag = retrieve_authorized(
        "password",
        "eve",
        filtering_mode="pre",
        collection_name="test_spicedb_doc",
        tenant_id="hr",
    )
    assert chunks == []
    assert "test_spicedb_doc" not in diag.get("allowed_documents", ["test_spicedb_doc"])
