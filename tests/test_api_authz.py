import pytest
from fastapi.testclient import TestClient

from secure_rag.api.app import create_app
from secure_rag.api.auth import create_token
from secure_rag.authz.client import get_authz_client, reset_authz_client
from secure_rag.retrieval.ingest import ingest_texts
from secure_rag.retrieval.qdrant_store import reset_vector_store


@pytest.fixture
def client():
    reset_vector_store()
    reset_authz_client()
    return TestClient(create_app())


def test_health_and_query_auth(client):
    assert client.get("/health").json()["status"] == "ok"
    denied = client.post("/query", json={"query": "hello"})
    assert denied.status_code == 401
    token = create_token("alice", "finance")
    ingest_texts(
        "finance-policy",
        ["Quarterly close requires dual control. Marker CANARY_FIN_A1."],
        owner_id="alice",
        tenant_id="finance",
        redact_pii=False,
    )
    response = client.post(
        "/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "What dual control is required?", "filtering_mode": "pre"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "dual control" in body["answer"].lower() or "CANARY_FIN_A1" in body["answer"]


def test_cross_tenant_prefilter_blocks_exposure():
    reset_vector_store()
    reset_authz_client()
    ingest_texts("finance-policy", ["secret CANARY_FIN_A1"], owner_id="alice", tenant_id="finance", redact_pii=False)
    ingest_texts("eng-runbook", ["secret CANARY_ENG_B2"], owner_id="bob", tenant_id="engineering", redact_pii=False)
    from secure_rag.agent.graph import query_rag_system

    result = query_rag_system(
        collection_name="",
        query="secret CANARY_ENG_B2",
        user_id="alice",
        tenant_id="finance",
        filtering_mode="pre",
        enable_indirect_injection_scan=False,
    )
    retrieved_docs = {item["document_id"] for item in result.get("retrieved", [])}
    assert "eng-runbook" not in retrieved_docs
    assert "CANARY_ENG_B2" not in result["answer"]


def test_action_authz_denied_for_non_caller():
    reset_authz_client()
    get_authz_client().write_relationships([("tool", "send_email", "caller", "user", "carol")])
    from secure_rag.agent.tools import execute_tool

    denied = execute_tool("send_email", "alice")
    allowed = execute_tool("send_email", "carol")
    assert denied.allowed is False
    assert allowed.allowed is True


def test_filtering_mode_none_rejected_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    from secure_rag.settings import reset_settings

    reset_settings()
    try:
        client = TestClient(create_app())
        token = create_token("alice", "finance")
        response = client.post(
            "/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "test query", "filtering_mode": "research_baseline_none"},
        )
        assert response.status_code == 403
        assert "Baseline-none mode is internal research-only; not available on production API." in response.json()["detail"]
    finally:
        reset_settings()


def test_filtering_mode_post_rejected_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    from secure_rag.settings import reset_settings

    reset_settings()
    try:
        client = TestClient(create_app())
        token = create_token("alice", "finance")
        response = client.post(
            "/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "test query", "filtering_mode": "post"},
        )
        assert response.status_code == 403
        assert "Post-filter mode is not permitted in production profile." in response.json()["detail"]
    finally:
        reset_settings()


def test_filtering_mode_bad_value_422(client):
    token = create_token("alice", "finance")
    response = client.post(
        "/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "test query", "filtering_mode": "banana"},
    )
    assert response.status_code == 422


def test_internal_baseline_none_works_via_direct_call():
    reset_vector_store()
    reset_authz_client()
    ingest_texts("finance-policy", ["secret CANARY_FIN_A1"], owner_id="alice", tenant_id="finance", redact_pii=False)
    ingest_texts("eng-runbook", ["secret CANARY_ENG_B2"], owner_id="bob", tenant_id="engineering", redact_pii=False)
    from secure_rag.agent.graph import query_rag_system

    result = query_rag_system(
        collection_name="",
        query="secret CANARY_ENG_B2",
        user_id="alice",
        tenant_id="finance",
        filtering_mode="research_baseline_none",
        enable_indirect_injection_scan=False,
    )
    retrieved_docs = {item["document_id"] for item in result.get("retrieved", [])}
    assert "eng-runbook" in retrieved_docs


def test_pre_mode_works_in_production(monkeypatch):
    reset_vector_store()
    reset_authz_client()
    monkeypatch.setenv("APP_ENV", "production")
    from secure_rag.settings import reset_settings

    reset_settings()
    try:
        ingest_texts("finance-policy", ["secret CANARY_FIN_A1"], owner_id="alice", tenant_id="finance", redact_pii=False)
        ingest_texts("eng-runbook", ["secret CANARY_ENG_B2"], owner_id="bob", tenant_id="engineering", redact_pii=False)
        client = TestClient(create_app())
        token = create_token("alice", "finance")
        response = client.post(
            "/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "secret CANARY_FIN_A1", "filtering_mode": "pre"},
        )
        assert response.status_code == 200
        retrieved_docs = {item["document_id"] for item in response.json().get("retrieved", [])}
        assert "finance-policy" in retrieved_docs
        assert "eng-runbook" not in retrieved_docs
    finally:
        reset_settings()


# --- Issue S3 Ingest Overwrite & Owner Authorization Tests ---


def test_ingest_overwrite_no_permission_403(client):
    """Alice owns doc1; Bob (unauthorized) attempts to overwrite doc1 -> HTTP 403, owner unchanged."""
    token_alice = create_token("alice", "engineering")
    token_bob = create_token("bob", "engineering")

    res1 = client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_alice}"},
        json={"document_id": "board-minutes-2026-q1", "texts": ["Original text CANARY_ORIG_1"], "redact_pii": False},
    )
    assert res1.status_code == 200

    authz = get_authz_client()
    assert authz.get_document_owner("board-minutes-2026-q1") == "alice"

    # Bob attempts to overwrite
    res2 = client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_bob}"},
        json={"document_id": "board-minutes-2026-q1", "texts": ["Mallory injection text"], "redact_pii": False},
    )
    assert res2.status_code == 403
    assert "caller is not owner/editor" in res2.json()["detail"]

    # Owner remains Alice
    assert authz.get_document_owner("board-minutes-2026-q1") == "alice"


def test_ingest_editor_overwrite_allowed(client):
    """Alice owns doc1, Bob is editor; Bob overwrites doc1 -> HTTP 200, owner remains Alice."""
    token_alice = create_token("alice", "engineering")
    token_bob = create_token("bob", "engineering")

    client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_alice}"},
        json={"document_id": "doc_editable", "texts": ["Initial content"], "redact_pii": False},
    )

    authz = get_authz_client()
    authz.write_relationships([("document", "doc_editable", "editor", "user", "bob")])

    # Bob overwrites as editor
    res = client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_bob}"},
        json={"document_id": "doc_editable", "texts": ["Editor updated content"], "redact_pii": False},
    )
    assert res.status_code == 200

    # Owner must still be Alice
    assert authz.get_document_owner("doc_editable") == "alice"


def test_ingest_owner_overwrite_allowed(client):
    """Alice owns doc1; Alice ingests doc1 again -> HTTP 200."""
    token_alice = create_token("alice", "engineering")

    res1 = client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_alice}"},
        json={"document_id": "doc_owner_repeat", "texts": ["Version 1"], "redact_pii": False},
    )
    assert res1.status_code == 200

    res2 = client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_alice}"},
        json={"document_id": "doc_owner_repeat", "texts": ["Version 2"], "redact_pii": False},
    )
    assert res2.status_code == 200
    assert get_authz_client().get_document_owner("doc_owner_repeat") == "alice"


def test_ingest_owner_transfer_allowed_only_by_owner(client):
    """Alice owns doc1; Alice transfers owner to Carol via owner_id parameter -> owner becomes Carol."""
    token_alice = create_token("alice", "engineering")

    client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_alice}"},
        json={"document_id": "doc_transfer", "texts": ["Initial content"], "redact_pii": False},
    )
    authz = get_authz_client()
    assert authz.get_document_owner("doc_transfer") == "alice"

    # Alice transfers to Carol
    res = client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_alice}"},
        json={"document_id": "doc_transfer", "texts": ["Transferred content"], "owner_id": "carol", "redact_pii": False},
    )
    assert res.status_code == 200
    assert authz.get_document_owner("doc_transfer") == "carol"


def test_ingest_editor_cannot_transfer_owner(client):
    """Alice owns doc1, Bob is editor; Bob attempts to set owner_id=Bob -> Ingest updates text but owner remains Alice."""
    token_alice = create_token("alice", "engineering")
    token_bob = create_token("bob", "engineering")

    client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_alice}"},
        json={"document_id": "doc_editor_preserve", "texts": ["Initial content"], "redact_pii": False},
    )
    authz = get_authz_client()
    authz.write_relationships([("document", "doc_editor_preserve", "editor", "user", "bob")])

    res = client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_bob}"},
        json={"document_id": "doc_editor_preserve", "texts": ["Bob edit"], "owner_id": "bob", "redact_pii": False},
    )
    assert res.status_code == 200
    # Owner remains Alice, NOT transferred to Bob
    assert authz.get_document_owner("doc_editor_preserve") == "alice"


def test_ingest_new_doc_allowed_for_tenant_member(client):
    """Tenant member creates new doc in their tenant -> HTTP 200."""
    token = create_token("dave", "engineering")
    res = client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token}"},
        json={"document_id": "dave_new_doc", "texts": ["Dave content"], "redact_pii": False},
    )
    assert res.status_code == 200
    assert get_authz_client().get_document_owner("dave_new_doc") == "dave"


def test_ingest_cross_tenant_forbidden_403(client):
    """Mallory (marketing tenant) attempts to create document in engineering tenant -> HTTP 403."""
    token_mallory = create_token("mallory", "marketing")
    res = client.post(
        "/ingest",
        headers={"Authorization": f"Bearer {token_mallory}"},
        json={
            "document_id": "foreign_tenant_doc",
            "tenant_id": "engineering",
            "texts": ["Malicious payload"],
            "redact_pii": False,
        },
    )
    assert res.status_code == 403
    assert "not a member of tenant 'engineering'" in res.json()["detail"]
