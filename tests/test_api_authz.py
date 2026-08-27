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
