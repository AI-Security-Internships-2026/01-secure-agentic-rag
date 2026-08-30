import pytest
from fastapi.testclient import TestClient

from secure_rag.api.app import create_app
from secure_rag.api.auth import create_token
from secure_rag.authz.client import reset_authz_client
from secure_rag.retrieval.ingest import ingest_texts
from secure_rag.retrieval.qdrant_store import reset_vector_store
from secure_rag.settings import reset_settings


@pytest.fixture
def client():
    reset_vector_store()
    reset_authz_client()
    return TestClient(create_app())


def test_chat_requires_auth(client):
    denied = client.post("/chat", json={"message": "hello"})
    assert denied.status_code == 401


def test_chat_with_jwt(client):
    ingest_texts(
        "help-center",
        ["Password resets require a verified work email. Marker CANARY_CHAT_A1."],
        owner_id="alice",
        tenant_id="finance",
        redact_pii=False,
    )
    token = create_token("alice", "finance")
    response = client.post(
        "/chat",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "How do password resets work?"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "reply" in body
    assert "CANARY_CHAT_A1" in body["reply"] or "email" in body["reply"].lower()


def test_widget_site_key_chat_only(monkeypatch):
    monkeypatch.setenv("WIDGET_SITE_KEY", "widget-secret-key")
    monkeypatch.setenv("WIDGET_USER_ID", "alice")
    monkeypatch.setenv("WIDGET_TENANT_ID", "finance")
    reset_settings()
    reset_vector_store()
    reset_authz_client()
    ingest_texts(
        "help-center",
        ["Office hours are 9 to 5. Marker CANARY_CHAT_B2."],
        owner_id="alice",
        tenant_id="finance",
        redact_pii=False,
    )
    client = TestClient(create_app())
    try:
        blocked = client.post(
            "/ingest",
            headers={"X-Site-Key": "widget-secret-key"},
            json={"document_id": "x", "texts": ["no"]},
        )
        assert blocked.status_code == 401
        chat = client.post(
            "/chat",
            headers={"X-Site-Key": "widget-secret-key"},
            json={"message": "What are office hours?"},
        )
        assert chat.status_code == 200
        assert "CANARY_CHAT_B2" in chat.json()["reply"] or "9" in chat.json()["reply"]
        wrong = client.post("/chat", headers={"X-Site-Key": "wrong"}, json={"message": "hello"})
        assert wrong.status_code == 401
    finally:
        monkeypatch.delenv("WIDGET_SITE_KEY", raising=False)
        monkeypatch.delenv("WIDGET_USER_ID", raising=False)
        monkeypatch.delenv("WIDGET_TENANT_ID", raising=False)
        reset_settings()


def test_widget_assets_and_config(client):
    assert client.get("/static/widget.js").status_code == 200
    assert client.get("/static/widget.css").status_code == 200
    assert "AuthInject-RAG" in client.get("/").text
    config = client.get("/widget/config").json()
    assert "title" in config
    assert "welcome" in config
    assert "enabled" in config
