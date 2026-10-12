import pytest

from secure_rag import demo
from secure_rag.agent import graph
from secure_rag.agent.guardrails import BLOCKED_INJECTION_MESSAGE
from secure_rag.audit.events import reset_audit_chain
from secure_rag.authz.client import reset_authz_client
from secure_rag.retrieval.qdrant_store import reset_vector_store
from secure_rag.settings import get_settings, reset_settings


@pytest.fixture
def fresh_state():
    policy_version = graph._policy_version
    yield
    reset_settings()
    reset_authz_client()
    reset_vector_store()
    reset_audit_chain()
    graph._policy_version = policy_version


def test_offline_demo_passes_every_check(monkeypatch, tmp_path, fresh_state):
    monkeypatch.chdir(tmp_path)
    for key, value in demo.mode_environment("offline").items():
        monkeypatch.setenv(key, value)
    demo.prepare("offline", set_environment=False)

    checks = demo.run("offline")

    assert len(checks) == 26
    assert [label for label, ok in checks if not ok] == []


def test_output_guard_keeps_fixed_system_messages(monkeypatch):
    development = get_settings().model_copy(update={"app_env": "development"})
    monkeypatch.setattr(graph, "get_settings", lambda: development)
    monkeypatch.setattr(graph, "anonymize_text", lambda text: text.replace("Alert", "<PERSON>"))

    blocked = graph.guard_output({"answer": BLOCKED_INJECTION_MESSAGE})
    generated = graph.guard_output({"answer": "Alert raised by Alice"})

    assert blocked["answer"] == BLOCKED_INJECTION_MESSAGE
    assert generated["answer"] == "<PERSON> raised by Alice"
