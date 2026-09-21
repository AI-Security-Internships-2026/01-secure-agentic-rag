import json
import pytest

from secure_rag.audit.events import emit, verify_audit_sink
from secure_rag.settings import reset_settings


def test_audit_stdout_destination(capsys, monkeypatch):
    monkeypatch.setenv("AUDIT_OUTPUT_DESTINATION", "stdout")
    reset_settings()
    try:
        emit("test.event.stdout", user_id="alice", document_id="doc1", tenant_id="finance", extra={"action": "read"})
        captured = capsys.readouterr()
        lines = [line for line in captured.out.strip().split("\n") if line.startswith("[AUDIT] ")]
        assert len(lines) >= 1
        record = json.loads(lines[-1].replace("[AUDIT] ", "", 1))
        assert record["event"] == "test.event.stdout"
        assert record["user_id"] == "alice"
        assert record["document_id"] == "doc1"
        assert record["tenant_id"] == "finance"
        assert record["action"] == "read"
    finally:
        reset_settings()


def test_audit_file_destination(tmp_path, monkeypatch):
    log_file = tmp_path / "test_audit.jsonl"
    monkeypatch.setenv("AUDIT_OUTPUT_DESTINATION", "file")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(log_file))
    reset_settings()
    try:
        verify_audit_sink()
        emit("test.event.file", user_id="bob", document_id="doc2", tenant_id="engineering")
        assert log_file.exists()
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) >= 1
        records = [json.loads(line) for line in lines]
        assert any(r["event"] == "test.event.file" and r["user_id"] == "bob" for r in records)
    finally:
        reset_settings()


def test_audit_fail_closed_on_unwritable_file(monkeypatch):
    from unittest.mock import patch

    monkeypatch.setenv("AUDIT_OUTPUT_DESTINATION", "file")
    monkeypatch.setenv("AUDIT_LOG_PATH", "/etc/forbidden/audit.jsonl")
    reset_settings()
    try:
        with patch("pathlib.Path.open", side_effect=PermissionError("Read-only file system")):
            with pytest.raises(SystemExit) as exc_info:
                verify_audit_sink()
            assert "FATAL" in str(exc_info.value)
    finally:
        reset_settings()


def test_audit_verify_sink_succeeds_on_stdout(monkeypatch):
    monkeypatch.setenv("AUDIT_OUTPUT_DESTINATION", "stdout")
    reset_settings()
    try:
        # verify_audit_sink should complete without error for stdout
        verify_audit_sink()
    finally:
        reset_settings()
