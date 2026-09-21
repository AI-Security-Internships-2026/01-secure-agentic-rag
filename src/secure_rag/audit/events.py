import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secure_rag.settings import Settings, get_settings

logger = logging.getLogger("secure_rag.audit")


def verify_audit_sink(settings: Settings | None = None) -> None:
    """Fail-closed startup check: verify file destination is writable if configured."""
    settings = settings or get_settings()
    if settings.audit_output_destination == "file":
        path = Path(settings.audit_log_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                test_record = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "event": "audit.startup.test",
                }
                handle.write(json.dumps(test_record) + "\n")
        except (PermissionError, OSError) as exc:
            logger.critical("FATAL: audit log destination '%s' is not writable: %s", path, exc)
            raise SystemExit(f"FATAL: audit log destination '{path}' is not writable: {exc}") from exc


def emit(
    event_type: str,
    *,
    user_id: str = "",
    document_id: str = "",
    tenant_id: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    settings = get_settings()
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "user_id": user_id,
        "document_id": document_id,
        "tenant_id": tenant_id,
        **(extra or {}),
    }
    line = json.dumps(record)
    if settings.audit_output_destination == "stdout":
        sys.stdout.write(f"[AUDIT] {line}\n")
        sys.stdout.flush()
    else:
        path = Path(settings.audit_log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    logger.info("audit %s user=%s doc=%s", event_type, user_id, document_id)
