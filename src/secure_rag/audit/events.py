from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secure_rag.settings import get_settings

logger = logging.getLogger("secure_rag.audit")


def emit(event_type: str, *, user_id: str = "", document_id: str = "", tenant_id: str = "", extra: dict[str, Any] | None = None) -> None:
    settings = get_settings()
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "user_id": user_id,
        "document_id": document_id,
        "tenant_id": tenant_id,
        **(extra or {}),
    }
    path = Path(settings.audit_log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    logger.info("audit %s user=%s doc=%s", event_type, user_id, document_id)
