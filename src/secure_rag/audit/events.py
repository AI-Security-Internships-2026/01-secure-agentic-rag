"""Audit sink with an HMAC-SHA256 hash chain.

Each line is ``{...payload, "chain_hash": h}`` where
``h = HMAC-SHA256(key=AUDIT_HMAC_SECRET, msg=prev_hash || canonical_json(payload))``.
Every chain segment starts with an ``audit.rotation_event`` line whose ``prev_hash`` is the
genesis value ``sha256("secure_rag_audit_v1" || AUDIT_HMAC_SECRET)``. A segment starts when
a new file is opened (or found empty after external rotation) and once per process on
stdout. ``secure_rag.audit.verify`` replays a log and reports the first tampered line.
"""

import hashlib
import hmac
import json
import logging
import os
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secure_rag.audit.schema import validate_record
from secure_rag.settings import Settings, get_settings

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None

logger = logging.getLogger("secure_rag.audit")

GENESIS_SEED = b"secure_rag_audit_v1"
MIN_HMAC_SECRET_LENGTH = 32
_DEV_HMAC_SECRET = "insecure-development-audit-hmac-secret-do-not-use"
AUDIT_PREFIX = "[AUDIT] "

_lock = threading.Lock()
_stdout_last_hash: str | None = None
_file_last_hash: dict[str, str] = {}


def hmac_secret(settings: Settings | None = None) -> bytes:
    settings = settings or get_settings()
    secret = settings.audit_hmac_secret
    if len(secret) >= MIN_HMAC_SECRET_LENGTH:
        return secret.encode("utf-8")
    if settings.app_env == "production":
        raise SystemExit(f"FATAL: AUDIT_HMAC_SECRET must be at least {MIN_HMAC_SECRET_LENGTH} characters in production")
    return (secret or _DEV_HMAC_SECRET).encode("utf-8")


def genesis_hash(secret: bytes) -> str:
    return hashlib.sha256(GENESIS_SEED + secret).hexdigest()


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def chain_hash(prev_hash: str, payload: dict[str, Any], secret: bytes) -> str:
    message = prev_hash.encode("utf-8") + canonical_json(payload).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def args_hash(arguments: dict[str, Any] | None) -> str:
    return hashlib.sha256(canonical_json(arguments or {}).encode("utf-8")).hexdigest()


def format_tuple(rel: tuple[str, str, str, str, str]) -> str:
    r_type, r_id, relation, s_type, s_id = rel
    return f"{r_type}:{r_id}#{relation}@{s_type}:{s_id}"


def reset_audit_chain() -> None:
    global _stdout_last_hash
    with _lock:
        _stdout_last_hash = None
        _file_last_hash.clear()


def _build_line(prev_hash: str, record: dict[str, Any], secret: bytes) -> tuple[str, str]:
    validate_record(record)
    payload = json.loads(canonical_json({**record, "ts": record["ts"].isoformat()}))
    digest = chain_hash(prev_hash, payload, secret)
    return canonical_json({**payload, "chain_hash": digest}), digest


def _rotation_record(prev_line_hash: str, genesis: str, reason: str) -> dict[str, Any]:
    return {
        "ts": datetime.now(timezone.utc),
        "event": "audit.rotation_event",
        "user_id": "",
        "document_id": "",
        "tenant_id": "",
        "prev_line_hash_chain": prev_line_hash,
        "next_chain_start": genesis,
        "reason": reason,
    }


class _UnchainedTailError(Exception):
    pass


def _last_chain_hash(handle) -> str | None:
    handle.seek(0, 2)
    size = handle.tell()
    if size == 0:
        return None
    handle.seek(max(0, size - 65536))
    tail = handle.read().decode("utf-8", errors="replace").splitlines()
    for raw in reversed(tail):
        if raw.strip():
            try:
                value = json.loads(raw).get("chain_hash")
            except (ValueError, AttributeError):
                value = None
            if not isinstance(value, str):
                raise _UnchainedTailError
            return value
    return None


@contextmanager
def _locked(handle) -> Iterator[None]:
    if fcntl is not None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _write_file(path: Path, record: dict[str, Any], secret: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    key = str(path.resolve())
    genesis = genesis_hash(secret)
    reason = "file_rotated" if key in _file_last_hash else "file_created"
    for _ in range(3):
        with path.open("a+b") as handle, _locked(handle):
            if not path.exists() or os.fstat(handle.fileno()).st_ino != os.stat(path).st_ino:
                continue  # another writer moved the file while we waited for the lock
            # Read the tail under the lock so concurrent writers (workers) extend one chain.
            try:
                prev = _last_chain_hash(handle)
            except _UnchainedTailError:
                # A pre-chain (legacy) or damaged file is kept aside for inspection, never extended.
                aside = path.with_name(f"{path.name}.unchained-{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}")
                path.rename(aside)
                logger.warning("audit log %s has an unchained tail; moved to %s", path, aside)
                reason = "unchained_tail_moved_aside"
                continue
            lines: list[str] = []
            if prev is None:
                rotation = _rotation_record(_file_last_hash.get(key, ""), genesis, reason)
                line, prev = _build_line(genesis, rotation, secret)
                lines.append(line)
            line, prev = _build_line(prev, record, secret)
            lines.append(line)
            handle.write("".join(f"{item}\n" for item in lines).encode("utf-8"))
            handle.flush()
            _file_last_hash[key] = prev
            return
    raise RuntimeError(f"audit log {path} kept changing underneath the writer")


def _write_stdout(record: dict[str, Any], secret: bytes) -> None:
    global _stdout_last_hash
    lines: list[str] = []
    prev = _stdout_last_hash
    if prev is None:
        genesis = genesis_hash(secret)
        line, prev = _build_line(genesis, _rotation_record("", genesis, "process_start"), secret)
        lines.append(line)
    line, prev = _build_line(prev, record, secret)
    lines.append(line)
    sys.stdout.write("".join(f"{AUDIT_PREFIX}{item}\n" for item in lines))
    sys.stdout.flush()
    _stdout_last_hash = prev


def verify_audit_sink(settings: Settings | None = None) -> None:
    """Fail-closed startup check: HMAC secret present in production and file sink writable."""
    settings = settings or get_settings()
    hmac_secret(settings)
    if settings.audit_output_destination == "file":
        path = Path(settings.audit_log_path)
        try:
            emit("audit.startup.test", settings=settings)
        except (PermissionError, OSError, RuntimeError) as exc:
            logger.critical("FATAL: audit log destination '%s' is not writable: %s", path, exc)
            raise SystemExit(f"FATAL: audit log destination '{path}' is not writable: {exc}") from exc


def emit(
    event_type: str,
    *,
    user_id: str = "",
    document_id: str = "",
    tenant_id: str = "",
    extra: dict[str, Any] | None = None,
    settings: Settings | None = None,
) -> None:
    if event_type == "audit.rotation_event":
        raise ValueError("audit.rotation_event is written by the audit sink itself")
    settings = settings or get_settings()
    secret = hmac_secret(settings)
    record = {
        "ts": datetime.now(timezone.utc),
        "event": event_type,
        "user_id": user_id,
        "document_id": document_id,
        "tenant_id": tenant_id,
        **(extra or {}),
    }
    with _lock:
        if settings.audit_output_destination == "stdout":
            _write_stdout(record, secret)
        else:
            _write_file(Path(settings.audit_log_path), record, secret)

    logger.info("audit %s user=%s doc=%s", event_type, user_id, document_id)
