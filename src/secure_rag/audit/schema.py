"""Typed audit event schema.

Every line carries the envelope fields of ``AuditEventBase``. Security events listed in
``EVENT_MODELS`` are validated strictly (no unknown fields, required fields non-null).
Operational events outside the registry (``document.ingested``, ``query.completed``,
``tool.parse.malformed`` ...) keep the envelope check but accept free-form extras.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator


class AuditEventBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts: datetime
    event: str
    user_id: str = ""
    document_id: str = ""
    tenant_id: str = ""

    @field_validator("ts")
    @classmethod
    def _utc_only(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("audit timestamps must be timezone-aware UTC")
        return value


class GenericAuditEvent(AuditEventBase):
    model_config = ConfigDict(extra="allow")


class AuthTokenMinted(AuditEventBase):
    event: Literal["auth.token.minted"]
    exp: int
    roles: list[str] = Field(default_factory=list)


class AuthTokenFailed(AuditEventBase):
    event: Literal["auth.token.failed"]
    error_reason: str
    jti: str | None = None


class AuthzPermissionDenied(AuditEventBase):
    event: Literal["authz.permission.denied"]
    resource: str
    permission: str
    denied_at_step: Literal["ingest", "query", "revalidate", "tool"]
    reason: str = ""


class SpiceDBTupleWrite(AuditEventBase):
    event: Literal["authz.spicedb_tuple.write"]
    tuples: list[str]
    writer_principal: str


class SpiceDBTupleDelete(AuditEventBase):
    event: Literal["authz.spicedb_tuple.delete"]
    tuples: list[str]
    deleter_principal: str
    reason_code: str


class GuardrailInjectionDetected(AuditEventBase):
    event: Literal["guardrail.injection_detected"]
    chunk_id: str
    detector_type: Literal["regex", "llm_classifier"]
    score: float
    matched_pattern: str


class GuardrailInputFailed(AuditEventBase):
    event: Literal["guardrail.input_failed"]
    guardrail_name: str
    reject_reason: str


class ContextRevalidatedPass(AuditEventBase):
    event: Literal["context.revalidated.pass"]
    chunk_ref: str
    policy_version: int


class ContextRevalidatedDrop(AuditEventBase):
    event: Literal["context.revalidated.drop"]
    chunk_ref: str
    old_policy_version: int | None
    current_policy_version: int
    reason: str


class ToolExecAllowed(AuditEventBase):
    event: Literal["tool.exec.allowed"]
    action: str
    args_hash: str


class ToolExecDenied(AuditEventBase):
    event: Literal["tool.exec.denied"]
    action: str
    args_hash: str
    deny_reason: str


class AuditRotationEvent(AuditEventBase):
    event: Literal["audit.rotation_event"]
    prev_line_hash_chain: str
    next_chain_start: str
    reason: str


SECURITY_EVENT_TYPES = (
    AuthTokenMinted,
    AuthTokenFailed,
    AuthzPermissionDenied,
    SpiceDBTupleWrite,
    SpiceDBTupleDelete,
    GuardrailInjectionDetected,
    GuardrailInputFailed,
    ContextRevalidatedPass,
    ContextRevalidatedDrop,
    ToolExecAllowed,
    ToolExecDenied,
    AuditRotationEvent,
)

EVENT_MODELS: dict[str, type[AuditEventBase]] = {
    model.model_fields["event"].annotation.__args__[0]: model for model in SECURITY_EVENT_TYPES
}

AuditEvent = Annotated[Union[SECURITY_EVENT_TYPES], Field(discriminator="event")]  # noqa: UP007
AUDIT_EVENT_ADAPTER: TypeAdapter = TypeAdapter(AuditEvent)


def validate_record(record: dict) -> AuditEventBase:
    """Validate one audit record (without ``chain_hash``) against its schema."""
    if record.get("event") in EVENT_MODELS:
        return AUDIT_EVENT_ADAPTER.validate_python(record)
    return GenericAuditEvent.model_validate(record)
