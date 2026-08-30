from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class QueryRequest(BaseModel):
    query: str
    document_id: str = ""
    n_results: int = 5
    filtering_mode: str = "pre"
    enable_indirect_injection_scan: bool = True
    enable_context_isolation: bool = True


class IngestRequest(BaseModel):
    document_id: str
    texts: list[str]
    viewers: list[str] = Field(default_factory=list)
    redact_pii: bool = True


class TokenRequest(BaseModel):
    user_id: str
    tenant_id: str = "default"
    roles: list[str] = Field(default_factory=list)


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=8000)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    document_id: str = ""
    history: list[ChatTurn] = Field(default_factory=list)
    n_results: int = 5
    filtering_mode: str = "pre"

    @field_validator("history")
    @classmethod
    def cap_history(cls, value: list[ChatTurn]) -> list[ChatTurn]:
        return value[-8:]


class ChatResponse(BaseModel):
    reply: str
    blocked: bool = False
    citations: list[str] = Field(default_factory=list)
    diagnostics: dict[str, Any] | None = None
