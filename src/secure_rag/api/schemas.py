from pydantic import BaseModel, Field


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
