from typing import Literal

from pydantic import BaseModel, Field

FilteringMode = Literal["pre", "post", "research_baseline_none"]


class QueryRequest(BaseModel):
    query: str
    document_id: str = ""
    n_results: int = 5
    filtering_mode: FilteringMode = Field(
        default="pre",
        json_schema_extra={
            "enum": ["pre"],
            "description": "Authorization filtering mode. Only 'pre' is allowed on the production API.",
        },
    )
    enable_indirect_injection_scan: bool = True
    enable_context_isolation: bool = True


class IngestRequest(BaseModel):
    document_id: str
    texts: list[str]
    tenant_id: str = ""
    owner_id: str = ""
    viewers: list[str] = Field(default_factory=list)
    redact_pii: bool = True


class TokenRequest(BaseModel):
    user_id: str
    tenant_id: str = "default"
    roles: list[str] = Field(default_factory=list)
