from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: Literal["test", "development", "production"] = "development"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    # Comma-separated origins for the embeddable widget. Use * only in development.
    cors_origins: str = "*"

    widget_enabled: bool = True
    widget_site_key: str = ""
    widget_user_id: str = "site-bot"
    widget_tenant_id: str = "default"
    widget_title: str = "Assistant"
    widget_welcome: str = "Ask a question about the knowledge base."

    jwt_secret: str = Field(default="change-me-to-a-long-random-secret")
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "authinject-rag"
    jwt_audience: str = "authinject-rag-api"
    jwt_expire_minutes: int = 480

    spicedb_endpoint: str = "localhost:50051"
    spicedb_preshared_key: str = "foobar"
    spicedb_fail_closed: bool = True

    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: str = ""
    qdrant_collection: str = "authinject_chunks"
    qdrant_in_memory: bool = False

    llm_base_url: str = "http://127.0.0.1:8000/v1"
    llm_api_key: str = "EMPTY"
    llm_model: str = "deepseek-chat"
    llm_temperature: float = 0.0
    llm_fail_closed: bool = True

    embed_backend: Literal["gemini", "hash"] = "gemini"
    google_api_key: str = ""
    embed_model: str = "models/gemini-embedding-001"
    embed_dim: int = 768

    enable_indirect_injection_scan: bool = True
    enable_context_isolation: bool = True
    enable_datamarking: bool = True
    enable_llm_injection_scan: bool = True
    enable_action_authz: bool = True
    enable_task_alignment: bool = False
    max_agent_steps: int = 2
    max_llm_calls: int = 12

    presidio_custom_deny_list: str = ""
    presidio_custom_patterns: str = ""
    # Empty means the direct-identifier default set in secure_rag.retrieval.pii.
    pii_entities: str = ""
    # 0.35 keeps common phone-number formats (scored 0.4) while dropping the
    # sub-0.1 noise that broad recognizers emit on digit strings.
    pii_score_threshold: float = 0.35

    audit_log_path: str = "logs/audit.jsonl"

    @property
    def allow_simulator(self) -> bool:
        return self.app_env == "test"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings() -> None:
    get_settings.cache_clear()
