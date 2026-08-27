import os

os.environ["APP_ENV"] = "test"
os.environ["EMBED_BACKEND"] = "hash"
os.environ["QDRANT_IN_MEMORY"] = "true"
os.environ["AUDIT_LOG_PATH"] = "logs/test-audit.jsonl"
os.environ["JWT_SECRET"] = "test-secret-please-change"

from secure_rag.settings import reset_settings
from secure_rag.authz.client import reset_authz_client
from secure_rag.retrieval.qdrant_store import reset_vector_store

reset_settings()
reset_authz_client()
reset_vector_store()
