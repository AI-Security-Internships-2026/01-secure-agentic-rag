"""Interactive CLI wrapping the AuthInject-RAG service functions."""

from __future__ import annotations

from secure_rag.agent.graph import query_rag_system
from secure_rag.api.auth import create_token
from secure_rag.authz.client import get_authz_client
from secure_rag.logging import configure_logging
from secure_rag.retrieval.ingest import ingest_pdf
from secure_rag.retrieval.qdrant_store import get_vector_store
from secure_rag.settings import get_settings


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    print("AuthInject-RAG CLI")
    print("Identity is JWT-backed. Development tokens are minted locally; production uses an IdP.")
    user_id = input("Username: ").strip() or "analyst"
    tenant_id = input("Tenant id [default]: ").strip() or "default"
    token = create_token(user_id, tenant_id)
    print(f"Session token minted for {user_id}@{tenant_id}")
    print(f"Authorization header: Bearer {token[:24]}...")

    mode = "pre"
    while True:
        print("\n1) query  2) ingest PDF  3) list docs  4) change mode  5) exit")
        choice = input("> ").strip()
        if choice == "5" or choice.lower() == "exit":
            return
        if choice == "4":
            mode = input("mode [pre|post|none]: ").strip() or "pre"
            continue
        if choice == "3":
            allowed = get_authz_client().lookup_resources("document", "view", "user", user_id)
            print("allowed documents:", allowed)
            print("indexed:", get_vector_store().list_documents(allowed))
            continue
        if choice == "2":
            path = input("PDF path: ").strip().strip("\"'")
            viewers = [v.strip() for v in input("viewers comma-separated: ").split(",") if v.strip()]
            print(ingest_pdf(path, owner_id=user_id, tenant_id=tenant_id, viewers=viewers))
            continue
        query = input("query: ").strip()
        document_id = input("document_id (blank = all authorized): ").strip()
        result = query_rag_system(
            collection_name=document_id,
            query=query,
            user_id=user_id,
            tenant_id=tenant_id,
            filtering_mode=mode,
        )
        print(result["answer"])
        print("diagnostics:", result.get("diagnostics"))


if __name__ == "__main__":
    main()
