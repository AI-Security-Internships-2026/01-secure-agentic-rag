"""Chat CLI for AuthInject-RAG: local agent, or a remote API used as a website backend."""

from __future__ import annotations

import argparse
import sys

from secure_rag.agent.graph import query_rag_system
from secure_rag.api.auth import create_token
from secure_rag.authz.client import get_authz_client
from secure_rag.logging import configure_logging
from secure_rag.retrieval.ingest import ingest_pdf
from secure_rag.retrieval.qdrant_store import get_vector_store
from secure_rag.sdk import AuthInjectClient
from secure_rag.settings import get_settings


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-rag",
        description="Chat with AuthInject-RAG locally or against a deployed API.",
    )
    parser.add_argument("--api", help="API base URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--token", help="Bearer token (remote mode)")
    parser.add_argument("--site-key", help="Website widget site key (remote /chat only)")
    parser.add_argument("--user", default="", help="User id (local mode, or remote /token)")
    parser.add_argument("--tenant", default="", help="Tenant id")
    parser.add_argument("--mode", default="pre", help="filtering mode: pre|post|none")
    parser.add_argument("--once", metavar="QUESTION", help="Ask one question and exit")
    return parser


def _mint_or_prompt(args: argparse.Namespace) -> tuple[str, str, str]:
    user_id = args.user or input("Username: ").strip() or "analyst"
    tenant_id = args.tenant or input("Tenant id [default]: ").strip() or "default"
    token = create_token(user_id, tenant_id)
    return user_id, tenant_id, token


def _print_reply(answer: str) -> None:
    print(f"Assistant: {answer}")


def _run_local(args: argparse.Namespace) -> int:
    settings = get_settings()
    configure_logging(settings.log_level)
    user_id, tenant_id, token = _mint_or_prompt(args)
    print(f"Local session {user_id}@{tenant_id}")
    print(f"Bearer token (for website/API): {token}")
    print("Type a question, or /help  /ingest  /docs  /mode  /quit")
    mode = args.mode
    history: list[dict[str, str]] = []

    def ask(question: str) -> str:
        result = query_rag_system(
            collection_name="",
            query=question if not history else _history_query(question, history),
            user_id=user_id,
            tenant_id=tenant_id,
            filtering_mode=mode,
        )
        return str(result.get("answer", ""))

    if args.once:
        answer = ask(args.once)
        print(answer)
        return 0

    while True:
        try:
            raw = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not raw:
            continue
        if raw in {"/quit", "/exit"}:
            return 0
        if raw == "/help":
            print("Commands: /ingest <pdf>  /docs  /mode pre|post|none  /quit")
            continue
        if raw == "/docs":
            allowed = get_authz_client().lookup_resources("document", "view", "user", user_id)
            print("allowed documents:", allowed)
            print("indexed:", get_vector_store().list_documents(allowed))
            continue
        if raw.startswith("/mode"):
            parts = raw.split(maxsplit=1)
            mode = parts[1].strip() if len(parts) > 1 else input("mode [pre|post|none]: ").strip() or mode
            print("mode:", mode)
            continue
        if raw.startswith("/ingest"):
            parts = raw.split(maxsplit=1)
            path = parts[1].strip().strip("\"'") if len(parts) > 1 else input("PDF path: ").strip().strip("\"'")
            viewers = [v.strip() for v in input("viewers comma-separated: ").split(",") if v.strip()]
            print(ingest_pdf(path, owner_id=user_id, tenant_id=tenant_id, viewers=viewers))
            continue
        answer = ask(raw)
        history.append({"role": "user", "content": raw})
        history.append({"role": "assistant", "content": answer})
        history = history[-8:]
        _print_reply(answer)


def _history_query(message: str, history: list[dict[str, str]]) -> str:
    lines = [f"{turn['role']}: {turn['content']}" for turn in history]
    return "Conversation so far:\n" + "\n".join(lines) + f"\nuser: {message}"


def _run_remote(args: argparse.Namespace) -> int:
    token = args.token
    if not token and not args.site_key:
        user_id = args.user or input("Username: ").strip() or "analyst"
        tenant_id = args.tenant or input("Tenant id [default]: ").strip() or "default"
        try:
            import httpx

            response = httpx.post(
                f"{args.api.rstrip('/')}/token",
                json={"user_id": user_id, "tenant_id": tenant_id},
                timeout=15.0,
            )
            response.raise_for_status()
            token = response.json()["access_token"]
            print(f"Minted development token for {user_id}@{tenant_id}")
        except Exception as exc:
            print(f"Could not mint token from {args.api}/token: {exc}", file=sys.stderr)
            return 1
    client = AuthInjectClient(args.api, token=token, site_key=args.site_key)
    history: list[dict[str, str]] = []

    def ask(question: str) -> str:
        body = client.chat(question, history=history, filtering_mode=args.mode)
        return str(body.get("reply", ""))

    if args.once:
        print(ask(args.once))
        return 0

    print(f"Connected to {args.api}")
    print("Type a question, or /quit")
    while True:
        try:
            raw = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not raw:
            continue
        if raw in {"/quit", "/exit"}:
            return 0
        answer = ask(raw)
        history.append({"role": "user", "content": raw})
        history.append({"role": "assistant", "content": answer})
        history = history[-8:]
        _print_reply(answer)


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    code = _run_remote(args) if args.api else _run_local(args)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
