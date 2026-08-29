from typing import Any

__all__ = [
    "query_rag_system",
    "retrieve_authorized",
    "BLOCKED_INJECTION_MESSAGE",
    "filter_injected_chunks",
    "heuristic_is_indirect_injection",
]


def __getattr__(name: str) -> Any:
    if name in {"query_rag_system", "retrieve_authorized"}:
        from secure_rag.agent.graph import query_rag_system, retrieve_authorized

        return query_rag_system if name == "query_rag_system" else retrieve_authorized
    if name in {"BLOCKED_INJECTION_MESSAGE", "filter_injected_chunks", "heuristic_is_indirect_injection"}:
        from secure_rag.agent import guardrails

        return getattr(guardrails, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
