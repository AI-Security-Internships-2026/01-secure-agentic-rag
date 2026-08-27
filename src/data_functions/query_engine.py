"""Compatibility shim for previous import paths."""

from secure_rag.agent.graph import (
    BLOCKED_INJECTION_MESSAGE,
    generate_from_contexts,
    query_rag_system,
    retrieve_authorized,
)
from secure_rag.agent.guardrails import (
    filter_injected_chunks,
    heuristic_is_indirect_injection,
    llm_is_indirect_injection,
)


def retrieve_context(collection_name, query, n_results=5, user_id="analyst", filtering_mode="none"):
    chunks, diagnostics = retrieve_authorized(
        query,
        user_id,
        n_results=n_results,
        filtering_mode=filtering_mode,
        collection_name=collection_name or None,
    )
    return [c.text for c in chunks], diagnostics

__all__ = [
    "BLOCKED_INJECTION_MESSAGE",
    "generate_from_contexts",
    "query_rag_system",
    "retrieve_context",
    "filter_injected_chunks",
    "heuristic_is_indirect_injection",
    "llm_is_indirect_injection",
]
