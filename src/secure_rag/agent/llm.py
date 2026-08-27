from __future__ import annotations

import logging
from dataclasses import dataclass

from langchain_openai import ChatOpenAI

from secure_rag.settings import Settings, get_settings

logger = logging.getLogger("secure_rag.llm")


class LLMError(RuntimeError):
    pass


@dataclass
class LLMBudget:
    used: int = 0
    maximum: int = 12

    def consume(self) -> None:
        self.used += 1
        if self.used > self.maximum:
            raise LLMError("LLM call budget exceeded")


def chat_llm(settings: Settings | None = None) -> ChatOpenAI:
    settings = settings or get_settings()
    return ChatOpenAI(
        api_key=settings.llm_api_key or "EMPTY",
        base_url=settings.llm_base_url.rstrip("/"),
        model=settings.llm_model,
        temperature=settings.llm_temperature,
    )


def invoke_text(prompt: str, budget: LLMBudget | None = None, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    if budget:
        budget.consume()
    try:
        message = chat_llm(settings).invoke(prompt)
        return str(getattr(message, "content", message)).strip()
    except Exception as exc:
        if settings.llm_fail_closed:
            raise LLMError("LLM invocation failed") from exc
        logger.warning("LLM failed open: %s", exc)
        return ""
