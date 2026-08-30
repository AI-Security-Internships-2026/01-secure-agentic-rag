from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

import httpx
from langchain_openai import ChatOpenAI

from secure_rag.settings import Settings, get_settings

logger = logging.getLogger("secure_rag.llm")

_REASONING_BLOCK = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
_OPEN_REASONING = re.compile(r"^.*?</think>", re.IGNORECASE | re.DOTALL)


def strip_reasoning(text: str) -> str:
    """Remove reasoning traces emitted by DeepSeek-R1 style models."""
    cleaned = _REASONING_BLOCK.sub("", text)
    if "</think>" in cleaned.lower():
        cleaned = _OPEN_REASONING.sub("", cleaned)
    return cleaned.strip()


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


def _normalize_base_url(url: str) -> str:
    parsed = urlparse(url.rstrip("/"))
    hostname = "127.0.0.1" if parsed.hostname in {"localhost", "::1"} else parsed.hostname
    netloc = parsed.netloc
    if hostname and parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    elif hostname:
        netloc = hostname
    return urlunparse(parsed._replace(netloc=netloc))


def chat_llm(settings: Settings | None = None) -> ChatOpenAI:
    settings = settings or get_settings()
    base_url = _normalize_base_url(settings.llm_base_url)
    logger.info("Using LLM %s at %s", settings.llm_model, base_url)
    return ChatOpenAI(
        api_key=settings.llm_api_key or "EMPTY",
        base_url=base_url,
        model=settings.llm_model,
        temperature=settings.llm_temperature,
        timeout=120,
        max_retries=1,
        http_client=httpx.Client(trust_env=False, timeout=120.0),
    )


def invoke_text(prompt: str, budget: LLMBudget | None = None, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    if budget:
        budget.consume()
    try:
        message = chat_llm(settings).invoke(prompt)
        return strip_reasoning(str(getattr(message, "content", message)))
    except Exception as exc:
        logger.error(
            "LLM call failed against %s model=%s: %s: %s",
            settings.llm_base_url,
            settings.llm_model,
            type(exc).__name__,
            exc,
        )
        if settings.llm_fail_closed:
            raise LLMError(f"LLM invocation failed ({type(exc).__name__}: {exc})") from exc
        return ""
