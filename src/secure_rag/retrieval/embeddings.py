from __future__ import annotations

import hashlib
from typing import Protocol

from secure_rag.settings import Settings, get_settings


class Embedder(Protocol):
    dim: int

    def embed(self, texts: list[str], task: str = "retrieval_document") -> list[list[float]]: ...


class HashEmbedder:
    """Deterministic offline embeddings for tests and CI."""

    def __init__(self, dim: int = 768) -> None:
        self.dim = dim

    def embed(self, texts: list[str], task: str = "retrieval_document") -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            vec = [0.0] * self.dim
            for token in text.lower().split():
                digest = hashlib.sha256(token.encode("utf-8")).digest()
                idx = int.from_bytes(digest[:4], "little") % self.dim
                vec[idx] += 1.0
            if not any(vec):
                digest = hashlib.sha256(f"{task}:{text}".encode("utf-8")).digest()
                raw = (digest * ((self.dim // len(digest)) + 1))[: self.dim]
                vec = [((b / 255.0) * 2) - 1 for b in raw]
            norm = sum(v * v for v in vec) ** 0.5 or 1.0
            vectors.append([v / norm for v in vec])
        return vectors


class GeminiEmbedder:
    def __init__(self, settings: Settings) -> None:
        import google.generativeai as genai

        if not settings.google_api_key:
            raise RuntimeError("GOOGLE_API_KEY is required when EMBED_BACKEND=gemini")
        genai.configure(api_key=settings.google_api_key)
        self._genai = genai
        self.model = settings.embed_model if settings.embed_model.startswith("models/") else f"models/{settings.embed_model}"
        self.dim = settings.embed_dim

    def embed(self, texts: list[str], task: str = "retrieval_document") -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            response = self._genai.embed_content(
                model=self.model,
                content=text,
                task_type="retrieval_query" if task == "retrieval_query" else "retrieval_document",
                output_dimensionality=self.dim,
            )
            vectors.append(response["embedding"])
        return vectors


def get_embedder(settings: Settings | None = None) -> Embedder:
    settings = settings or get_settings()
    if settings.embed_backend == "hash" or settings.app_env == "test":
        return HashEmbedder(settings.embed_dim)
    return GeminiEmbedder(settings)
