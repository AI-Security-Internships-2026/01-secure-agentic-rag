"""Small HTTP client for websites and scripts that talk to a running AuthInject-RAG API."""

from __future__ import annotations

from typing import Any

import httpx


class AuthInjectClient:
    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        site_key: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._headers: dict[str, str] = {"content-type": "application/json"}
        if token:
            self._headers["authorization"] = f"Bearer {token}"
        if site_key:
            self._headers["x-site-key"] = site_key

    def chat(
        self,
        message: str,
        *,
        history: list[dict[str, str]] | None = None,
        document_id: str = "",
        n_results: int = 5,
        filtering_mode: str = "pre",
    ) -> dict[str, Any]:
        response = httpx.post(
            f"{self.base_url}/chat",
            headers=self._headers,
            json={
                "message": message,
                "history": history or [],
                "document_id": document_id,
                "n_results": n_results,
                "filtering_mode": filtering_mode,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def ingest(self, document_id: str, texts: list[str], viewers: list[str] | None = None) -> dict[str, Any]:
        response = httpx.post(
            f"{self.base_url}/ingest",
            headers=self._headers,
            json={"document_id": document_id, "texts": texts, "viewers": viewers or []},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()
