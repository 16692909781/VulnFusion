"""LLM provider adapters.

DeepSeek exposes an OpenAI-compatible Chat Completions API. The adapter uses
the standard library, and only plans work; tool execution remains behind
VulnFusion's scope and human approval gates.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class ProviderResult:
    content: str
    model: str
    provider: str
    usage: dict[str, Any]


class LLMProviderError(RuntimeError):
    pass


class OpenAICompatibleProvider:
    provider_name = "openai-compatible"

    def __init__(self, api_key: str, base_url: str, model: str, timeout: int = 60) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.1,
        max_tokens: int = 1200,
    ) -> ProviderResult:
        if not self.configured:
            raise LLMProviderError(f"{self.provider_name} API key is not configured")
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "VulnFusion/0.1",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise LLMProviderError(f"{self.provider_name} HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise LLMProviderError(f"{self.provider_name} request failed: {exc}") from exc
        try:
            message = body["choices"][0]["message"]
            content = message.get("content", "") if isinstance(message, dict) else str(message)
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMProviderError(f"{self.provider_name} returned an invalid response") from exc
        return ProviderResult(
            content=str(content or ""),
            model=str(body.get("model", self.model)),
            provider=self.provider_name,
            usage=body.get("usage", {}) if isinstance(body, dict) else {},
        )


class DeepSeekProvider(OpenAICompatibleProvider):
    provider_name = "deepseek"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: int = 60,
    ) -> None:
        super().__init__(
            api_key=api_key or os.getenv("DEEPSEEK_API_KEY", ""),
            base_url=base_url or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            model=model or os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
            timeout=timeout,
        )
