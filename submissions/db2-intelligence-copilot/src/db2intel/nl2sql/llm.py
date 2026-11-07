"""LLM providers for SQL generation. None of them needs a paid API key.

  NoLLM      no model configured: generation is unavailable and /ask answers NO_SQL
  OllamaLLM  local Ollama /api/chat (temperature 0). The base URL must be a loopback address
             unless DB2INTEL_LLM_ALLOW_REMOTE is set, because prompts contain schema descriptions.
  StaticLLM  fixed or scripted answers, for tests and offline demos; cannot be selected from
             the environment.

Every provider returns text only. Whatever it returns is untrusted: the pipeline extracts at
most one statement and the SQL guard decides; generated SQL is never executed or prepared.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Callable, Sequence

from db2intel.config import LlmSettings

MAX_RESPONSE_CHARS = 32_000


class LLMError(RuntimeError):
    """The model failed or answered with something unusable."""


class LLMUnavailable(LLMError):
    """No model is configured."""


class LLMProvider(ABC):
    name = "abstract"

    @property
    def model_id(self) -> str:
        return self.name

    @abstractmethod
    def _generate(self, system: str, user: str) -> str: ...

    def generate(self, system: str, user: str) -> str:
        text = self._generate(system, user)
        if not isinstance(text, str):
            raise LLMError("the model returned no text")
        if len(text) > MAX_RESPONSE_CHARS:
            raise LLMError(f"the model returned more than {MAX_RESPONSE_CHARS} characters")
        return text


class NoLLM(LLMProvider):
    name = "none"

    def _generate(self, system: str, user: str) -> str:
        raise LLMUnavailable("no LLM is configured (LLM_PROVIDER=none); SQL generation is unavailable")


class StaticLLM(LLMProvider):
    """Returns scripted answers in order (the last one repeats), or calls a function."""

    name = "static"

    def __init__(self, responses: str | Sequence[str] | Callable[[str, str], str]):
        if callable(responses):
            self._fn, self._responses = responses, []
        else:
            self._fn = None
            self._responses = [responses] if isinstance(responses, str) else list(responses)
        if self._fn is None and not self._responses:
            raise ValueError("StaticLLM needs at least one response")
        self.calls: list[tuple[str, str]] = []

    def _generate(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if self._fn is not None:
            return self._fn(system, user)
        return self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]


Transport = Callable[[str, dict, int], dict]


def _http_post_json(url: str, payload: dict, timeout: int) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_CHARS * 4 + 1)
    except urllib.error.HTTPError as exc:
        raise LLMError(f"HTTP {exc.code} from the local model server") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LLMError(f"cannot reach the local model server ({type(exc).__name__})") from None
    if len(raw) > MAX_RESPONSE_CHARS * 4:
        raise LLMError("the model server response is too large")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise LLMError("the model server returned invalid JSON") from None


class OllamaLLM(LLMProvider):
    name = "ollama"

    def __init__(self, model: str, base_url: str, timeout: int = 120, transport: Transport = _http_post_json):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._transport = transport

    @property
    def model_id(self) -> str:
        return f"ollama/{self.model}"

    def _generate(self, system: str, user: str) -> str:
        data = self._transport(f"{self.base_url}/api/chat", {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "options": {"temperature": 0},
        }, self.timeout)
        message = data.get("message") if isinstance(data, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise LLMError("unexpected response from the local model server")
        return content


def create_llm(settings: LlmSettings, transport: Transport | None = None) -> LLMProvider:
    settings.validate()
    if settings.provider == "none":
        return NoLLM()
    kwargs = {"transport": transport} if transport else {}
    return OllamaLLM(settings.model, settings.base_url, settings.timeout_seconds, **kwargs)
