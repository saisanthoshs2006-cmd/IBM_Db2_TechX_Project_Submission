"""Pluggable embedding providers with strict vector-dimension validation.

Supported now:
  ollama         local Ollama server, default model nomic-embed-text (768 dims). No API key.
  deterministic  offline feature-hashing embedder for tests and environments without Ollama.
Reserved for later (configuration accepted, not yet implemented): openai, watsonx.

Every vector passes validate_vector() before it can be inserted into, or searched
against, a Db2 VECTOR column, so a model/schema mismatch fails fast in Python with
a clear message instead of as a Db2 error.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Callable, Sequence

from db2intel.config import ConfigError, EmbeddingSettings

# Known output sizes. A configured EMBEDDING_DIM that contradicts this table is rejected.
KNOWN_DIMENSIONS: dict[tuple[str, str], int] = {
    ("ollama", "nomic-embed-text"): 768,
    ("ollama", "all-minilm"): 384,
    ("ollama", "mxbai-embed-large"): 1024,
    ("watsonx", "ibm/slate-125m-english-rtrvr"): 768,
    ("watsonx", "ibm/slate-30m-english-rtrvr"): 384,
}
# Models whose output size is selectable via an API parameter.
CONFIGURABLE_DIMENSIONS: dict[tuple[str, str], range] = {
    ("openai", "text-embedding-3-small"): range(1, 1537),
    ("openai", "text-embedding-3-large"): range(1, 3073),
}
MAX_FLOAT32_DIM_4K_PAGE = 980  # Db2 limit for VECTOR(n, FLOAT32) on 4K pages
PLANNED_PROVIDERS = frozenset({"openai", "watsonx"})


class EmbeddingDimensionError(ValueError):
    """A vector or configuration does not match the expected embedding dimension."""


class EmbeddingProviderError(RuntimeError):
    """The embedding backend failed or returned an unusable response."""


def _base_model(model: str) -> str:
    return model.split(":", 1)[0]  # "nomic-embed-text:latest" -> "nomic-embed-text"


def validate_vector(vector: Sequence[float], expected_dim: int) -> list[float]:
    """Return the vector as floats, or raise if its size or values are invalid."""
    if isinstance(vector, (str, bytes)) or not isinstance(vector, Sequence):
        raise EmbeddingDimensionError(f"expected a sequence of floats, got {type(vector).__name__}")
    if len(vector) != expected_dim:
        raise EmbeddingDimensionError(f"vector has {len(vector)} dimensions, expected {expected_dim}")
    values: list[float] = []
    for i, value in enumerate(vector):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise EmbeddingDimensionError(f"element {i} is {type(value).__name__}, not a number")
        f = float(value)
        if not math.isfinite(f):
            raise EmbeddingDimensionError(f"element {i} is not finite ({f})")
        values.append(f)
    if not any(values):
        raise EmbeddingDimensionError("zero vector has no direction; cosine distance is undefined")
    return values


def to_db2_vector_literal(vector: Sequence[float], expected_dim: int) -> str:
    """Validated vector as the string accepted by VECTOR(?, <dim>, FLOAT32)."""
    values = validate_vector(vector, expected_dim)
    return "[" + ",".join(f"{v:.8g}" for v in values) + "]"


class EmbeddingProvider(ABC):
    """Base class. Subclasses implement _embed(); public methods always validate output."""

    provider_name: str = ""

    def __init__(self, model: str, dimension: int):
        self.model = model
        self.dimension = dimension

    @property
    def model_id(self) -> str:
        """Value stored in the EMBEDDING_MODEL column, e.g. 'ollama/nomic-embed-text'."""
        return f"{self.provider_name}/{_base_model(self.model)}"

    @abstractmethod
    def _embed(self, texts: list[str], kind: str) -> list[list[float]]: ...

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return self._run(list(texts), "document")

    def embed_query(self, text: str) -> list[float]:
        return self._run([text], "query")[0]

    def _run(self, texts: list[str], kind: str) -> list[list[float]]:
        if not texts:
            return []
        if any(not isinstance(t, str) or not t.strip() for t in texts):
            raise ValueError("texts must be non-empty strings")
        vectors = self._embed(texts, kind)
        if len(vectors) != len(texts):
            raise EmbeddingProviderError(f"{self.model_id} returned {len(vectors)} vectors for {len(texts)} texts")
        return [validate_vector(v, self.dimension) for v in vectors]


Transport = Callable[[str, dict, int], dict]


def _http_post_json(url: str, payload: dict, timeout: int) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        raise EmbeddingProviderError(f"HTTP {exc.code} from {url}: {body}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise EmbeddingProviderError(f"cannot reach {url}: {exc}") from None


class OllamaEmbeddingProvider(EmbeddingProvider):
    """Ollama /api/embed. nomic-embed-text expects task prefixes for retrieval."""

    provider_name = "ollama"
    _PREFIXES = {"nomic-embed-text": {"document": "search_document: ", "query": "search_query: "}}

    def __init__(self, model: str, dimension: int, base_url: str, timeout: int = 60,
                 transport: Transport = _http_post_json):
        super().__init__(model, dimension)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._transport = transport

    def _embed(self, texts: list[str], kind: str) -> list[list[float]]:
        prefix = self._PREFIXES.get(_base_model(self.model), {}).get(kind, "")
        data = self._transport(
            f"{self.base_url}/api/embed", {"model": self.model, "input": [prefix + t for t in texts]}, self.timeout
        )
        vectors = data.get("embeddings") if isinstance(data, dict) else None
        if not isinstance(vectors, list):
            raise EmbeddingProviderError(f"unexpected Ollama response keys: {sorted(data) if isinstance(data, dict) else type(data)}")
        return vectors


class DeterministicEmbeddingProvider(EmbeddingProvider):
    """Offline, dependency-free embedder: signed feature hashing of words and character trigrams.

    Lexical, not semantic, but stable across runs and machines, so tests and demos work
    without network access or model downloads.
    """

    provider_name = "deterministic"
    _TOKEN_RE = re.compile(r"[a-z0-9]+")

    def __init__(self, dimension: int, model: str = "hash-v1"):
        super().__init__(model, dimension)

    def _features(self, text: str) -> list[str]:
        words = self._TOKEN_RE.findall(text.lower())
        grams = [f"#{w[i:i + 3]}" for w in words for i in range(max(1, len(w) - 2))]
        return words + grams

    def _embed(self, texts: list[str], kind: str) -> list[list[float]]:
        out = []
        for text in texts:
            vec = [0.0] * self.dimension
            for feature in self._features(text) or ["<empty>"]:
                digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
                bucket = int.from_bytes(digest[:4], "big") % self.dimension
                vec[bucket] += 1.0 if digest[4] & 1 else -1.0
            norm = math.sqrt(sum(v * v for v in vec))
            if norm == 0.0:  # all features cancelled out; fall back to a fixed unit direction
                vec[0], norm = 1.0, 1.0
            out.append([v / norm for v in vec])
        return out


def expected_dimension(provider: str, model: str) -> int | None:
    return KNOWN_DIMENSIONS.get((provider, _base_model(model)))


def check_dimension_config(settings: EmbeddingSettings) -> None:
    """Reject configurations whose EMBEDDING_DIM contradicts the model or Db2 limits."""
    dim = settings.dimension
    if not 1 <= dim <= MAX_FLOAT32_DIM_4K_PAGE:
        raise EmbeddingDimensionError(
            f"EMBEDDING_DIM={dim} is outside 1..{MAX_FLOAT32_DIM_4K_PAGE} (Db2 VECTOR FLOAT32 limit on 4K pages)"
        )
    known = expected_dimension(settings.provider, settings.model)
    if known is not None and known != dim:
        raise EmbeddingDimensionError(
            f"{settings.provider}/{settings.model} produces {known}-dimensional vectors but EMBEDDING_DIM={dim}"
        )
    allowed = CONFIGURABLE_DIMENSIONS.get((settings.provider, _base_model(settings.model)))
    if allowed is not None and dim not in allowed:
        raise EmbeddingDimensionError(f"{settings.model} cannot produce {dim} dimensions")


def create_embedding_provider(settings: EmbeddingSettings, transport: Transport | None = None) -> EmbeddingProvider:
    check_dimension_config(settings)
    if settings.provider == "ollama":
        kwargs = {"transport": transport} if transport else {}
        return OllamaEmbeddingProvider(settings.model, settings.dimension, settings.base_url,
                                       settings.timeout_seconds, **kwargs)
    if settings.provider == "deterministic":
        return DeterministicEmbeddingProvider(settings.dimension)
    if settings.provider in PLANNED_PROVIDERS:
        raise ConfigError(
            f"EMBEDDING_PROVIDER={settings.provider} is planned but not implemented yet. "
            "Use 'ollama' (no API key) or 'deterministic' (offline)."
        )
    raise ConfigError(f"unknown EMBEDDING_PROVIDER={settings.provider!r}")
