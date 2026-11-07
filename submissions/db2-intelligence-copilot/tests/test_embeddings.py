import math

import pytest

from db2intel.ai.embeddings import (
    DeterministicEmbeddingProvider,
    EmbeddingDimensionError,
    EmbeddingProviderError,
    OllamaEmbeddingProvider,
    check_dimension_config,
    create_embedding_provider,
    to_db2_vector_literal,
    validate_vector,
)
from db2intel.config import ConfigError, EmbeddingSettings, load_settings

DIM = 768


def settings(**overrides):
    base = dict(provider="ollama", model="nomic-embed-text", dimension=DIM,
                base_url="http://localhost:11434", timeout_seconds=5)
    base.update(overrides)
    return EmbeddingSettings(**base)


# ---- validate_vector ---------------------------------------------------------------
def test_valid_vector_passes():
    assert validate_vector([0.1] * DIM, DIM) == [0.1] * DIM


@pytest.mark.parametrize("vector,match", [
    ([0.1] * 384, "384 dimensions, expected 768"),
    ([0.1] * 769, "769 dimensions"),
    ([0.1] * 767 + [float("nan")], "not finite"),
    ([0.1] * 767 + [float("inf")], "not finite"),
    ([0.1] * 767 + [True], "bool"),
    ([0.1] * 767 + ["0.1"], "str"),
    ([0.0] * DIM, "zero vector"),
    ("not a vector", "sequence"),
])
def test_invalid_vectors_are_rejected(vector, match):
    with pytest.raises(EmbeddingDimensionError, match=match):
        validate_vector(vector, DIM)


def test_db2_literal_format_and_validation():
    literal = to_db2_vector_literal([0.5] * DIM, DIM)
    assert literal.startswith("[0.5,") and literal.endswith("]")
    assert len(literal[1:-1].split(",")) == DIM
    with pytest.raises(EmbeddingDimensionError):
        to_db2_vector_literal([0.5] * 384, DIM)


# ---- configuration -------------------------------------------------------------------
def test_defaults_are_ollama_nomic_768_without_api_keys():
    s = load_settings({})
    assert (s.embedding.provider, s.embedding.model, s.embedding.dimension) == ("ollama", "nomic-embed-text", 768)
    assert isinstance(create_embedding_provider(s.embedding), OllamaEmbeddingProvider)


@pytest.mark.parametrize("overrides,match", [
    ({"dimension": 384}, "produces 768-dimensional"),
    ({"model": "nomic-embed-text:latest", "dimension": 1024}, "outside 1..980"),
    ({"dimension": 0}, "outside"),
    ({"provider": "openai", "model": "text-embedding-3-small", "dimension": 2000}, "outside"),
])
def test_inconsistent_dimension_config_is_rejected(overrides, match):
    with pytest.raises(EmbeddingDimensionError, match=match):
        check_dimension_config(settings(**overrides))


@pytest.mark.parametrize("provider", ["openai", "watsonx"])
def test_hosted_providers_are_reserved_not_required(provider):
    with pytest.raises(ConfigError, match="planned but not implemented"):
        create_embedding_provider(settings(provider=provider, model="any-model"))


def test_unknown_provider_is_rejected():
    with pytest.raises(ConfigError, match="unknown"):
        create_embedding_provider(settings(provider="magic"))


# ---- Ollama provider (fake transport, no network) --------------------------------------
class FakeTransport:
    def __init__(self, dim=DIM, count=None, payload=None):
        self.dim, self.count, self.payload, self.requests = dim, count, payload, []

    def __call__(self, url, body, timeout):
        self.requests.append((url, body, timeout))
        if self.payload is not None:
            return self.payload
        n = self.count if self.count is not None else len(body["input"])
        return {"embeddings": [[0.01 * (i + 1)] * self.dim for i in range(n)]}


def test_ollama_uses_api_embed_and_nomic_task_prefixes():
    transport = FakeTransport()
    provider = create_embedding_provider(settings(), transport=transport)
    docs = provider.embed_documents(["customer table", "order lines"])
    query = provider.embed_query("top customers by revenue")
    assert len(docs) == 2 and all(len(v) == DIM for v in docs) and len(query) == DIM
    (url, body, _), (_, qbody, _) = transport.requests
    assert url == "http://localhost:11434/api/embed" and body["model"] == "nomic-embed-text"
    assert body["input"] == ["search_document: customer table", "search_document: order lines"]
    assert qbody["input"] == ["search_query: top customers by revenue"]
    assert provider.model_id == "ollama/nomic-embed-text"


def test_ollama_wrong_output_dimension_is_caught_before_db2():
    provider = create_embedding_provider(settings(), transport=FakeTransport(dim=384))
    with pytest.raises(EmbeddingDimensionError, match="384 dimensions, expected 768"):
        provider.embed_query("anything")


def test_ollama_wrong_vector_count_is_caught():
    provider = create_embedding_provider(settings(), transport=FakeTransport(count=1))
    with pytest.raises(EmbeddingProviderError, match="1 vectors for 2 texts"):
        provider.embed_documents(["a", "b"])


def test_ollama_unexpected_response_is_caught():
    provider = create_embedding_provider(settings(), transport=FakeTransport(payload={"error": "model not found"}))
    with pytest.raises(EmbeddingProviderError, match="unexpected Ollama response"):
        provider.embed_query("x")


def test_empty_text_is_rejected():
    provider = create_embedding_provider(settings(), transport=FakeTransport())
    with pytest.raises(ValueError):
        provider.embed_documents(["ok", "  "])


# ---- deterministic fallback -------------------------------------------------------------
def cosine(a, b):
    return sum(x * y for x, y in zip(a, b))


def test_deterministic_provider_is_stable_unit_length_and_768():
    p = create_embedding_provider(settings(provider="deterministic", model="hash-v1"))
    a1, a2 = p.embed_query("monthly revenue by region"), DeterministicEmbeddingProvider(DIM).embed_query(
        "monthly revenue by region")
    assert a1 == a2 and len(a1) == DIM
    assert math.isclose(math.sqrt(sum(v * v for v in a1)), 1.0, rel_tol=1e-9)


def test_deterministic_provider_ranks_lexically_related_text_higher():
    p = DeterministicEmbeddingProvider(DIM)
    q = p.embed_query("customer revenue by region")
    related = p.embed_documents(["Customers with region and revenue"])[0]
    unrelated = p.embed_documents(["Migration ledger checksum"])[0]
    assert cosine(q, related) > cosine(q, unrelated)
