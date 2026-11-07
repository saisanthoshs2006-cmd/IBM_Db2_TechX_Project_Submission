"""In-memory semantic index over schema cards (Phase 2C-a: no database reads or writes).

Cards are embedded once with an EmbeddingProvider (Ollama nomic-embed-text, or the offline
deterministic provider) and ranked by cosine similarity. Results are filtered to the schemas of
the requested data source, so a card from another source can never be returned. The Db2 VECTOR
index (DB2INTEL.SCHEMA_EMBEDDING, VECTOR_DISTANCE) replaces this after gate G6.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Sequence

from db2intel.ai.embeddings import EmbeddingProvider
from db2intel.rag.cards import SchemaCard

MAX_TOP_K = 50


@dataclass(frozen=True)
class Hit:
    card: SchemaCard
    score: float


def _norm(vector: Sequence[float]) -> float:
    return math.sqrt(sum(v * v for v in vector))


class InMemoryIndex:
    def __init__(self, provider: EmbeddingProvider, cards: Iterable[SchemaCard]):
        self.provider = provider
        self.cards: tuple[SchemaCard, ...] = tuple(cards)
        if not self.cards:
            raise ValueError("the index needs at least one schema card")
        vectors = provider.embed_documents([c.text for c in self.cards])
        self._vectors = [(v, _norm(v)) for v in vectors]

    @property
    def model_id(self) -> str:
        return self.provider.model_id

    def search(self, query: str, k: int, schemas: Iterable[str]) -> list[Hit]:
        if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= MAX_TOP_K:
            raise ValueError(f"k must be between 1 and {MAX_TOP_K}")
        allowed = {s.upper() for s in schemas}
        q = self.provider.embed_query(query)
        qn = _norm(q)
        hits = []
        for card, (vec, vn) in zip(self.cards, self._vectors):
            if card.schema not in allowed:
                continue
            score = 0.0 if qn == 0 or vn == 0 else sum(a * b for a, b in zip(q, vec)) / (qn * vn)
            hits.append(Hit(card, score))
        hits.sort(key=lambda h: (-h.score, h.card.card_id))
        return hits[:k]
