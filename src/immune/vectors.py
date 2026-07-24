"""Attack-signature vector store, backed by Actian VectorAI DB.

Embed every attack on arrival; before full synthesis, similarity-search this
store. A near neighbor with an existing antibody means "we've seen a cousin
of this" — mutated variants get blocked without a fresh synthesis cycle.

VectorAI DB is self-hosted (Docker, no account/API key — see docs/sponsor-notes.md).
Falls back to an in-memory cosine-similarity index over a crude character
n-gram embedding if the local instance is unreachable, so a Docker hiccup
never stalls the loop.
"""

from __future__ import annotations

import hashlib
import math
import os
from collections import Counter
from typing import Any

DIMENSION = 128
COLLECTION = "attack_signatures"

_fallback_index: dict[str, tuple[list[float], dict[str, Any]]] = {}  # attack_id -> (vector, payload)


def embed_text(text: str, dimension: int = DIMENSION) -> list[float]:
    """Crude, dependency-free embedding: hash character trigrams into a
    fixed-size bag-of-features vector, L2-normalized. Good enough to make
    near-duplicate/mutated payloads land close together; not a real semantic
    embedding. Swap for a real embedding model if time allows.
    """
    vec = [0.0] * dimension
    trigrams = [text[i : i + 3] for i in range(max(len(text) - 2, 1))]
    for gram, count in Counter(trigrams).items():
        idx = int(hashlib.sha256(gram.encode("utf-8")).hexdigest(), 16) % dimension
        vec[idx] += count
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


class SignatureStore:
    """3 methods: add, search, health."""

    def __init__(self, host: str = "localhost:6574") -> None:
        self.host = os.environ.get("ACTIAN_HOST", host)
        self._client = None
        self.live = self._connect()

    def _connect(self) -> bool:
        try:
            from actian_vectorai import VectorAIClient, VectorParams, Distance

            client = VectorAIClient(self.host)
            client.connect()
            client.health_check()
            try:
                client.collections.create(COLLECTION, vectors_config=VectorParams(size=DIMENSION, distance=Distance.Cosine))
            except Exception:
                pass  # already exists
            self._client = client
            return True
        except Exception:
            return False

    def add(self, attack_id: str, text: str, payload: dict[str, Any]) -> None:
        vector = embed_text(text)
        if self.live:
            try:
                from actian_vectorai import PointStruct

                numeric_id = int(hashlib.sha256(attack_id.encode("utf-8")).hexdigest(), 16) % (2**63)
                self._client.points.upsert(COLLECTION, [PointStruct(id=numeric_id, vector=vector, payload={**payload, "attack_id": attack_id})])
                return
            except Exception:
                self.live = False
        _fallback_index[attack_id] = (vector, payload)

    def search(self, text: str, top_k: int = 3) -> list[dict[str, Any]]:
        vector = embed_text(text)
        if self.live:
            try:
                results = self._client.points.search(COLLECTION, vector=vector, limit=top_k)
                return [{"attack_id": r.payload.get("attack_id"), "score": r.score, "payload": r.payload} for r in results]
            except Exception:
                self.live = False

        scored = [
            {"attack_id": attack_id, "score": _cosine(vector, v), "payload": payload}
            for attack_id, (v, payload) in _fallback_index.items()
        ]
        scored.sort(key=lambda r: r["score"], reverse=True)
        return scored[:top_k]

    def health(self) -> dict[str, Any]:
        if self.live:
            try:
                return self._client.health_check()
            except Exception:
                self.live = False
        return {"title": "in-memory fallback", "version": "n/a"}
