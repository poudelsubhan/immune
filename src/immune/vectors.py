"""Attack-signature vector store, backed by Actian VectorAI DB.

Embed every attack on arrival; before full synthesis, similarity-search this
store. A near neighbor with an existing antibody means "we've seen a cousin
of this" — mutated variants get blocked without a fresh synthesis cycle.

VectorAI DB is self-hosted (Docker, no account/API key — see
docs/sponsor-notes.md) and does real storage and nearest-neighbor search
over whatever vectors we hand it — that part is genuinely live. No vector
database generates its own embeddings, though; that's always a separate
concern. Ours are real OpenAI embeddings (text-embedding-3-small) — cheap,
genuinely semantic, and able to tell "recipient hijack" from "amount
inflation" apart even when both are styled as near-identical invoice
emails, which a hand-rolled lexical embedding could not do. Falls back to
an in-memory cosine-similarity index if the local Actian instance is
unreachable, so a Docker hiccup never stalls the loop.
"""

from __future__ import annotations

import hashlib
import math
import os
from typing import Any

import requests

from .cache import disk_cache

DIMENSION = 512  # text-embedding-3-small supports shortening via `dimensions`
COLLECTION = "attack_signatures"
OPENAI_EMBEDDINGS_URL = "https://api.openai.com/v1/embeddings"

_fallback_index: dict[str, tuple[list[float], dict[str, Any]]] = {}  # attack_id -> (vector, payload)


@disk_cache
def _embed_via_openai(text: str) -> list[float]:
    api_key = os.environ["OPENAI_API_KEY"]
    resp = requests.post(
        OPENAI_EMBEDDINGS_URL,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": "text-embedding-3-small", "input": text, "dimensions": DIMENSION},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["data"][0]["embedding"]


def _fallback_embed(text: str) -> list[float]:
    """Only used if OPENAI_API_KEY is unset or the API call fails — a crude
    hashed bag-of-words, purely to keep the loop alive, not to discriminate
    well. See docs/sponsor-notes.md for why this is a known limitation.
    """
    vec = [0.0] * DIMENSION
    for word in text.lower().split():
        idx = int(hashlib.sha256(word.encode("utf-8")).hexdigest(), 16) % DIMENSION
        vec[idx] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def embed_text(text: str) -> list[float]:
    if os.environ.get("OPENAI_API_KEY"):
        try:
            return _embed_via_openai(text)
        except Exception:
            pass  # never let an embedding-provider outage stall the loop
    return _fallback_embed(text)


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

    def reset(self) -> None:
        """Drop every stored signature and start the collection empty.

        The collection lives in the Docker volume and persists across runs,
        while search() only ever inspects its top_k hits. Vectors left behind
        by earlier runs therefore crowd out the neighbor a fresh run actually
        needs, and similarity scores drift from one run to the next — which is
        enough on its own to make a run non-reproducible.
        """
        _fallback_index.clear()
        if not self.live:
            return
        try:
            from actian_vectorai import Distance, VectorParams

            try:
                self._client.collections.delete(COLLECTION)
            except Exception:
                pass  # nothing to drop, or this build exposes no delete
            self._client.collections.create(
                COLLECTION, vectors_config=VectorParams(size=DIMENSION, distance=Distance.Cosine)
            )
        except Exception:
            self.live = False

    def health(self) -> dict[str, Any]:
        if self.live:
            try:
                return self._client.health_check()
            except Exception:
                self.live = False
        return {"title": "in-memory fallback", "version": "n/a"}
