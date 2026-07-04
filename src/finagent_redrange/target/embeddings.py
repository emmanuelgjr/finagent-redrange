"""A tiny, deterministic, dependency-free text embedding for the RAG store.

The range needs a *real* similarity-search retriever (so the vector/embedding-weakness scenario
demonstrates a genuine embedding store, not keyword overlap) that is also offline and reproducible
in CI. This is a bag-of-character-trigrams hashing embedding — the same subword-hashing idea
fastText uses — projected into a fixed-width vector and L2-normalized, with cosine similarity for
ranking. No model download, no network, no dependency.

Determinism matters: Python's built-in ``hash()`` is per-process salted (PYTHONHASHSEED), which
would make retrieval order vary between runs. We hash trigrams with blake2b instead, so the same
text always embeds to the same vector.
"""

from __future__ import annotations

import hashlib
import math

#: Embedding width. Small enough to be cheap over the sandbox corpus, wide enough that unrelated
#: trigrams rarely collide.
EMBED_DIM = 512


def _stable_hash(token: str) -> int:
    """A process-stable hash (blake2b), unlike the salted built-in ``hash()``."""
    return int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big")


def embed(text: str) -> list[float]:
    """Return the L2-normalized bag-of-character-trigrams vector for ``text``.

    Trigrams capture subword overlap (so "verification" and "verify" share features) without any
    tokenizer or vocabulary. The vector is normalized so a plain dot product is the cosine."""
    vec = [0.0] * EMBED_DIM
    padded = f"  {text.lower().strip()}  "
    for i in range(len(padded) - 2):
        vec[_stable_hash(padded[i : i + 3]) % EMBED_DIM] += 1.0
    norm = math.sqrt(sum(x * x for x in vec))
    return [x / norm for x in vec] if norm else vec


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two vectors (a plain dot product when both are already normalized)."""
    return sum(x * y for x, y in zip(a, b, strict=False))
