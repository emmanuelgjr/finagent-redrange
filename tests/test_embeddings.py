"""Tests for the deterministic embedding-based retrieval — the real (offline) vector store.

These prove retrieval ranks by semantic/subword similarity (not keyword overlap or corpus size),
which is what makes the vector/embedding-weakness scenario a genuine LLM08 demonstration, and that
the access-scoped-retrieval control still drops a foreign chunk even when similarity ranks it first.
"""

from __future__ import annotations

from finagent_redrange.target.agent import KnowledgeStore
from finagent_redrange.target.embeddings import cosine, embed
from finagent_redrange.target.guardrails import Guardrails
from finagent_redrange.target.tools import Session


def test_embed_is_deterministic() -> None:
    # A process-stable hash (not the salted built-in) — the same text always embeds identically.
    assert embed("recovery passphrase") == embed("recovery passphrase")


def test_cosine_ranks_semantic_overlap_higher() -> None:
    q = embed("identity verification for account recovery")
    related = embed("recovery passphrase and identity verification desk")
    unrelated = embed("branch opening hours on public holidays")
    assert cosine(q, related) > cosine(q, unrelated)


def test_retrieval_surfaces_similar_chunk_over_distractors() -> None:
    """With a corpus larger than k, the relevant chunk is returned because it RANKS highest —
    not because k >= corpus. This is the property the LLM08 scenario now depends on."""
    store = KnowledgeStore()
    store.inject("Branch hours: open 9 to 5 on weekdays.", source="a.md", trusted=True)
    store.inject("Card replacement takes 5-7 days via the app.", source="b.md", trusted=True)
    store.inject(
        "Mortgage rates and a repayment calculator are online.", source="c.md", trusted=True
    )
    store.inject(
        "Recovery passphrase and identity verification handled by the desk.",
        source="d.md",
        trusted=True,
    )
    top = store.retrieve("help with my recovery passphrase and identity verification", k=1)
    assert [c.source for c in top] == ["d.md"]


def test_access_control_drops_foreign_chunk_even_when_top_ranked() -> None:
    store = KnowledgeStore()
    store.inject("Public: branch hours.", source="pub.md", trusted=True)
    store.inject(
        "Recovery passphrase MOON for carol.", source="carol.md", trusted=True, audience="carol"
    )
    session = Session(user="alice", account_id="ACC-1001")
    top = store.retrieve("recovery passphrase", k=2)
    assert any(c.source == "carol.md" for c in top)  # the store WOULD surface it (ranks in)
    kept = Guardrails(enabled=True).check_retrieved(top, store, session)
    assert all(c.source != "carol.md" for c in kept)  # ...but access-scoped retrieval drops it
