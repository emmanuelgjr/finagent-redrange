"""Seed-library tests, including the curated incident corpus (the `from_incident_db` moat hook)."""

from __future__ import annotations

from pathlib import Path

from finagent_redrange.attacker.seeds import Seed, SeedLibrary

_ROOT = Path(__file__).resolve().parents[1]

# The techniques the range's scenarios recognise — every incident seed should map to one.
KNOWN_TECHNIQUES = {
    "indirect_prompt_injection",
    "data_poisoning",
    "excessive_agency",
    "system_prompt_leakage",
    "unsafe_output_handling",
    "vector_embedding_weakness",
    "unbounded_consumption",
    "supply_chain",
}


def test_from_incident_db_loads_curated_corpus() -> None:
    seeds = SeedLibrary.from_incident_db().all()
    assert len(seeds) >= 4
    for s in seeds:
        assert isinstance(s, Seed)
        assert s.id and s.technique and s.text
        assert s.source, f"{s.id}: an incident seed must carry a provenance source"
        assert s.technique in KNOWN_TECHNIQUES, f"{s.id}: unknown technique {s.technique!r}"


def test_from_incident_db_accepts_a_custom_path(tmp_path) -> None:
    corpus = tmp_path / "custom.yaml"
    corpus.write_text(
        "- id: x1\n  technique: data_poisoning\n  owasp: [LLM04]\n  source: test\n  text: hello\n",
        encoding="utf-8",
    )
    seeds = SeedLibrary.from_incident_db(corpus).all()
    assert [s.id for s in seeds] == ["x1"]
    assert seeds[0].source == "test"


def test_by_technique_filters_incident_seeds() -> None:
    lib = SeedLibrary.from_incident_db()
    leak = lib.by_technique("system_prompt_leakage")
    assert leak and all(s.technique == "system_prompt_leakage" for s in leak)


def test_incident_seeds_cover_multiple_techniques() -> None:
    techniques = {s.technique for s in SeedLibrary.from_incident_db().all()}
    assert len(techniques) >= 4  # a corpus, not a single demo prompt
