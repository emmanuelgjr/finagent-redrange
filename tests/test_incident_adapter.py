"""Incident-corpus adapter tests.

The mapping is unit-tested with fake incident dicts (no genai-incidents dependency), so CI covers
it deterministically. The end-to-end query against the real corpus runs only where the [incidents]
extra is installed. The load-bearing property is SCOPE SAFETY: a real incident's own text is never
copied into a seed payload — the payload is always a synthetic mock-agent template.
"""

from __future__ import annotations

import importlib.util
from collections import Counter

import pytest

from finagent_redrange.attacker.incident_adapter import (
    _OWASP_TO_TECHNIQUE,
    _TEMPLATES,
    incident_to_seed,
    seeds_from_incidents,
)


def _inc(inc_id, owasp, *, severity="High", tier="reviewed", cve=None, description="DO-NOT-LEAK"):
    return {
        "id": inc_id,
        "owasp_llm": owasp,
        "severity": severity,
        "quality_tier": tier,
        "cve_ids": cve or [],
        "title": "example incident",
        "primary_reference": "https://example.com/incident",
        "attack_vector": "prompt-injection",
        "description": description,
    }


def test_incident_maps_to_technique_with_provenance() -> None:
    seed = incident_to_seed(_inc("INC-1", ["LLM04"]))
    assert seed is not None
    assert seed.technique == "data_poisoning"
    assert seed.id == "gi-INC-1"
    assert seed.owasp == ["LLM04"]
    assert "INC-1" in seed.source and "https://example.com/incident" in seed.source


def test_payload_is_synthetic_never_the_incident_text() -> None:
    """SCOPE SAFETY: the seed payload is a template, and the incident's own text never appears."""
    seed = incident_to_seed(_inc("INC-9", ["LLM07"], description="REAL-INCIDENT-SECRET-PAYLOAD"))
    assert seed is not None
    assert seed.text == _TEMPLATES["system_prompt_leakage"]
    assert "REAL-INCIDENT-SECRET-PAYLOAD" not in seed.text


def test_unmappable_incident_is_dropped() -> None:
    assert incident_to_seed(_inc("INC-2", ["LLM09"])) is None  # impact-only code, not a technique
    assert incident_to_seed(_inc("INC-3", [])) is None


def test_first_mappable_owasp_code_wins() -> None:
    seed = incident_to_seed(_inc("INC-4", ["LLM02", "LLM06"]))  # LLM02 unmapped, LLM06 maps
    assert seed is not None
    assert seed.technique == "excessive_agency"


def test_prioritized_and_capped_per_technique() -> None:
    incidents = [
        _inc("low", ["LLM04"], severity="Low"),
        _inc("crit", ["LLM04"], severity="Critical"),
        _inc("med", ["LLM04"], severity="Medium"),
    ]
    seeds = seeds_from_incidents(incidents, limit_per_technique=2)
    assert [s.id for s in seeds] == ["gi-crit", "gi-med"]  # severest first, Low dropped by the cap


def test_technique_filter() -> None:
    incidents = [_inc("a", ["LLM04"]), _inc("b", ["LLM06"])]
    seeds = seeds_from_incidents(incidents, techniques=["data_poisoning"])
    assert {s.technique for s in seeds} == {"data_poisoning"}


def test_no_incident_text_leaks_into_any_seed() -> None:
    incidents = [
        _inc("a", ["LLM04"], description="LEAK-A"),
        _inc("b", ["LLM07"], description="LEAK-B"),
    ]
    seeds = seeds_from_incidents(incidents)
    templates = set(_TEMPLATES.values())
    for s in seeds:
        assert s.text in templates
        assert "LEAK-A" not in s.text and "LEAK-B" not in s.text


# --- opt-in end-to-end against the real corpus (needs the [incidents] extra) ----------------

_HAS_GENAI_INCIDENTS = importlib.util.find_spec("genai_incidents") is not None


@pytest.mark.skipif(not _HAS_GENAI_INCIDENTS, reason="genai-incidents extra not installed")
def test_load_seeds_from_real_corpus() -> None:
    from finagent_redrange.attacker.seeds import SeedLibrary

    seeds = SeedLibrary.from_genai_incidents(limit_per_technique=3).all()
    assert seeds, "expected non-empty seeds from the real corpus"
    known_techniques = set(_OWASP_TO_TECHNIQUE.values())
    templates = set(_TEMPLATES.values())
    for s in seeds:
        assert s.id.startswith("gi-")
        assert s.source.startswith("genai-incidents ")
        assert s.technique in known_techniques
        assert s.text in templates  # synthetic payload only — no real incident text
    assert max(Counter(s.technique for s in seeds).values()) <= 3  # cap respected
