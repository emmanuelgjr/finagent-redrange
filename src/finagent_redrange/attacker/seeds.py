"""Attack seed library.

Seeds are short, technique-tagged starting points that scenarios and (later) the autonomous
engine compose into full campaigns. v0.1 loads them from data/seeds.yaml.

The differentiator hook: `from_incident_db()` is where you wire in your external GenAI/agentic
incident dataset so real-world incidents become the attacker's knowledge base. Keep that
integration behind this interface so the rest of the code doesn't care about the source.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class Seed:
    id: str
    technique: str  # e.g. "indirect_prompt_injection"
    owasp: list[str]
    text: str  # the seed payload / instruction (targets the mock agent only)


class SeedLibrary:
    def __init__(self, seeds: list[Seed]) -> None:
        self._seeds = seeds

    @classmethod
    def from_yaml(cls, path: Path) -> SeedLibrary:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        return cls([Seed(**s) for s in raw])

    def all(self) -> list[Seed]:
        return list(self._seeds)

    @classmethod
    def from_incident_db(cls, **kwargs) -> SeedLibrary:
        """Build seeds from an external incident dataset.

        TODO(you): adapt your incident records -> Seed objects here (map each incident's
        technique + minimal repro to a Seed). This is the moat: the attacker is seeded by a
        curated corpus of real GenAI/agentic incidents rather than a handful of demo prompts.
        """
        raise NotImplementedError("wire your incident dataset adapter here")

    def by_technique(self, technique: str) -> list[Seed]:
        return [s for s in self._seeds if s.technique == technique]
