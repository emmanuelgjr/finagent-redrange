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

#: Repo-root data directory holding the seed corpora (works in the editable install).
_DATA_DIR = Path(__file__).resolve().parents[3] / "data"


@dataclass
class Seed:
    id: str
    technique: str  # e.g. "indirect_prompt_injection"
    owasp: list[str]
    text: str  # the seed payload / instruction (targets the mock agent only)
    source: str = ""  # provenance (e.g. the public incident/technique class it models)


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
    def from_incident_db(cls, path: Path | None = None) -> SeedLibrary:
        """Build seeds from a curated incident corpus (``data/incidents.yaml`` by default).

        The bundled corpus is **public and category-level**: each seed models a publicly documented
        technique class (OWASP LLM / MITRE ATLAS) and targets ONLY the bundled mock agent + its
        synthetic accounts — it is *not* proprietary incident data. This is the moat hook: point
        ``path`` at (or override this method to adapt) your own incident dataset so real-world
        GenAI/agentic incidents become the attacker's knowledge base. The rest of the code depends
        only on the ``Seed`` interface, so the source is swappable without touching the engine.
        """
        src = path or (_DATA_DIR / "incidents.yaml")
        raw = yaml.safe_load(src.read_text(encoding="utf-8")) or []
        return cls([Seed(**s) for s in raw])

    def by_technique(self, technique: str) -> list[Seed]:
        return [s for s in self._seeds if s.technique == technique]
