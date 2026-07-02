"""Export a MITRE ATLAS Navigator layer — a coverage heatmap of the ATLAS techniques the range hits.

Loads in the **MITRE ATLAS Navigator** (https://mitre-atlas.github.io/atlas-navigator/), NOT the
standard enterprise ATT&CK Navigator: ATLAS ``AML.T####`` ids are invalid in the enterprise / mobile
/ ics domains and will not render there. The layer therefore uses ``domain: "atlas-atlas"`` and
``versions: {"layer": "4.3", "navigator": "4.6.4"}`` (no ``attack`` key) — verified against the
official ``mitre-atlas/atlas-navigator-data`` output.

Each technique is scored by how many scenarios exercise it (a coverage frequency); the scenarios are
listed in the technique comment. Mappings are the range's closest-fit ATLAS ids — a coverage view of
what the range demonstrates, not a claim of exhaustive ATLAS coverage.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from finagent_redrange import __version__

if TYPE_CHECKING:
    from finagent_redrange.types import Finding

_DOMAIN = "atlas-atlas"
_VERSIONS = {"layer": "4.3", "navigator": "4.6.4"}
#: Light-to-dark coverage ramp for the scoring gradient.
_GRADIENT_COLORS = ["#deebf7", "#3182bd"]


def _coverage(findings: list[Finding]) -> dict[str, list[str]]:
    """ATLAS technique id -> sorted scenario titles that exercise it."""
    cov: dict[str, set[str]] = {}
    for finding in findings:
        for aml in finding.frameworks.mitre_atlas:
            cov.setdefault(aml, set()).add(finding.title)
    return {aml: sorted(titles) for aml, titles in cov.items()}


def to_layer(findings: list[Finding]) -> dict[str, Any]:
    """Build the ATLAS Navigator layer from the findings' ATLAS crosswalk."""
    cov = _coverage(findings)
    max_count = max((len(t) for t in cov.values()), default=1)
    techniques = [
        {
            "techniqueID": aml,
            "score": len(cov[aml]),
            "comment": "Exercised by: " + "; ".join(cov[aml]),
            "enabled": True,
        }
        for aml in sorted(cov)
    ]
    description = (
        f"MITRE ATLAS techniques exercised by the FinAgent-RedRange scenarios (v{__version__}). "
        "Score = number of scenarios exercising the technique. Load in the MITRE ATLAS Navigator "
        "(mitre-atlas.github.io/atlas-navigator); AML.T#### ids do not render in the enterprise "
        "ATT&CK Navigator. Closest-fit mappings — a coverage view, not exhaustive ATLAS coverage."
    )
    return {
        "name": "FinAgent-RedRange - ATLAS coverage",
        "versions": _VERSIONS,
        "domain": _DOMAIN,
        "description": description,
        "techniques": techniques,
        "gradient": {"colors": _GRADIENT_COLORS, "minValue": 0, "maxValue": max_count},
        "legendItems": [],
        "showTacticRowBackground": False,
        "hideDisabled": False,
        "selectTechniquesAcrossTactics": True,
        "metadata": [
            {"name": "generated-by", "value": "python -m finagent_redrange run --navigator"},
            {"name": "generator-version", "value": __version__},
        ],
    }


def write_navigator(findings_off: list[Finding], findings_on: list[Finding], out_dir: Path) -> None:
    """Write the ATLAS Navigator coverage layer to results/navigator/atlas-coverage.json."""
    ndir = out_dir / "navigator"
    ndir.mkdir(parents=True, exist_ok=True)
    (ndir / "atlas-coverage.json").write_text(
        json.dumps(to_layer(findings_off), indent=2), encoding="utf-8"
    )
