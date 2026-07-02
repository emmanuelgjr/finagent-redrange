"""Export findings as a SARIF 2.1.0 run with the framework crosswalk as taxonomies.

SARIF 2.1.0 (OASIS) is the lingua franca of devsecops findings — GitHub Code Scanning, Azure
DevOps, and DefectDojo ingest it directly. SARIF has no native "AI/agent finding" concept, so each
result maps to a transcript evidence artifact (not scanned source); this is a documented adaptation
importers accept. The OWASP/ATLAS/NIST crosswalk is emitted once as ``run.taxonomies`` so every
framework code is a dereferenceable taxon rather than free text.

Output is deterministic (no timestamps, no random GUIDs; stable ``partialFingerprints``) so it is
diffable and snapshot-testable. The AIRQ composite is clamped to SARIF's required 0.0-10.0 range
and tagged as an illustrative heuristic — never a calibrated score.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from finagent_redrange import __version__
from finagent_redrange.scoring import frameworks
from finagent_redrange.types import Severity

if TYPE_CHECKING:
    from finagent_redrange.types import Finding

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: Taxonomy toolComponents, in a stable order (their position is their index in run.taxonomies).
#: Each is (name, description, predicate over a REFERENCE id).
_TAXONOMIES: list[tuple[str, str, Any]] = [
    ("OWASP-LLM", "OWASP Top 10 for LLM Applications (2025)", lambda i: i.startswith("LLM")),
    (
        "OWASP-Agentic-ThreatsMitigations",
        "OWASP Agentic AI - Threats & Mitigations (T1-T15)",
        lambda i: re.fullmatch(r"T\d+", i) is not None,
    ),
    (
        "OWASP-Agentic-Top10",
        "OWASP Top 10 for Agentic Applications (2026)",
        lambda i: i.startswith("ASI"),
    ),
    ("MITRE-ATLAS", "MITRE ATLAS techniques", lambda i: i.startswith("AML.")),
    (
        "NIST-AI-RMF",
        "NIST AI Risk Management Framework 1.0 (AI 100-1)",
        lambda i: i.split(" ")[0] in {"GOVERN", "MAP", "MEASURE", "MANAGE"},
    ),
]


def _clamp(value: float) -> float:
    return max(0.0, min(10.0, value))


def _pascal(scenario_id: str) -> str:
    return "".join(part.capitalize() for part in scenario_id.split("_"))


def _framework_ids(finding: Finding) -> list[str]:
    """All crosswalk ids for a finding, de-duplicated, order-stable."""
    fw = finding.frameworks
    ordered = [
        *fw.owasp_llm,
        *fw.owasp_agentic,
        *fw.owasp_agentic_top10,
        *fw.mitre_atlas,
        *fw.nist_ai_rmf,
    ]
    seen: dict[str, None] = {}
    for i in ordered:
        seen.setdefault(i, None)
    return list(seen)


def _build_taxonomies() -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Build run.taxonomies from frameworks.REFERENCE and a map id -> taxonomy index."""
    taxonomies: list[dict[str, Any]] = []
    id_to_tax: dict[str, int] = {}
    for index, (name, description, predicate) in enumerate(_TAXONOMIES):
        taxa = []
        for ref_id in sorted(i for i in frameworks.REFERENCE if predicate(i)):
            taxa.append({"id": ref_id, "name": frameworks.label(ref_id)})
            id_to_tax[ref_id] = index
        taxonomies.append(
            {
                "name": name,
                "organization": "FinAgent-RedRange crosswalk",
                "shortDescription": {"text": description},
                "isComprehensive": False,
                "taxa": taxa,
            }
        )
    return taxonomies, id_to_tax


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document. Results are emitted for exploited (succeeded) findings only."""
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    for finding in findings:
        if finding.scenario_id in rule_index:
            continue
        rule_index[finding.scenario_id] = len(rules)
        rules.append(
            {
                "id": finding.scenario_id,
                "name": _pascal(finding.scenario_id),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.mitigation_notes or finding.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(finding.severity, "warning")},
                "properties": {
                    "security-severity": f"{_clamp(finding.airq.composite):.1f}",
                    "airq-band": finding.airq.band.value,
                    "validating-control": finding.validating_control,
                    "note": (
                        "security-severity is derived from the AIRQ analyst heuristic "
                        "(asserted defense-controls sub-score), not a calibrated score."
                    ),
                    "tags": _framework_ids(finding),
                },
            }
        )

    taxonomies, id_to_tax = _build_taxonomies()

    results: list[dict[str, Any]] = []
    for finding in findings:
        if not finding.succeeded:
            continue
        results.append(
            {
                "ruleId": finding.scenario_id,
                "ruleIndex": rule_index[finding.scenario_id],
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {
                    "text": (
                        f"Attack landed with controls OFF; blocked by "
                        f"{finding.validating_control} with controls ON."
                    )
                },
                "partialFingerprints": {"scenarioId/v1": finding.scenario_id},
                "properties": {"security-severity": f"{_clamp(finding.airq.composite):.1f}"},
                "taxa": [
                    {"toolComponent": {"index": id_to_tax[i]}, "id": i}
                    for i in _framework_ids(finding)
                    if i in id_to_tax
                ],
            }
        )

    run = {
        "tool": {
            "driver": {
                "name": "FinAgent-RedRange",
                "informationUri": "https://github.com/emmanuelgjr/finagent-redrange",
                "version": __version__,
                "rules": rules,
            }
        },
        "taxonomies": taxonomies,
        "results": results,
    }
    return {"$schema": _SCHEMA, "version": "2.1.0", "runs": [run]}


def write_sarif(findings_off: list[Finding], findings_on: list[Finding], out_dir: Path) -> None:
    """Write the controls-off (exploited) findings as ``results/findings.sarif``.

    ``findings_on`` is accepted for a uniform exporter signature; SARIF results are the exploited
    controls-off findings (a scanner surfaces open findings, not proofs that a control held).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    doc = to_sarif(findings_off)
    (out_dir / "findings.sarif").write_text(json.dumps(doc, indent=2), encoding="utf-8")
