"""Export a regulatory control crosswalk — for AI Security Architects / GRC in financial services.

Maps each validated control to the obligations a European FS risk/compliance function is asked
about: **NIST AI RMF 1.0** (+ the **NIST AI 600-1** Generative AI Profile), **ISO/IEC 42001:2023**
(Annex A control themes), and the **EU AI Act** (article references). It complements the GSN
assurance case: the assurance case argues *effectiveness* over the range's own evidence; this
crosswalk maps that evidence onto the *regulatory frameworks* a board or auditor cites.

HONESTY IS THE POINT. Only the NIST AI RMF subcategories already carried on the scenarios (and
verified against the published standard) are labeled ``basis: declared``. Every ISO 42001 / EU AI
Act / GenAI-Profile mapping is labeled ``basis: interpretive`` — a self-authored, category-level
suggestion, not a certified conformity assessment and not legal advice. Mappings are kept at the
control-theme / article level (never reproducing copyrighted standard text) and each carries the
verified EU AI Act timeline. The precision gate (tests/test_export_compliance.py) checks
*completeness* (no scenario unmapped) and *provenance* (no interpretive mapping masquerades as
authoritative), not legal accuracy — which no automated check can assert.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from finagent_redrange.types import Finding

NIST_RMF = "NIST AI RMF 1.0"
NIST_GENAI = "NIST AI 600-1 (GenAI Profile)"
ISO_42001 = "ISO/IEC 42001:2023"
EU_AI_ACT = "EU AI Act"

#: Verified EU AI Act timeline (carried into the artifact so a reader can't misread the dates).
EU_AI_ACT_TIMELINE = (
    "EU AI Act: general-purpose AI (GPAI) provider obligations have applied since 2 Aug 2025; the "
    "AI Office's enforcement powers and penalties apply from 2 Aug 2026, alongside most high-risk "
    "system obligations (certain product-safety high-risk cases run to 2 Aug 2027). Article "
    "references below are interpretive, at the obligation level."
)

DISCLAIMER = (
    "Interpretive control crosswalk — NOT legal advice and NOT a certified conformity assessment. "
    "Only NIST AI RMF subcategories carried on the scenarios (verified against the published "
    "standard) are 'declared'; ISO/IEC 42001, EU AI Act, and GenAI-Profile rows are self-authored, "
    "category-level suggestions. Verify against the current published standard text before use."
)

#: Obligations that apply to every scenario (logging, risk management, security baseline).
_CROSS_CUTTING: list[tuple[str, str]] = [
    (EU_AI_ACT, "Art. 9 (risk management system)"),
    (EU_AI_ACT, "Art. 12 (record-keeping / logging)"),
    (EU_AI_ACT, "Art. 15 (accuracy, robustness & cybersecurity)"),
    (ISO_42001, "A.5 (assessing impacts of AI systems)"),
    (ISO_42001, "A.6 (AI system life cycle)"),
    (NIST_GENAI, "GenAI Profile: Information Security"),
]

#: Scenario-specific interpretive mappings (in addition to the cross-cutting set above).
_PER_SCENARIO: dict[str, list[tuple[str, str]]] = {
    "indirect_prompt_injection": [
        (EU_AI_ACT, "Art. 10 (data & data governance)"),
        (ISO_42001, "A.7 (data for AI systems)"),
        (NIST_GENAI, "GenAI Profile: Data Privacy"),
    ],
    "data_poisoning": [
        (EU_AI_ACT, "Art. 10 (data & data governance)"),
        (ISO_42001, "A.7 (data for AI systems)"),
        (NIST_GENAI, "GenAI Profile: Information Integrity"),
    ],
    "excessive_agency": [
        (EU_AI_ACT, "Art. 14 (human oversight)"),
        (ISO_42001, "A.9 (use of AI systems)"),
        (NIST_GENAI, "GenAI Profile: Human-AI Configuration"),
    ],
    "system_prompt_leakage": [
        (ISO_42001, "A.6 (AI system life cycle)"),
        (NIST_GENAI, "GenAI Profile: Information Security"),
    ],
    "unsafe_output_handling": [
        (EU_AI_ACT, "Art. 14 (human oversight)"),
        (ISO_42001, "A.9 (use of AI systems)"),
        (NIST_GENAI, "GenAI Profile: Information Integrity"),
    ],
    "vector_embedding_weakness": [
        (EU_AI_ACT, "Art. 10 (data & data governance)"),
        (ISO_42001, "A.7 (data for AI systems)"),
        (NIST_GENAI, "GenAI Profile: Data Privacy"),
    ],
    "unbounded_consumption": [
        (ISO_42001, "A.6 (AI system life cycle)"),
        (NIST_GENAI, "GenAI Profile: Information Security (availability)"),
    ],
    "supply_chain": [
        (EU_AI_ACT, "Art. 25 (responsibilities along the value chain)"),
        (ISO_42001, "A.10 (third-party & customer relationships)"),
        (NIST_GENAI, "GenAI Profile: Value Chain & Component Integration"),
    ],
}


def _mappings_for(finding: Finding) -> list[dict[str, str]]:
    """Build the mapping rows for one scenario, each tagged with its provenance basis.

    De-duplicates on (framework, ref) so a scenario-specific mapping that overlaps a cross-cutting
    one appears once.
    """
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(framework: str, ref: str, basis: str) -> None:
        if (framework, ref) in seen:
            return
        seen.add((framework, ref))
        rows.append({"framework": framework, "ref": ref, "basis": basis})

    # Declared: the NIST AI RMF subcategories already on the (verified) scenario crosswalk.
    for ref in finding.frameworks.nist_ai_rmf:
        add(NIST_RMF, ref, "declared")
    # Interpretive: scenario-specific + cross-cutting suggestions.
    for framework, ref in [*_PER_SCENARIO.get(finding.scenario_id, []), *_CROSS_CUTTING]:
        add(framework, ref, "interpretive")
    return rows


def to_compliance(findings: list[Finding]) -> dict[str, Any]:
    """Build the structured compliance crosswalk from the (controls-off) findings."""
    return {
        "artifact": "regulatory control crosswalk",
        "disclaimer": DISCLAIMER,
        "eu_ai_act_timeline": EU_AI_ACT_TIMELINE,
        "generatedBy": "python -m finagent_redrange run --compliance",
        "scenarios": [
            {
                "scenario_id": f.scenario_id,
                "title": f.title,
                "validating_control": f.validating_control,
                "mappings": _mappings_for(f),
            }
            for f in findings
        ],
    }


def _refs(rows: list[dict[str, str]], framework: str) -> str:
    return "; ".join(r["ref"] for r in rows if r["framework"] == framework) or "—"


def render_markdown(findings: list[Finding]) -> str:
    data = to_compliance(findings)
    lines = [
        "# FinAgent-RedRange — regulatory control crosswalk",
        "",
        f"> **{DISCLAIMER}**",
        "",
        EU_AI_ACT_TIMELINE,
        "",
        "**Basis legend:** `declared` = a verified framework id carried on the scenario; "
        "`interpretive` = a self-authored, category-level suggestion (see disclaimer).",
        "",
        "| Scenario | Validating control | "
        f"{NIST_RMF} | {NIST_GENAI} | {ISO_42001} | {EU_AI_ACT} |",
        "|---|---|---|---|---|---|",
    ]
    for scenario in data["scenarios"]:
        rows = scenario["mappings"]
        lines.append(
            f"| {scenario['title']} | {scenario['validating_control']} | "
            f"{_refs(rows, NIST_RMF)} | {_refs(rows, NIST_GENAI)} | "
            f"{_refs(rows, ISO_42001)} | {_refs(rows, EU_AI_ACT)} |"
        )
    lines += ["", "Regenerated by `python -m finagent_redrange run --compliance`.", ""]
    return "\n".join(lines)


def write_compliance(
    findings_off: list[Finding], findings_on: list[Finding], out_dir: Path
) -> None:
    """Write the regulatory crosswalk (JSON + markdown). Uses the controls-off findings."""
    cdir = out_dir / "compliance"
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "crosswalk.json").write_text(
        json.dumps(to_compliance(findings_off), indent=2), encoding="utf-8"
    )
    (cdir / "crosswalk.md").write_text(render_markdown(findings_off), encoding="utf-8")
