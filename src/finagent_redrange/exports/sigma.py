"""Export each scenario's DetectionSignature as a portable Sigma detection rule.

Sigma (https://sigmahq.io) is a community open specification (SigmaHQ) — not an OASIS/ISO
standard — that converts to Splunk / Sentinel / Elastic via `pySigma`. There is no standardized
Sigma logsource for LLM/agent telemetry, so these rules declare a self-described logsource
(`product: finagent_redrange, category: llm_agent`); treat it as a convention, not a standard.

Each rule is rendered from the scenario's :class:`~finagent_redrange.types.DetectionSignature`, the
same object the labeled-replay harness evaluates — so the shipped detection is kept provably
equivalent to the validated oracle (see ``tests/test_export_sigma.py``). Alongside the rules we
emit a precision report: a full confusion matrix over the range's own controls-off/controls-on
transcripts. That precision is oracle/translation fidelity over labeled evidence, NOT a real-world
false-positive rate (the corpus has no benign traffic).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from finagent_redrange.exports.detection import RuleScore, confusion_matrix
from finagent_redrange.types import DetectionSignature, Severity

if TYPE_CHECKING:
    from finagent_redrange.types import Finding

#: Fixed namespace so a scenario's rule id is stable across runs (deterministic uuid5). The Sigma
#: spec recommends a random v4 id; we trade that for reproducibility so the artifact is diffable.
_ID_NS = uuid.NAMESPACE_URL

_SIGMA_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "informational",
}


def _rule_id(scenario_id: str) -> str:
    return str(uuid.uuid5(_ID_NS, f"finagent-redrange/sigma/{scenario_id}"))


def _tags(finding: Finding) -> list[str]:
    """Freeform Sigma tags from the framework crosswalk.

    NOTE: Sigma reserves the ``attack.`` namespace for MITRE ATT&CK; MITRE ATLAS has no official
    Sigma namespace, so ATLAS ids use a custom ``atlas.`` prefix (non-standard, documented).
    """
    fw = finding.frameworks
    tags = [f"owasp.{i.lower()}" for i in fw.owasp_llm]
    tags += [f"owasp.agentic.{i.lower()}" for i in fw.owasp_agentic]
    tags += [f"owasp.{i.lower()}" for i in fw.owasp_agentic_top10]
    tags += [f"atlas.{i.lower()}" for i in fw.mitre_atlas]  # custom namespace (not Sigma `attack.`)
    return tags


def _detection_block(sig: DetectionSignature) -> dict[str, Any]:
    """Render the signature into a Sigma `detection:` mapping (selection + condition)."""
    selection: dict[str, Any] = {}
    for fm in sig.selection:
        key = f"{fm.field}|contains" if fm.op == "contains" else fm.field
        selection[key] = fm.value
    block: dict[str, Any] = {"selection": selection}
    if sig.count_over_threshold is not None:
        # Legacy Sigma aggregation. pySigma backend support for `| count()` is limited; the
        # in-repo replay harness evaluates it exactly regardless.
        block["condition"] = f"selection | count() > {sig.count_over_threshold}"
    else:
        block["condition"] = "selection"
    return block


def to_sigma_dict(finding: Finding) -> dict[str, Any]:
    """Build the Sigma rule (as a dict) for one finding. Requires a detection signature."""
    if finding.detection is None:
        raise ValueError(f"{finding.scenario_id}: no detection signature to export")
    return {
        "title": finding.title,
        "id": _rule_id(finding.scenario_id),
        "status": "experimental",
        "description": (
            f"Detects a landed '{finding.title}' attack in a FinAgent-RedRange agent transcript. "
            f"Derived from the scenario oracle; validating control: {finding.validating_control}."
        ),
        "references": ["https://github.com/emmanuelgjr/finagent-redrange"],
        "author": "FinAgent-RedRange (generated)",
        "logsource": {"product": "finagent_redrange", "category": "llm_agent"},
        "detection": _detection_block(finding.detection),
        "fields": [fm.field for fm in finding.detection.selection],
        "falsepositives": [
            "Benign/normal traffic is not represented in the range's synthetic corpus; validate "
            "against real telemetry and tune before production use."
        ],
        "level": _SIGMA_LEVEL.get(finding.severity, "medium"),
        "tags": _tags(finding),
    }


def render_rule(finding: Finding) -> str:
    return yaml.safe_dump(to_sigma_dict(finding), sort_keys=False, allow_unicode=True)


def render_precision_report(findings_off: list[Finding], findings_on: list[Finding]) -> str:
    scores = confusion_matrix(findings_off, findings_on)
    n = len(findings_off) + len(findings_on)
    lines = [
        "# FinAgent-RedRange — Sigma detection precision (labeled-replay)",
        "",
        f"Corpus: {len(findings_off)} scenarios x 2 passes "
        f"(controls-off = exploited, controls-on = blocked) = {n} labeled transcripts.",
        "Each rule is the detector for its own scenario; its single ground-truth positive is that "
        "scenario's controls-off transcript. All other transcripts are negatives.",
        "",
        "| Rule (scenario) | TP | FP | FN | TN | Precision | Recall |",
        "|---|---|---|---|---|---|---|",
    ]
    t_tp = t_fp = t_fn = t_tn = 0
    for s in scores:
        t_tp += s.tp
        t_fp += s.fp
        t_fn += s.fn
        t_tn += s.tn
        lines.append(
            f"| {s.scenario_id} | {s.tp} | {s.fp} | {s.fn} | {s.tn} | "
            f"{s.precision:.2f} | {s.recall:.2f} |"
        )
    overall = RuleScore("overall", t_tp, t_fp, t_fn, t_tn)
    lines.append(
        f"| **Overall** | {t_tp} | {t_fp} | {t_fn} | {t_tn} | "
        f"**{overall.precision:.2f}** | **{overall.recall:.2f}** |"
    )
    lines += [
        "",
        "**Honest scope of this precision.** It measures oracle/translation fidelity over the "
        "range's own labeled evidence: every rule reproduces its scenario's validated oracle "
        "verdict on both the exploited and the blocked transcript, and does not cross-fire on any "
        "other scenario. It is NOT a real-world false-positive rate — the corpus contains no "
        "benign/normal traffic. Validate against production telemetry before deployment.",
        "",
        "Regenerated by `python -m finagent_redrange run --sigma`.",
        "",
    ]
    return "\n".join(lines)


def write_sigma(findings_off: list[Finding], findings_on: list[Finding], out_dir: Path) -> None:
    """Write one Sigma rule per scenario plus the labeled-replay precision report."""
    sigma_dir = out_dir / "sigma"
    sigma_dir.mkdir(parents=True, exist_ok=True)
    for finding in findings_off:
        if finding.detection is None:
            continue
        (sigma_dir / f"{finding.scenario_id}.yml").write_text(
            render_rule(finding), encoding="utf-8"
        )
    (sigma_dir / "precision_report.md").write_text(
        render_precision_report(findings_off, findings_on), encoding="utf-8"
    )
