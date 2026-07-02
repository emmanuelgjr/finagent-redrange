"""Export a GSN-style control-effectiveness assurance case bound to the range's own evidence.

An assurance case is the artifact an AI security architect / GRC function puts in front of an
architecture-review board or auditor: a structured argument that a top claim holds, decomposed to
leaf claims each backed by concrete evidence. This exporter builds one in the vocabulary of the
Goal Structuring Notation (GSN Community Standard v3). There is no canonical GSN JSON interchange
(OMG SACM is the metamodel), so this is a defined-in-repo JSON serialization, labeled as such.

What makes it trustworthy rather than narrative: every leaf claim resolves to a real regression
test node id AND a deterministic SHA-256 of the exact transcript that evidences it. Because the
EchoClient is deterministic, re-running the range and re-hashing reproduces byte-identical hashes —
so ``tests/test_export_assurance.py`` can assert zero orphan claims/evidence, well-formedness, and
hash reproducibility. Honesty caveats (AIRQ heuristic, asserted DC, offline EchoClient) ride as
explicit Assumption/Justification nodes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from finagent_redrange.types import Finding, Transcript

#: The regression module + parametrized functions the assurance evidence points at. The
#: parametrize ids ARE the scenario ids (tests/test_regression.py uses ids=lambda c: c.id).
REGRESSION_TEST = "tests/test_regression.py"
OFF_TEST = "test_attack_lands_without_controls"
ON_TEST = "test_attack_blocked_with_controls"

_SHAPES = {
    "Goal": "box",
    "Strategy": "parallelogram",
    "Solution": "circle",
    "Context": "box",
    "Assumption": "ellipse",
    "Justification": "ellipse",
}


def regression_node_id(func: str, scenario_id: str) -> str:
    return f"{REGRESSION_TEST}::{func}[{scenario_id}]"


def canonical_transcript(transcript: Transcript) -> str:
    """A deterministic line-per-turn serialization of a transcript (the hashed evidence)."""
    lines = []
    for t in transcript.turns:
        ok = "" if t.tool_ok is None else ("ok" if t.tool_ok else "blocked")
        args = json.dumps(t.tool_args, sort_keys=True) if t.tool_args else ""
        lines.append(f"{t.role.value}|{t.tool_name or ''}|{ok}|{args}|{t.content}")
    return "\n".join(lines) + "\n"


def transcript_sha256(transcript: Transcript) -> str:
    return hashlib.sha256(canonical_transcript(transcript).encode("utf-8")).hexdigest()


def _crosswalk_text(finding: Finding) -> str:
    fw = finding.frameworks
    parts = []
    if fw.owasp_llm:
        parts.append("OWASP LLM: " + ", ".join(fw.owasp_llm))
    agentic = [*fw.owasp_agentic, *fw.owasp_agentic_top10]
    if agentic:
        parts.append("OWASP Agentic: " + ", ".join(agentic))
    if fw.mitre_atlas:
        parts.append("MITRE ATLAS: " + ", ".join(fw.mitre_atlas))
    if fw.nist_ai_rmf:
        parts.append("NIST AI RMF: " + ", ".join(fw.nist_ai_rmf))
    return "; ".join(parts)


def to_assurance_case(
    findings_off: list[Finding], findings_on: list[Finding]
) -> dict[str, Any]:
    """Build the GSN assurance case from the paired controls-off / controls-on findings."""
    on_by_id = {f.scenario_id: f for f in findings_on}
    nodes: list[dict[str, Any]] = [
        {
            "id": "G1",
            "type": "Goal",
            "statement": "The mock banking agent's guardrails mitigate the covered OWASP LLM "
            "Top 10 risks.",
        },
        {
            "id": "S1",
            "type": "Strategy",
            "statement": "Argue over each covered risk: for every scenario, demonstrate the "
            "exploit lands with controls OFF and is blocked with controls ON, evidenced by "
            "passing regression tests and reproducible transcripts.",
        },
        {
            "id": "A1",
            "type": "Assumption",
            "statement": "AIRQ is an illustrative analyst heuristic; the controls-on "
            "defense-controls sub-score is asserted, not measured. Evidence is generated offline "
            "against the deterministic EchoClient.",
        },
        {
            "id": "J1",
            "type": "Justification",
            "statement": "Project invariant 'no exploit without its fix': a control is accepted "
            "only when its controls-on regression test passes.",
        },
    ]
    links: list[dict[str, str]] = [
        {"type": "SupportedBy", "source": "G1", "target": "S1"},
        {"type": "InContextOf", "source": "G1", "target": "A1"},
        {"type": "InContextOf", "source": "G1", "target": "J1"},
    ]

    for finding in findings_off:
        sid = finding.scenario_id
        goal, ctx = f"G_{sid}", f"C_{sid}"
        off_sol, on_sol = f"Sn_{sid}_off", f"Sn_{sid}_on"
        nodes.append(
            {
                "id": goal,
                "type": "Goal",
                "statement": f"{finding.validating_control} blocks: {finding.title}.",
            }
        )
        nodes.append({"id": ctx, "type": "Context", "statement": _crosswalk_text(finding)})
        nodes.append(
            {
                "id": off_sol,
                "type": "Solution",
                "statement": "Exploit reproduced with controls OFF (the threat is real).",
                "evidence": {
                    "testId": regression_node_id(OFF_TEST, sid),
                    "transcriptRef": f"evidence/{sid}.controls_off.txt",
                    "sha256": transcript_sha256(finding.transcript),
                    "verdict": "exploited" if finding.succeeded else "blocked",
                },
            }
        )
        links += [
            {"type": "SupportedBy", "source": "S1", "target": goal},
            {"type": "InContextOf", "source": goal, "target": ctx},
            {"type": "SupportedBy", "source": goal, "target": off_sol},
        ]
        on = on_by_id.get(sid)
        if on is not None:
            nodes.append(
                {
                    "id": on_sol,
                    "type": "Solution",
                    "statement": "Attack blocked with controls ON (the control holds).",
                    "evidence": {
                        "testId": regression_node_id(ON_TEST, sid),
                        "transcriptRef": f"evidence/{sid}.controls_on.txt",
                        "sha256": transcript_sha256(on.transcript),
                        "verdict": "blocked" if not on.succeeded else "exploited",
                    },
                }
            )
            links.append({"type": "SupportedBy", "source": goal, "target": on_sol})

    return {
        "format": "GSN Community Standard v3 vocabulary (in-repo JSON serialization; no canonical "
        "GSN JSON interchange exists - OMG SACM is the metamodel).",
        "argument": "control-effectiveness assurance case",
        "generatedBy": "python -m finagent_redrange run --assurance (EchoClient, deterministic)",
        "nodes": nodes,
        "links": links,
    }


def validate_case(case: dict[str, Any]) -> list[str]:
    """Structural well-formedness checks. Returns a list of problems (empty == valid)."""
    errors: list[str] = []
    node_ids = {n["id"] for n in case["nodes"]}
    adjacency: dict[str, list[str]] = {nid: [] for nid in node_ids}
    targets: set[str] = set()
    supported: set[str] = set()

    for link in case["links"]:
        src, tgt = link["source"], link["target"]
        if src not in node_ids:
            errors.append(f"link source does not resolve: {src}")
        if tgt not in node_ids:
            errors.append(f"link target does not resolve: {tgt}")
        if src in adjacency and tgt in node_ids:
            adjacency[src].append(tgt)
        targets.add(tgt)
        if link["type"] == "SupportedBy":
            supported.add(src)

    goals = [n["id"] for n in case["nodes"] if n["type"] == "Goal"]
    roots = [g for g in goals if g not in targets]
    if roots != ["G1"]:
        errors.append(f"expected exactly one root Goal 'G1', found roots: {roots}")
    for g in goals:
        if g not in supported:
            errors.append(f"undischarged Goal (no supporting evidence/strategy): {g}")

    # Acyclicity (DFS with a recursion stack).
    WHITE, GREY, BLACK = 0, 1, 2
    colour = dict.fromkeys(node_ids, WHITE)

    def visit(node: str) -> bool:
        colour[node] = GREY
        for nxt in adjacency.get(node, []):
            if colour[nxt] == GREY or (colour[nxt] == WHITE and not visit(nxt)):
                return False
        colour[node] = BLACK
        return True

    for nid in node_ids:
        if colour[nid] == WHITE and not visit(nid):
            errors.append("assurance graph contains a cycle")
            break
    return errors


def to_dot(case: dict[str, Any]) -> str:
    """Render the assurance case as Graphviz DOT (SVG needs the optional graphviz binary)."""
    lines = ["digraph assurance {", "  rankdir=TB;", '  node [fontname="Helvetica", fontsize=10];']
    for node in case["nodes"]:
        label = node["statement"].replace('"', "'")
        if len(label) > 64:
            label = label[:61] + "..."
        shape = _SHAPES.get(node["type"], "box")
        lines.append(f'  "{node["id"]}" [shape={shape}, label="{node["id"]}: {label}"];')
    for link in case["links"]:
        style = "dashed" if link["type"] == "InContextOf" else "solid"
        lines.append(f'  "{link["source"]}" -> "{link["target"]}" [style={style}];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_assurance(
    findings_off: list[Finding], findings_on: list[Finding], out_dir: Path
) -> None:
    """Write the assurance case (JSON + DOT) and the per-transcript evidence files it hashes."""
    adir = out_dir / "assurance"
    (adir / "evidence").mkdir(parents=True, exist_ok=True)
    case = to_assurance_case(findings_off, findings_on)
    (adir / "assurance-case.json").write_text(json.dumps(case, indent=2), encoding="utf-8")
    (adir / "assurance-case.dot").write_text(to_dot(case), encoding="utf-8")
    # Write as raw bytes so the on-disk file hashes to exactly the sha256 recorded in the case
    # (text mode would translate "\n" to "\r\n" on Windows and break the match).
    for finding in findings_off:
        (adir / "evidence" / f"{finding.scenario_id}.controls_off.txt").write_bytes(
            canonical_transcript(finding.transcript).encode("utf-8")
        )
    for finding in findings_on:
        (adir / "evidence" / f"{finding.scenario_id}.controls_on.txt").write_bytes(
            canonical_transcript(finding.transcript).encode("utf-8")
        )
