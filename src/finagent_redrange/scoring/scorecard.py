"""Scorecard rendering.

Aggregates Findings into (a) the markdown table shown in the README and (b) a JSON artifact
for CI / dashboards. Pair runs (controls off + controls on) render side by side so the
mitigation effect is the headline.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from finagent_redrange.types import Finding


def _status(succeeded: bool) -> str:
    return "🔴 exploited" if succeeded else "🟢 blocked"


def render_markdown(findings_off: list[Finding], findings_on: list[Finding]) -> str:
    """findings_off / findings_on are parallel lists keyed by scenario_id."""
    on_by_id = {f.scenario_id: f for f in findings_on}
    lines = [
        "| Scenario | OWASP | ATLAS | AIRQ (AS / BR / DC) | "
        "Controls off | Controls on | Validating control |",
        "|---|---|---|---|---|---|---|",
    ]
    for off in findings_off:
        on = on_by_id.get(off.scenario_id)
        fw = off.frameworks
        owasp = " · ".join(fw.owasp_llm + fw.owasp_agentic)
        atlas = ", ".join(fw.mitre_atlas)
        a = off.airq
        scores = f"{a.attack_surface} / {a.blast_radius} / {a.defense_controls}"
        airq_cell = f"{scores} → **{a.band.value}**"
        lines.append(
            f"| {off.title} | {owasp} | {atlas} | {airq_cell} | "
            f"{_status(off.succeeded)} | {_status(on.succeeded) if on else '—'} | "
            f"{off.validating_control} |"
        )
    return "\n".join(lines)


def write(findings_off: list[Finding], findings_on: list[Finding], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = render_markdown(findings_off, findings_on)
    # UTF-8 explicitly: the table uses → and emoji, which the Windows cp1252 default can't encode.
    (out_dir / "scorecard.md").write_text(
        "# FinAgent-RedRange scorecard\n\n"
        "Each scenario should be `exploited` with controls off and `blocked` with controls on.\n\n"
        + md
        + "\n",
        encoding="utf-8",
    )
    payload = {
        "controls_off": [_finding_json(f) for f in findings_off],
        "controls_on": [_finding_json(f) for f in findings_on],
    }
    (out_dir / "scorecard.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8"
    )


def _finding_json(f: Finding) -> dict:
    d = asdict(f)
    d.pop("transcript", None)  # keep the summary artifact compact; full logs live elsewhere
    d["airq_composite"] = f.airq.composite
    d["airq_band"] = f.airq.band.value
    return d
