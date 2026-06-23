"""Scorecard rendering.

Aggregates Findings into three artifacts written to results/:
  * scorecard.md   — the human-readable headline (rendered in the README / a preview pane)
  * scorecard.json — machine-readable, for CI / dashboards
  * scorecard.html — a standalone, styled report for screen-sharing in a demo

Controls-off and controls-on runs render side by side, and the AIRQ composite is shown for
both so the mitigation effect is visible in the *risk score*, not just a pass/fail flag.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from finagent_redrange.scoring import frameworks
from finagent_redrange.types import RETRIEVAL_TOOL, Finding, Role, Turn

if TYPE_CHECKING:
    from finagent_redrange.attacker.engine import AutonomousReport

# The full OWASP LLM Top 10 (2025), so the coverage matrix shows gaps as well as hits.
_ALL_LLM = [f"LLM{i:02d}" for i in range(1, 11)]

# Plain (non-f) string so CSS braces need no escaping; kept under the line-length limit.
_HTML_STYLE = """
 :root { color-scheme: light dark; }
 body {
   font: 15px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif;
   margin: 2rem auto; max-width: 1100px; padding: 0 1rem;
 }
 h1 { margin-bottom: .2rem; }
 h2 { margin-top: 2rem; }
 .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
 .card {
   border: 1px solid #8884; border-radius: 10px;
   padding: .8rem 1.1rem; min-width: 150px;
 }
 .card b { font-size: 1.6rem; display: block; }
 table {
   border-collapse: collapse; width: 100%;
   margin-top: .6rem; font-size: 14px;
 }
 th, td {
   border: 1px solid #8884; padding: .45rem .6rem;
   text-align: left; vertical-align: top;
 }
 th { background: #8881; }
 .pill {
   border-radius: 999px; padding: .1rem .55rem;
   font-weight: 600; font-size: .85em;
 }
 .good { background: #1a7f3722; color: #1a7f37; }
 .bad { background: #cf222e22; color: #cf222e; }
 em { color: #888; font-style: normal; font-size: .85em; }
 code { background: #8882; padding: .05rem .3rem; border-radius: 4px; }
 footer { margin-top: 2rem; color: #888; font-size: .85em; }
"""


# --- small helpers ------------------------------------------------------------------------


def _status(succeeded: bool) -> str:
    return "🔴 exploited" if succeeded else "🟢 blocked"


def _airq_cell(f: Finding) -> str:
    a = f.airq
    return f"{a.attack_surface}/{a.blast_radius}/{a.defense_controls} → **{a.band.value}**"


def _mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 2) if values else 0.0


def _band_for(composite: float) -> str:
    if composite >= 6:
        return "High"
    if composite >= 3:
        return "Medium"
    return "Low"


# --- summary ------------------------------------------------------------------------------


def _summary(findings_off: list[Finding], findings_on: list[Finding]) -> dict:
    on_by_id = {f.scenario_id: f for f in findings_on}
    n = len(findings_off)
    exploited_off = sum(f.succeeded for f in findings_off)
    blocked_on = sum(
        not on_by_id[f.scenario_id].succeeded for f in findings_off if f.scenario_id in on_by_id
    )
    mean_off = _mean([f.airq.composite for f in findings_off])
    mean_on = _mean([f.airq.composite for f in findings_on]) if findings_on else None
    return {
        "scenarios": n,
        "exploited_controls_off": exploited_off,
        "blocked_controls_on": blocked_on,
        "mean_airq_off": mean_off,
        "mean_airq_on": mean_on,
        "mean_band_off": _band_for(mean_off),
        "mean_band_on": _band_for(mean_on) if mean_on is not None else None,
    }


def _coverage(findings_off: list[Finding]) -> dict[str, list[str]]:
    """OWASP LLM id -> titles of scenarios exercising it (empty list = not yet covered)."""
    cov: dict[str, list[str]] = {llm: [] for llm in _ALL_LLM}
    for f in findings_off:
        for llm in f.frameworks.owasp_llm:
            cov.setdefault(llm, []).append(f.title)
    return cov


# --- markdown -----------------------------------------------------------------------------


def render_markdown(
    findings_off: list[Finding],
    findings_on: list[Finding],
    autonomous: list[AutonomousReport] | None = None,
) -> str:
    on_by_id = {f.scenario_id: f for f in findings_on}
    s = _summary(findings_off, findings_on)
    lines: list[str] = ["# FinAgent-RedRange scorecard", ""]

    # Summary block — the headline.
    lines += [
        "## Summary",
        "",
        f"- **Scenarios:** {s['scenarios']}",
        f"- **Controls off:** {s['exploited_controls_off']}/{s['scenarios']} exploited",
        f"- **Controls on:** {s['blocked_controls_on']}/{s['scenarios']} blocked ✅",
    ]
    if s["mean_band_on"] is not None:
        lines.append(
            f"- **Mean AIRQ composite:** {s['mean_airq_off']} (**{s['mean_band_off']}**) "
            f"→ {s['mean_airq_on']} (**{s['mean_band_on']}**) when controls engage"
        )
    lines += [
        "",
        "Each scenario should be `exploited` with controls off and `blocked` with controls on.",
        "",
        "## Mitigation-validation results",
        "",
        "| Scenario | OWASP LLM | Agentic | ATLAS | NIST | AIRQ off (AS/BR/DC) | "
        "AIRQ on (AS/BR/DC) | Controls off | Controls on | Validating control |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for off in findings_off:
        on = on_by_id.get(off.scenario_id)
        fw = off.frameworks
        agentic = " · ".join(fw.owasp_agentic) or "—"
        atlas = ", ".join(fw.mitre_atlas) or "—"
        nist = ", ".join(fw.nist_ai_rmf) or "—"
        lines.append(
            f"| {off.title} | {' · '.join(fw.owasp_llm)} | {agentic} | {atlas} | {nist} | "
            f"{_airq_cell(off)} | {_airq_cell(on) if on else '—'} | "
            f"{_status(off.succeeded)} | {_status(on.succeeded) if on else '—'} | "
            f"{off.validating_control} |"
        )

    # OWASP coverage matrix.
    cov = _coverage(findings_off)
    lines += [
        "",
        "## OWASP LLM Top 10 (2025) coverage",
        "",
        "| ID | Risk | Exercised by |",
        "|---|---|---|",
    ]
    for llm in _ALL_LLM:
        hits = cov.get(llm, [])
        mark = "✅ " + "; ".join(sorted(set(hits))) if hits else "—"
        lines.append(f"| {llm} | {frameworks.label(llm)} | {mark} |")

    # Autonomous attacker.
    if autonomous:
        lines += ["", "## Autonomous attacker", ""]
        for r in autonomous:
            state = "controls on" if r.guardrails_enabled else "controls off"
            if r.succeeded:
                verdict = (
                    f"🔴 **objective achieved** via `{r.winning_strategy}` "
                    f"after {r.attempts_made} attempt(s)"
                )
            else:
                verdict = (
                    f"🟢 **control held** — objective not achieved after "
                    f"{r.attempts_made} strateg(ies) tried"
                )
            lines.append(f"- _{r.objective}_ ({state}): {verdict}")

    lines += [
        "",
        "## Notes",
        "",
        "- **AIRQ is an illustrative analyst heuristic** (1-10 anchored sub-scores) for ordering "
        "work, not a calibrated metric; the controls-on DC is the control's *asserted* strength, "
        "so High→Medium shows the intended mitigation effect, not a measured residual-risk number.",
        "- **ATLAS mappings are closest-fit:** AML.T0053 (excessive agency) approximates own-tool "
        "misuse — the agentic T2/T3 codes capture it more precisely; AML.T0020 (data poisoning) "
        "is the stable id, RAG Poisoning AML.T0070 is the newer fit.",
        "- A blank **Agentic** cell means no honest OWASP Agentic (T1-T15) mapping exists for that "
        "scenario, rather than a forced one.",
    ]
    return "\n".join(lines) + "\n"


# --- html ---------------------------------------------------------------------------------


def render_html(
    findings_off: list[Finding],
    findings_on: list[Finding],
    autonomous: list[AutonomousReport] | None = None,
) -> str:
    on_by_id = {f.scenario_id: f for f in findings_on}
    s = _summary(findings_off, findings_on)

    def badge(succeeded: bool) -> str:
        cls = "bad" if succeeded else "good"
        txt = "exploited" if succeeded else "blocked"
        return f'<span class="pill {cls}">{txt}</span>'

    rows = []
    for off in findings_off:
        on = on_by_id.get(off.scenario_id)
        fw = off.frameworks
        rows.append(
            "<tr>"
            f"<td>{off.title}</td>"
            f"<td>{' · '.join(fw.owasp_llm)}</td>"
            f"<td>{' · '.join(fw.owasp_agentic) or '—'}</td>"
            f"<td>{', '.join(fw.mitre_atlas) or '—'}</td>"
            f"<td>{off.airq.composite} <em>{off.airq.band.value}</em></td>"
            f"<td>{on.airq.composite if on else '—'} "
            f"<em>{on.airq.band.value if on else ''}</em></td>"
            f"<td>{badge(off.succeeded)}</td>"
            f"<td>{badge(on.succeeded) if on else '—'}</td>"
            f"<td>{off.validating_control}</td>"
            "</tr>"
        )

    cov = _coverage(findings_off)

    def cov_cell(llm: str) -> str:
        hits = sorted(set(cov.get(llm, [])))
        return "✅ " + "; ".join(hits) if hits else "—"

    cov_rows = "".join(
        f"<tr><td>{llm}</td><td>{frameworks.label(llm)}</td><td>{cov_cell(llm)}</td></tr>"
        for llm in _ALL_LLM
    )

    auto_html = ""
    if autonomous:
        items = []
        for r in autonomous:
            state = "controls on" if r.guardrails_enabled else "controls off"
            if r.succeeded:
                v = (
                    '<span class="pill bad">objective achieved</span> via '
                    f"<code>{r.winning_strategy}</code> after {r.attempts_made} attempt(s)"
                )
            else:
                v = (
                    '<span class="pill good">control held</span> after '
                    f"{r.attempts_made} strateg(ies)"
                )
            items.append(f"<li><em>{r.objective}</em> ({state}): {v}</li>")
        auto_html = f"<h2>Autonomous attacker</h2><ul>{''.join(items)}</ul>"

    if s["mean_band_on"] is not None:
        on_summary = (
            f"{s['mean_airq_off']} ({s['mean_band_off']}) &rarr; "
            f"{s['mean_airq_on']} ({s['mean_band_on']})"
        )
    else:
        on_summary = f"{s['mean_airq_off']} ({s['mean_band_off']})"

    cards = (
        f'<div class="card"><b>{s["scenarios"]}</b>scenarios</div>'
        f'<div class="card"><b>{s["exploited_controls_off"]}/{s["scenarios"]}</b>'
        "exploited (off)</div>"
        f'<div class="card"><b>{s["blocked_controls_on"]}/{s["scenarios"]}</b>'
        "blocked (on)</div>"
        f'<div class="card"><b>{on_summary}</b>mean AIRQ composite</div>'
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FinAgent-RedRange scorecard</title>
<style>{_HTML_STYLE}</style></head><body>
<h1>FinAgent-RedRange scorecard</h1>
<p>Defensive AI-security range — each attack should be <b>exploited</b> with controls off
and <b>blocked</b> with controls on.</p>
<div class="cards">{cards}</div>
<h2>Mitigation-validation results</h2>
<table><thead><tr>
 <th>Scenario</th><th>OWASP LLM</th><th>Agentic</th><th>ATLAS</th>
 <th>AIRQ off</th><th>AIRQ on</th><th>Controls off</th><th>Controls on</th>
 <th>Validating control</th>
</tr></thead><tbody>{"".join(rows)}</tbody></table>
<h2>OWASP LLM Top 10 (2025) coverage</h2>
<table><thead><tr><th>ID</th><th>Risk</th><th>Exercised by</th></tr></thead>
<tbody>{cov_rows}</tbody></table>
{auto_html}
<footer>Generated by <code>python -m finagent_redrange run</code>. All data synthetic; single
target is the bundled mock agent. AIRQ is an illustrative analyst heuristic (asserted DC), not
a calibrated metric; ATLAS rows are closest-fit; a blank Agentic cell means no honest
T1–T15 mapping.</footer>
</body></html>
"""


# --- transcripts (evidence dump) ----------------------------------------------------------


def _render_turn(t: Turn) -> str:
    if t.role is Role.USER:
        return f"- **User:** {t.content}"
    if t.role is Role.ASSISTANT:
        if t.tool_calls:
            calls = ", ".join(f"`{c.name}({c.args})`" for c in t.tool_calls)
            return f"- **Assistant** _(requests {calls})_: {t.content}".rstrip()
        return f"- **Assistant:** {t.content}"
    if t.role is Role.TOOL:
        if t.tool_name == RETRIEVAL_TOOL:
            return f"- **Retrieved (RAG):** {t.content}"
        status = "ok" if t.tool_ok else "BLOCKED"
        return f"- **Tool[{t.tool_name} → {status}]:** {t.content}"
    return f"- **{t.role}:** {t.content}"


def render_transcripts(findings_off: list[Finding], findings_on: list[Finding]) -> str:
    """Full conversation per scenario — the evidence behind each oracle verdict."""
    lines = ["# FinAgent-RedRange — transcripts", ""]
    for label, findings in (("Controls OFF", findings_off), ("Controls ON", findings_on)):
        if not findings:
            continue
        lines.append(f"## {label}")
        lines.append("")
        for f in findings:
            outcome = "🔴 exploited" if f.succeeded else "🟢 blocked"
            lines.append(f"### {f.title} — {outcome}")
            for t in f.transcript.turns:
                lines.append(_render_turn(t))
            lines.append("")
    return "\n".join(lines) + "\n"


def write_transcripts(
    findings_off: list[Finding], findings_on: list[Finding], out_dir: Path
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "transcripts.md").write_text(
        render_transcripts(findings_off, findings_on), encoding="utf-8"
    )


# --- writer -------------------------------------------------------------------------------


def write(
    findings_off: list[Finding],
    findings_on: list[Finding],
    out_dir: Path,
    autonomous: list[AutonomousReport] | None = None,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    # UTF-8 explicitly: the report uses → and emoji, which the Windows cp1252 default can't encode.
    (out_dir / "scorecard.md").write_text(
        render_markdown(findings_off, findings_on, autonomous), encoding="utf-8"
    )
    (out_dir / "scorecard.html").write_text(
        render_html(findings_off, findings_on, autonomous), encoding="utf-8"
    )
    payload = {
        "summary": _summary(findings_off, findings_on),
        "coverage": _coverage(findings_off),
        "controls_off": [_finding_json(f) for f in findings_off],
        "controls_on": [_finding_json(f) for f in findings_on],
        "autonomous": [_autonomous_json(r) for r in (autonomous or [])],
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


def _autonomous_json(r: AutonomousReport) -> dict:
    return {
        "objective": r.objective,
        "guardrails_enabled": r.guardrails_enabled,
        "succeeded": r.succeeded,
        "attempts_made": r.attempts_made,
        "winning_strategy": r.winning_strategy,
        "attempts": [{"strategy": a.strategy, "succeeded": a.succeeded} for a in r.attempts],
    }
