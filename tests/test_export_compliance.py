"""Compliance-crosswalk export gates.

Because a regulatory mapping is interpretive, the precision gate here is honest about what it can
prove: **completeness** (no scenario is left unmapped) and **provenance labeling** (nothing
self-authored is passed off as authoritative). It deliberately does NOT assert legal accuracy —
no automated check can.
"""

from __future__ import annotations

import json

from finagent_redrange.exports import compliance
from finagent_redrange.exports.compliance import NIST_RMF, to_compliance


def test_every_scenario_is_mapped(findings_off) -> None:
    data = to_compliance(findings_off)
    mapped_ids = {s["scenario_id"] for s in data["scenarios"]}
    assert mapped_ids == {f.scenario_id for f in findings_off}
    for scenario in data["scenarios"]:
        assert scenario["mappings"], f"{scenario['scenario_id']}: no control mappings"


def test_declared_rows_bind_to_verified_crosswalk(findings_off) -> None:
    # A row is only 'declared' if its ref is an actual NIST AI RMF id carried on the scenario;
    # every other row must be 'interpretive' (nothing self-authored poses as authoritative).
    by_id = {f.scenario_id: f for f in findings_off}
    for scenario in to_compliance(findings_off)["scenarios"]:
        finding = by_id[scenario["scenario_id"]]
        for row in scenario["mappings"]:
            if row["basis"] == "declared":
                assert row["framework"] == NIST_RMF
                assert row["ref"] in finding.frameworks.nist_ai_rmf
            else:
                assert row["basis"] == "interpretive"
                assert row["framework"] != NIST_RMF


def test_artifact_carries_disclaimer_and_timeline(findings_off) -> None:
    data = to_compliance(findings_off)
    assert "NOT legal advice" in data["disclaimer"]
    # The verified EU AI Act timeline must be present and correct (GPAI in force since 2 Aug 2025).
    assert "since 2 Aug 2025" in data["eu_ai_act_timeline"]
    assert "from 2 Aug 2026" in data["eu_ai_act_timeline"]


def test_markdown_renders_and_is_deterministic(findings_off, tmp_path) -> None:
    md = compliance.render_markdown(findings_off)
    assert "regulatory control crosswalk" in md
    assert "Basis legend" in md
    assert compliance.render_markdown(findings_off) == md  # deterministic


def test_write_compliance_emits_both_files(findings_off, findings_on, tmp_path) -> None:
    compliance.write_compliance(findings_off, findings_on, tmp_path)
    cdir = tmp_path / "compliance"
    assert (cdir / "crosswalk.md").exists()
    payload = json.loads((cdir / "crosswalk.json").read_text(encoding="utf-8"))
    assert len(payload["scenarios"]) == len(findings_off)
