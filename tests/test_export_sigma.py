"""The Sigma detection pack's precision gate — the range's headline measurable-precision artifact.

Three properties, all offline against the deterministic EchoClient:
  1. Labeled-replay confusion matrix is perfect: every rule fires on its own exploited (controls-
     off) transcript and stays silent on its blocked (controls-on) transcript AND on every other
     scenario's transcripts. Any cross-fire or miss fails the build.
  2. Oracle equivalence: each exported signature reproduces the scenario oracle's verdict on BOTH
     labels — so a shipped rule can never silently drift from the validated oracle.
  3. Sigma rules are well-formed (valid YAML, required fields, no reserved-namespace misuse).
"""

from __future__ import annotations

import uuid

import yaml

from finagent_redrange.exports import sigma
from finagent_redrange.exports.detection import (
    confusion_matrix,
    evaluate,
    events_from_transcript,
)


def test_confusion_matrix_is_perfect(findings_off, findings_on) -> None:
    scores = confusion_matrix(findings_off, findings_on)
    assert len(scores) == len(findings_off)
    for s in scores:
        assert s.tp == 1, f"{s.scenario_id}: rule did not fire on its own exploit"
        assert s.fp == 0, f"{s.scenario_id}: rule fired on a blocked/foreign transcript"
        assert s.fn == 0, f"{s.scenario_id}: rule missed its own exploit"
        assert s.precision == 1.0
        assert s.recall == 1.0


def test_oracle_equivalence_on_both_labels(findings_off, findings_on) -> None:
    on_by_id = {f.scenario_id: f for f in findings_on}
    for off in findings_off:
        assert off.detection is not None, f"{off.scenario_id}: no detection signature"
        on = on_by_id[off.scenario_id]
        # the range invariant: exploit lands off, is blocked on
        assert off.succeeded is True
        assert on.succeeded is False
        # the exported detection reproduces the oracle verdict on BOTH labels
        assert evaluate(off.detection, events_from_transcript(off.transcript)) == off.succeeded
        assert evaluate(off.detection, events_from_transcript(on.transcript)) == on.succeeded


def test_sigma_rules_are_valid_and_wellformed(findings_off, findings_on, tmp_path) -> None:
    sigma.write_sigma(findings_off, findings_on, tmp_path)
    sigma_dir = tmp_path / "sigma"
    seen_ids: set[str] = set()
    for off in findings_off:
        path = sigma_dir / f"{off.scenario_id}.yml"
        assert path.exists()
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        for key in ("title", "id", "status", "logsource", "detection", "level"):
            assert key in rule, f"{off.scenario_id}: Sigma rule missing '{key}'"
        uuid.UUID(rule["id"])  # a valid UUID
        assert rule["id"] not in seen_ids  # deterministic + unique per scenario
        seen_ids.add(rule["id"])
        detection = rule["detection"]
        assert "selection" in detection and "condition" in detection
        assert "selection" in detection["condition"]  # condition references the selection
        for tag in rule.get("tags", []):
            # Sigma reserves attack.* for MITRE ATT&CK; ATLAS ids must use the custom namespace.
            assert not tag.startswith("attack."), f"reserved Sigma namespace misused: {tag}"


def test_precision_report_written(findings_off, findings_on, tmp_path) -> None:
    sigma.write_sigma(findings_off, findings_on, tmp_path)
    report = (tmp_path / "sigma" / "precision_report.md").read_text(encoding="utf-8")
    assert "Overall" in report
    assert "**1.00**" in report  # overall precision and recall are 1.00 on the labeled corpus


def test_rule_rendering_is_deterministic(findings_off) -> None:
    off = findings_off[0]
    assert sigma.render_rule(off) == sigma.render_rule(off)
