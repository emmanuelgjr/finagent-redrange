"""Assurance-case export gates — the traceability/precision property for the architect handout.

Checks, all offline against the deterministic EchoClient:
  1. Well-formedness: one root Goal, all links resolve, acyclic, no undischarged Goal.
  2. Zero orphan claims / zero orphan evidence: every Solution's evidence resolves to a real
     regression node id + a 64-char SHA-256, and every regression node id is cited (a bijection).
  3. Reproducibility: re-running the range reproduces byte-identical transcript hashes.
  4. Evidence binding: the honest 'greenness' check — recompute the verdicts the case asserts and
     confirm each evidence file on disk hashes to exactly the sha256 recorded in the case.
"""

from __future__ import annotations

import hashlib
import json

from finagent_redrange.cli import _run_pass
from finagent_redrange.exports import assurance
from finagent_redrange.exports.assurance import (
    OFF_TEST,
    ON_TEST,
    regression_node_id,
    to_assurance_case,
    validate_case,
)


def test_case_is_wellformed(findings_off, findings_on) -> None:
    case = to_assurance_case(findings_off, findings_on)
    assert validate_case(case) == []


def test_zero_orphan_claims_and_evidence(findings_off, findings_on) -> None:
    case = to_assurance_case(findings_off, findings_on)
    expected = set()
    for f in findings_off:
        expected.add(regression_node_id(OFF_TEST, f.scenario_id))
        expected.add(regression_node_id(ON_TEST, f.scenario_id))

    cited = set()
    for node in case["nodes"]:
        if node["type"] != "Solution":
            continue
        evidence = node["evidence"]
        assert evidence["testId"] in expected, f"orphan claim: {evidence['testId']}"
        assert len(evidence["sha256"]) == 64
        cited.add(evidence["testId"])

    assert cited == expected, "orphan evidence: not every regression node is cited by a claim"


def test_transcript_hashes_are_reproducible(findings_off, findings_on) -> None:
    case1 = to_assurance_case(findings_off, findings_on)
    # A second independent range run reproduces byte-identical hashes (deterministic EchoClient).
    off2 = _run_pass("echo", controls_on=False)
    on2 = _run_pass("echo", controls_on=True)
    case2 = to_assurance_case(off2, on2)

    def hashes(case):
        return {n["id"]: n["evidence"]["sha256"] for n in case["nodes"] if n["type"] == "Solution"}

    assert hashes(case1) == hashes(case2)


def test_evidence_verdicts_bind_to_recomputed_findings(findings_off, findings_on) -> None:
    # Non-tautological greenness: the exploit really lands off and the control really holds on.
    on_by_id = {f.scenario_id: f for f in findings_on}
    for off in findings_off:
        assert off.succeeded is True
        assert on_by_id[off.scenario_id].succeeded is False


def test_write_assurance_evidence_files_match_hashes(findings_off, findings_on, tmp_path) -> None:
    assurance.write_assurance(findings_off, findings_on, tmp_path)
    adir = tmp_path / "assurance"
    assert (adir / "assurance-case.json").exists()
    assert (adir / "assurance-case.dot").exists()

    case = json.loads((adir / "assurance-case.json").read_text(encoding="utf-8"))
    for node in case["nodes"]:
        if node["type"] != "Solution":
            continue
        evidence = node["evidence"]
        evidence_file = adir / evidence["transcriptRef"]
        assert evidence_file.exists(), f"missing evidence file: {evidence['transcriptRef']}"
        digest = hashlib.sha256(evidence_file.read_bytes()).hexdigest()
        assert digest == evidence["sha256"], f"evidence hash mismatch for {node['id']}"
