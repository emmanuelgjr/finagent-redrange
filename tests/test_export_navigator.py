"""ATLAS Navigator layer export gates.

Verifies the layer is a structurally valid MITRE ATLAS Navigator layer (the ATLAS domain, not the
enterprise ATT&CK domain, which would not render AML.T#### ids) and that every technique in it is a
real ATLAS id from the verified crosswalk that the range actually exercises.
"""

from __future__ import annotations

import json

from finagent_redrange.exports import navigator
from finagent_redrange.exports.navigator import to_layer
from finagent_redrange.scoring import frameworks


def test_targets_the_atlas_navigator_not_enterprise(findings_off) -> None:
    layer = to_layer(findings_off)
    # ATLAS ids only render in the ATLAS Navigator; the enterprise domain would silently break.
    assert layer["domain"] == "atlas-atlas"
    assert layer["versions"] == {"layer": "4.3", "navigator": "4.6.4"}
    assert "attack" not in layer["versions"]  # no ATT&CK version key on an ATLAS layer
    for key in ("name", "domain", "versions", "techniques", "gradient"):
        assert key in layer


def test_every_technique_is_a_real_exercised_atlas_id(findings_off) -> None:
    layer = to_layer(findings_off)
    exercised = {aml for f in findings_off for aml in f.frameworks.mitre_atlas}
    layer_ids = {t["techniqueID"] for t in layer["techniques"]}
    # completeness: every ATLAS id the range exercises appears as a technique
    assert layer_ids == exercised
    # provenance: every technique id is a real ATLAS id in the verified crosswalk
    for aml in layer_ids:
        assert aml.startswith("AML.")
        assert aml in frameworks.REFERENCE


def test_scores_reflect_scenario_coverage(findings_off) -> None:
    layer = to_layer(findings_off)
    counts = {}
    for f in findings_off:
        for aml in f.frameworks.mitre_atlas:
            counts[aml] = counts.get(aml, 0) + 1
    for tech in layer["techniques"]:
        assert tech["score"] == counts[tech["techniqueID"]]
        assert tech["score"] >= 1
        assert tech["enabled"] is True
    assert layer["gradient"]["maxValue"] == max(counts.values())


def test_output_is_deterministic_and_writes(findings_off, findings_on, tmp_path) -> None:
    assert json.dumps(to_layer(findings_off)) == json.dumps(to_layer(findings_off))
    navigator.write_navigator(findings_off, findings_on, tmp_path)
    written = json.loads(
        (tmp_path / "navigator" / "atlas-coverage.json").read_text(encoding="utf-8")
    )
    assert written["domain"] == "atlas-atlas"
