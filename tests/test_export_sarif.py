"""SARIF 2.1.0 export gates — structural validity, serialization fidelity, taxonomy integrity.

The taxonomy referential-integrity check doubles as a crosswalk-completeness gate: it fails if a
finding uses a framework id that is absent from frameworks.REFERENCE, or if a result's taxa pointer
does not resolve into a declared taxonomy.
"""

from __future__ import annotations

import json

from finagent_redrange.exports.sarif import to_sarif
from finagent_redrange.scoring import frameworks


def _all_ids(finding) -> list[str]:
    fw = finding.frameworks
    return [
        *fw.owasp_llm,
        *fw.owasp_agentic,
        *fw.owasp_agentic_top10,
        *fw.mitre_atlas,
        *fw.nist_ai_rmf,
    ]


def test_sarif_top_level_structure(findings_off) -> None:
    doc = to_sarif(findings_off)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "FinAgent-RedRange"
    assert run["tool"]["driver"]["rules"], "no rules emitted"
    assert run["results"], "no results emitted"


def test_serialization_fidelity(findings_off, findings_on) -> None:
    # Exactly the exploited (succeeded) findings become active results; none of the blocked do.
    off_results = to_sarif(findings_off)["runs"][0]["results"]
    assert len(off_results) == sum(1 for f in findings_off if f.succeeded) == len(findings_off)
    on_results = to_sarif(findings_on)["runs"][0]["results"]
    assert on_results == []


def test_taxonomy_referential_integrity(findings_off) -> None:
    run = to_sarif(findings_off)["runs"][0]
    taxonomies = run["taxonomies"]
    for result in run["results"]:
        assert result["taxa"], f"{result['ruleId']}: no taxa references"
        for ref in result["taxa"]:
            idx = ref["toolComponent"]["index"]
            assert 0 <= idx < len(taxonomies)
            taxon_ids = {t["id"] for t in taxonomies[idx]["taxa"]}
            assert ref["id"] in taxon_ids, f"unresolved taxon reference: {ref['id']}"


def test_every_framework_id_exists_in_crosswalk(findings_off, findings_on) -> None:
    for finding in [*findings_off, *findings_on]:
        for framework_id in _all_ids(finding):
            assert framework_id in frameworks.REFERENCE, (
                f"{finding.scenario_id}: framework id {framework_id!r} missing from REFERENCE"
            )


def test_security_severity_within_sarif_range(findings_off) -> None:
    run = to_sarif(findings_off)["runs"][0]
    for rule in run["tool"]["driver"]["rules"]:
        severity = float(rule["properties"]["security-severity"])
        assert 0.0 <= severity <= 10.0


def test_output_is_deterministic(findings_off) -> None:
    assert json.dumps(to_sarif(findings_off)) == json.dumps(to_sarif(findings_off))
