"""Framework crosswalk.

Turns a scenario's declared tags into a structured FrameworkMapping so findings drop straight
into governance/audit pipelines. This is the lightweight, embedded version of a full
OWASP<->ATLAS<->NIST crosswalk — extend `REFERENCE` with descriptions, or replace this module
to import your standalone crosswalk dataset.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from finagent_redrange.types import FrameworkMapping

if TYPE_CHECKING:
    from finagent_redrange.scenarios.base import Scenario

# Reference table — id -> human label. Extend or swap for your full standalone crosswalk.
# IDs were verified against the published standards (OWASP genai.owasp.org, MITRE ATLAS,
# NIST AI 100-1). Where no honest mapping exists (e.g. an LLM-layer issue with no agentic
# behaviour), the scenario leaves that field blank rather than forcing a code.
REFERENCE: dict[str, str] = {
    # OWASP Top 10 for LLM Applications (2025)
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
    # OWASP "Agentic AI — Threats and Mitigations" v1.0 (Feb 2025): the 15 agentic threats.
    "T1": "Agentic — Memory Poisoning",
    "T2": "Agentic — Tool Misuse",
    "T3": "Agentic — Privilege Compromise",
    "T6": "Agentic — Intent Breaking & Goal Manipulation",
    # MITRE ATLAS techniques / sub-techniques (canonical names, verified June 2026 against the
    # live atlas.mitre.org matrix / mitre-atlas/atlas-data).
    "AML.T0051": "ATLAS — LLM Prompt Injection",
    "AML.T0051.001": "ATLAS — LLM Prompt Injection: Indirect",
    "AML.T0070": "ATLAS — RAG Poisoning",  # runtime RAG-corpus poisoning (the data-poisoning fit)
    "AML.T0020": "ATLAS — Poison Training Data",  # training-time relative of RAG Poisoning
    "AML.T0048.000": "ATLAS — External Harms: Financial Harm",
    "AML.T0052.000": "ATLAS — Phishing: Spearphishing via Social Engineering LLM",
    "AML.T0053": "ATLAS — AI Agent Tool Invocation",
    "AML.T0056": "ATLAS — Extract LLM System Prompt",
    "AML.T0057": "ATLAS — LLM Data Leakage",
    # NIST AI Risk Management Framework (AI RMF 1.0 / NIST AI 100-1) subcategories.
    "MEASURE 2.5": "NIST AI RMF — AI system demonstrated to be valid and reliable",
    "MEASURE 2.7": "NIST AI RMF — security & resilience evaluated",
}


def label(framework_id: str) -> str:
    return REFERENCE.get(framework_id, framework_id)


def map_finding(scenario: Scenario) -> FrameworkMapping:
    return FrameworkMapping(
        owasp_llm=list(scenario.owasp_llm),
        owasp_agentic=list(scenario.owasp_agentic),
        mitre_atlas=list(scenario.mitre_atlas),
        nist_ai_rmf=list(scenario.nist_ai_rmf),
    )
