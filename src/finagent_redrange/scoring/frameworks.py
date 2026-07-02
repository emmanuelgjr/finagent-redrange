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
    "T4": "Agentic — Resource Overload",
    "T6": "Agentic — Intent Breaking & Goal Manipulation",
    # OWASP "Top 10 for Agentic Applications" 2026 (the ranked agentic Top 10, ASI01–ASI10) —
    # the newer, incident-grounded benchmark that complements the T1–T15 taxonomy above.
    "ASI01": "Agentic Top 10 — Agent Behavior Hijacking",
    "ASI02": "Agentic Top 10 — Tool Misuse & Exploitation",
    "ASI03": "Agentic Top 10 — Identity & Privilege Abuse",
    "ASI04": "Agentic Top 10 — Agentic Supply Chain Vulnerabilities",
    "ASI05": "Agentic Top 10 — Unexpected Code Execution",
    "ASI06": "Agentic Top 10 — Memory & Context Poisoning",
    "ASI07": "Agentic Top 10 — Insecure Inter-Agent Communication",
    "ASI08": "Agentic Top 10 — Cascading Failures",
    "ASI09": "Agentic Top 10 — Human-Agent Trust Exploitation",
    "ASI10": "Agentic Top 10 — Rogue Agents",
    # MITRE ATLAS techniques / sub-techniques (canonical names, verified June 2026 against the
    # live atlas.mitre.org matrix / mitre-atlas/atlas-data).
    "AML.T0010": "ATLAS — AI Supply Chain Compromise",
    "AML.T0010.001": "ATLAS — AI Supply Chain Compromise: AI Software",
    "AML.T0034": "ATLAS — Cost Harvesting",
    "AML.T0029": "ATLAS — Denial of AI Service",
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
        owasp_agentic_top10=list(scenario.owasp_agentic_top10),
        mitre_atlas=list(scenario.mitre_atlas),
        nist_ai_rmf=list(scenario.nist_ai_rmf),
    )
