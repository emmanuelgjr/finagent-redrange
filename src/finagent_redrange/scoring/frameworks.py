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
    # OWASP Agentic AI — repo tags aligned to the Agentic Security Initiative threat taxonomy
    "ASI-01": "Agentic — prompt/instruction manipulation",
    "ASI-05": "Agentic — knowledge/memory poisoning",
    # MITRE ATLAS techniques (canonical technique names)
    "AML.T0051": "ATLAS — LLM Prompt Injection",
    "AML.T0020": "ATLAS — Poison Training Data",  # by analogy for RAG/reference poisoning
    # NIST AI Risk Management Framework (AI RMF 1.0) subcategories
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
