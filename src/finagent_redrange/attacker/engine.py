"""The red-team engine: runs a Scenario against the mock agent and produces a Finding.

v0.1 runs a scripted multi-turn campaign defined by each Scenario. The seam for the
roadmap's *autonomous* attacker-agent is `run_autonomous()` — an LLM that, given a
natural-language objective, selects and composes attacks until the oracle fires.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from finagent_redrange.scoring import airq, frameworks
from finagent_redrange.types import Finding, Transcript

if TYPE_CHECKING:
    from finagent_redrange.llm.client import LLMClient
    from finagent_redrange.scenarios.base import Scenario
    from finagent_redrange.target.agent import BankingAgent


def run_campaign(scenario: Scenario, agent: BankingAgent) -> Finding:
    """Execute one scenario end to end and return a scored Finding."""
    scenario.setup(agent)  # plant poisoned docs / arrange state
    transcript: Transcript = scenario.attack(agent)  # drive the conversation
    succeeded = scenario.oracle(agent, transcript)  # did the attack land?

    fw = frameworks.map_finding(scenario)
    score = airq.score(scenario, succeeded=succeeded, controls_on=agent.guardrails.enabled)

    return Finding(
        scenario_id=scenario.id,
        title=scenario.title,
        succeeded=succeeded,
        guardrails_enabled=agent.guardrails.enabled,
        severity=score.band,
        transcript=transcript,
        frameworks=fw,
        airq=score,
        validating_control=scenario.validating_control,
        mitigation_notes=scenario.mitigation_notes,
    )


def run_autonomous(objective: str, agent: BankingAgent, attacker_llm: LLMClient) -> Finding:
    """LLM-driven campaign: the attacker model picks/composes attacks toward `objective`.

    TODO(roadmap): give attacker_llm the seed library + transforms as a toolset, loop until
    an oracle fires or a budget is exhausted, then emit a Finding. This is the v0.2 headline.
    """
    raise NotImplementedError("autonomous attacker-agent is on the roadmap (see README)")
