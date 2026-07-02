"""The red-team engine.

Two modes:
  * `run_campaign` — the scripted path: run one Scenario's hand-written campaign and judge it
    with the scenario oracle (the regression-tested backbone of the range).
  * `run_autonomous` — the strategy-sweep path: an attacker that *composes* seed payloads and
    transforms into candidate campaigns and keeps trying until an oracle fires or a budget is
    spent. The default planner is a deterministic sweep (a fixed product of seeds × transforms,
    offline-safe for CI) — NOT adaptive. It's a pluggable seam: swap in an LLM-driven planner to
    make the attacker actually reason about what to try next.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from finagent_redrange.attacker.transforms import base64_encode, crescendo, roleplay_wrap
from finagent_redrange.scoring import airq, frameworks
from finagent_redrange.types import Finding, Transcript

if TYPE_CHECKING:
    from finagent_redrange.attacker.seeds import Seed
    from finagent_redrange.scenarios.base import Scenario
    from finagent_redrange.target.agent import BankingAgent

#: An oracle judges, from the agent + its transcript, whether the objective was achieved.
Oracle = Callable[["BankingAgent", Transcript], bool]
#: A factory that produces a *fresh* target agent (so each attempt starts from clean state).
AgentFactory = Callable[[], "BankingAgent"]
#: A planner turns the seed library into an ordered stream of (strategy-label, user-turns).
Planner = Callable[[list["Seed"]], Iterator[tuple[str, list[str]]]]


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
        detection=scenario.detection,
    )


# --- autonomous attacker ------------------------------------------------------------------


@dataclass
class AttackAttempt:
    """One candidate campaign the autonomous attacker tried."""

    strategy: str  # e.g. "roleplay(leak-001)"
    messages: list[str]
    succeeded: bool


@dataclass
class AutonomousReport:
    """The record of an autonomous campaign — what was tried and what landed."""

    objective: str
    guardrails_enabled: bool
    succeeded: bool
    attempts_made: int
    winning_strategy: str | None
    attempts: list[AttackAttempt] = field(default_factory=list)
    transcript: Transcript | None = None  # the winning (or last) transcript


def default_planner(seeds: list[Seed]) -> Iterator[tuple[str, list[str]]]:
    """Deterministic strategy stream: for each seed, escalate through transforms.

    Order matters and is intentional — cheaper/encoded probes first, then plain and
    role-wrapped phrasings, then a multi-turn crescendo — so the report shows the attacker
    *working through* options. Replace with an LLM planner for adaptive selection.
    """
    for seed in seeds:
        yield f"base64({seed.id})", [base64_encode(seed.text)]
        yield f"identity({seed.id})", [seed.text]
        yield f"roleplay({seed.id})", [roleplay_wrap(seed.text)]
        yield f"crescendo({seed.id})", crescendo([seed.text])


def run_autonomous(
    make_agent: AgentFactory,
    objective: str,
    oracle: Oracle,
    seeds: list[Seed],
    *,
    planner: Planner = default_planner,
    budget: int = 16,
    guardrails_enabled: bool = False,
) -> AutonomousReport:
    """Compose seeds+transforms into campaigns until the oracle fires or the budget is spent.

    Each attempt runs against a fresh agent from `make_agent`, so success can't leak between
    candidates. Returns a report of every attempt and the winning strategy (if any). With
    controls on, a robust defense yields `succeeded=False` even against many strategies — the
    headline defensive result.
    """
    attempts: list[AttackAttempt] = []
    for strategy, messages in planner(seeds):
        if len(attempts) >= budget:
            break
        agent = make_agent()
        for msg in messages:
            agent.respond(msg)
        landed = oracle(agent, agent.transcript)
        attempts.append(AttackAttempt(strategy=strategy, messages=messages, succeeded=landed))
        if landed:
            return AutonomousReport(
                objective=objective,
                guardrails_enabled=guardrails_enabled,
                succeeded=True,
                attempts_made=len(attempts),
                winning_strategy=strategy,
                attempts=attempts,
                transcript=agent.transcript,
            )
    return AutonomousReport(
        objective=objective,
        guardrails_enabled=guardrails_enabled,
        succeeded=False,
        attempts_made=len(attempts),
        winning_strategy=None,
        attempts=attempts,
        transcript=None,
    )
