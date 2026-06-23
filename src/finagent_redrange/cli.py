"""Command-line entrypoint.

    python -m finagent_redrange run                 # offline (EchoClient), all scenarios
    python -m finagent_redrange run --model claude   # against a real model
    python -m finagent_redrange run --controls on    # only the controls-on pass

By default it runs BOTH passes (off then on) so the scorecard shows the mitigation effect.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TYPE_CHECKING

from finagent_redrange.attacker.engine import run_campaign
from finagent_redrange.llm.client import get_client
from finagent_redrange.scenarios.data_poisoning import DataPoisoningScenario
from finagent_redrange.scenarios.indirect_prompt_injection import IndirectPromptInjectionScenario
from finagent_redrange.scoring import scorecard
from finagent_redrange.target.agent import BankingAgent, KnowledgeStore
from finagent_redrange.target.guardrails import Guardrails
from finagent_redrange.target.tools import Session, ToolRegistry

if TYPE_CHECKING:
    from finagent_redrange.types import Finding

KNOWLEDGE_DIR = Path(__file__).parent / "target" / "knowledge"
RESULTS_DIR = Path.cwd() / "results"

SCENARIOS = [IndirectPromptInjectionScenario, DataPoisoningScenario]


def build_agent(model: str, controls_on: bool) -> BankingAgent:
    """Fresh agent per run so poisoned state never leaks between scenarios/passes."""
    session = Session(user="alice", account_id="ACC-1001")
    return BankingAgent(
        llm=get_client(model),
        knowledge=KnowledgeStore.from_dir(KNOWLEDGE_DIR),
        guardrails=Guardrails(enabled=controls_on),
        tools=ToolRegistry(session=session),
    )


def _run_pass(model: str, controls_on: bool) -> list[Finding]:
    findings = []
    for scenario_cls in SCENARIOS:
        agent = build_agent(model, controls_on=controls_on)
        findings.append(run_campaign(scenario_cls(), agent))
    return findings


def run(args: argparse.Namespace) -> None:
    if args.controls == "both":
        off = _run_pass(args.model, controls_on=False)
        on = _run_pass(args.model, controls_on=True)
    elif args.controls == "off":
        off, on = _run_pass(args.model, controls_on=False), []
    else:
        off, on = [], _run_pass(args.model, controls_on=True)

    scorecard.write(off, on, RESULTS_DIR)
    print(f"Wrote {RESULTS_DIR / 'scorecard.md'} and scorecard.json")
    for f in off + on:
        state = "controls-on " if f.guardrails_enabled else "controls-off"
        print(f"  [{state}] {f.scenario_id}: {'EXPLOITED' if f.succeeded else 'blocked'}")


def main() -> None:
    p = argparse.ArgumentParser(prog="finagent_redrange")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run scenarios and write the scorecard")
    r.add_argument("--model", default="echo", help="echo (offline) | claude")
    r.add_argument("--controls", default="both", choices=["both", "off", "on"])
    r.set_defaults(func=run)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
