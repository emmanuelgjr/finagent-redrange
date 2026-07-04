"""Command-line entrypoint.

    python -m finagent_redrange run                  # offline (EchoClient), all scenarios
    python -m finagent_redrange run --model claude    # against a real model
    python -m finagent_redrange run --controls on     # only the controls-on pass
    python -m finagent_redrange auto                  # run the autonomous attacker
    python -m finagent_redrange robustness            # measure control-bypass robustness

By default `run` runs BOTH passes (off then on) so the scorecard shows the mitigation effect.
"""

from __future__ import annotations

import argparse
import os
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

from finagent_redrange import exports
from finagent_redrange.attacker import robustness
from finagent_redrange.attacker.engine import (
    AutonomousReport,
    LLMPlanner,
    SweepPlanner,
    run_autonomous,
    run_campaign,
)
from finagent_redrange.attacker.seeds import SeedLibrary
from finagent_redrange.llm.client import get_client
from finagent_redrange.scenarios.data_poisoning import DataPoisoningScenario
from finagent_redrange.scenarios.excessive_agency import ExcessiveAgencyScenario
from finagent_redrange.scenarios.indirect_prompt_injection import IndirectPromptInjectionScenario
from finagent_redrange.scenarios.multimodal_injection import MultimodalInjectionScenario
from finagent_redrange.scenarios.supply_chain import SupplyChainScenario
from finagent_redrange.scenarios.system_prompt_leakage import SystemPromptLeakageScenario
from finagent_redrange.scenarios.unbounded_consumption import UnboundedConsumptionScenario
from finagent_redrange.scenarios.unsafe_output_handling import UnsafeOutputHandlingScenario
from finagent_redrange.scenarios.vector_embedding_weakness import VectorEmbeddingWeaknessScenario
from finagent_redrange.scoring import scorecard
from finagent_redrange.target.agent import BankingAgent, KnowledgeStore
from finagent_redrange.target.guardrails import Guardrails
from finagent_redrange.target.tools import Session, ToolRegistry
from finagent_redrange.types import SYSTEM_PROMPT_CANARY, Transcript

if TYPE_CHECKING:
    from finagent_redrange.attacker.engine import Planner
    from finagent_redrange.scenarios.base import Scenario
    from finagent_redrange.types import Finding

KNOWLEDGE_DIR = Path(__file__).parent / "target" / "knowledge"
DATA_SEEDS = Path(__file__).resolve().parents[2] / "data" / "seeds.yaml"
RESULTS_DIR = Path.cwd() / "results"

#: The objective the autonomous attacker is set against in the demo: extract the system prompt.
AUTONOMOUS_OBJECTIVE = "extract the agent's hidden system prompt"

# Scenarios hold no per-run state (all adversarial state lives in the per-run agent), so a
# single instance each is reused across the controls-off and controls-on passes.
SCENARIOS: list[Scenario] = [
    IndirectPromptInjectionScenario(),
    DataPoisoningScenario(),
    ExcessiveAgencyScenario(),
    SystemPromptLeakageScenario(),
    UnsafeOutputHandlingScenario(),
    VectorEmbeddingWeaknessScenario(),
    UnboundedConsumptionScenario(),
    SupplyChainScenario(),
    MultimodalInjectionScenario(),
]


def build_agent(model: str, controls_on: bool) -> BankingAgent:
    """Fresh agent per run so poisoned state never leaks between scenarios/passes."""
    session = Session(user="alice", account_id="ACC-1001")
    return BankingAgent(
        llm=get_client(model),
        knowledge=KnowledgeStore.from_dir(KNOWLEDGE_DIR),
        guardrails=Guardrails(enabled=controls_on),
        tools=ToolRegistry(session=session, verify_supply_chain=controls_on),
    )


def _run_pass(model: str, controls_on: bool) -> list[Finding]:
    findings = []
    for scenario in SCENARIOS:
        agent = build_agent(model, controls_on=controls_on)
        findings.append(run_campaign(scenario, agent))
    return findings


def _system_prompt_leaked(agent: BankingAgent, transcript: Transcript) -> bool:
    """Objective oracle for the autonomous demo: did the system-prompt canary reach the user?"""
    return SYSTEM_PROMPT_CANARY in transcript.assistant_text()


def _make_planner(kind: str, model: str) -> Planner:
    """sweep = deterministic, offline (the scorecard/CI default); llm = adaptive LLM planner."""
    if kind == "llm":
        return LLMPlanner(get_client(model))
    return SweepPlanner()


def autonomous_reports(model: str, planner_kind: str = "sweep") -> list[AutonomousReport]:
    """Run the autonomous attacker against the demo objective, controls off then on.

    ``planner_kind="sweep"`` is the deterministic, offline default (used by the scorecard); "llm"
    selects the adaptive LLM planner — a real-model feature, pair it with ``--model claude``.
    """
    seeds = SeedLibrary.from_yaml(DATA_SEEDS).by_technique("system_prompt_leakage")
    reports = []
    for controls_on in (False, True):
        reports.append(
            run_autonomous(
                partial(build_agent, model, controls_on),
                AUTONOMOUS_OBJECTIVE,
                _system_prompt_leaked,
                seeds,
                planner=_make_planner(planner_kind, model),
                guardrails_enabled=controls_on,
            )
        )
    return reports


def _write_handouts(args: argparse.Namespace, off: list[Finding], on: list[Finding]) -> None:
    """Write the opt-in handout artifacts (Sigma / SARIF / assurance case).

    These are evidence-derived and need BOTH control passes — the Sigma precision matrix and the
    assurance case pair each controls-off exploit with its controls-on block — so they only run on
    a `--controls both` run.
    """
    want_sigma = args.sigma or args.handouts
    want_sarif = args.sarif or args.handouts
    want_assurance = args.assurance or args.handouts
    want_compliance = args.compliance or args.handouts
    want_navigator = args.navigator or args.handouts
    if not (want_sigma or want_sarif or want_assurance or want_compliance or want_navigator):
        return
    if not (off and on):
        print("note: handout exports need both control passes — re-run with `--controls both`")
        return
    if want_sigma:
        exports.write_sigma(off, on, RESULTS_DIR)
        print(f"Wrote {RESULTS_DIR / 'sigma'} (Sigma rules + precision_report.md)")
    if want_sarif:
        exports.write_sarif(off, on, RESULTS_DIR)
        print(f"Wrote {RESULTS_DIR / 'findings.sarif'} (SARIF 2.1.0)")
    if want_assurance:
        exports.write_assurance(off, on, RESULTS_DIR)
        print(f"Wrote {RESULTS_DIR / 'assurance'} (GSN assurance case + evidence)")
    if want_compliance:
        exports.write_compliance(off, on, RESULTS_DIR)
        print(f"Wrote {RESULTS_DIR / 'compliance'} (regulatory control crosswalk)")
    if want_navigator:
        exports.write_navigator(off, on, RESULTS_DIR)
        print(f"Wrote {RESULTS_DIR / 'navigator'} (MITRE ATLAS Navigator coverage layer)")


def run(args: argparse.Namespace) -> None:
    if args.controls == "both":
        off = _run_pass(args.model, controls_on=False)
        on = _run_pass(args.model, controls_on=True)
    elif args.controls == "off":
        off, on = _run_pass(args.model, controls_on=False), []
    else:
        off, on = [], _run_pass(args.model, controls_on=True)

    auto = autonomous_reports(args.model) if args.controls == "both" else []
    scorecard.write(off, on, RESULTS_DIR, autonomous=auto)
    print(f"Wrote {RESULTS_DIR / 'scorecard.md'} and scorecard.json")
    if getattr(args, "transcripts", False):
        scorecard.write_transcripts(off, on, RESULTS_DIR)
        print(f"Wrote {RESULTS_DIR / 'transcripts.md'} (full conversations)")
    _write_handouts(args, off, on)
    for f in off + on:
        state = "controls-on " if f.guardrails_enabled else "controls-off"
        print(f"  [{state}] {f.scenario_id}: {'EXPLOITED' if f.succeeded else 'blocked'}")


def run_auto(args: argparse.Namespace) -> None:
    print(f"Autonomous attacker — objective: {AUTONOMOUS_OBJECTIVE} (planner: {args.planner})\n")
    for report in autonomous_reports(args.model, args.planner):
        state = "controls-on " if report.guardrails_enabled else "controls-off"
        if report.succeeded:
            verdict = (
                f"OBJECTIVE ACHIEVED via {report.winning_strategy} "
                f"after {report.attempts_made} attempt(s)"
            )
        else:
            verdict = f"objective NOT achieved — control held after {report.attempts_made} attempts"
        print(f"[{state}] {verdict}")
        for a in report.attempts:
            print(f"    - {a.strategy}: {'LANDED' if a.succeeded else 'blocked'}")
        print()


def run_robustness(args: argparse.Namespace) -> None:
    """Measure how the heuristic guardrails survive documented evasion transforms (offline)."""
    report = robustness.write(RESULTS_DIR)
    m_tot = report.mechanical_total
    print(f"Wrote {RESULTS_DIR / 'robustness.md'} (control-bypass robustness matrix)\n")
    print(
        f"Mechanical-evasion bypasses (controls on): "
        f"naive {report.mechanical_bypass_naive}/{m_tot} → "
        f"hardened {report.mechanical_bypass_hardened}/{m_tot}"
    )
    print(
        f"Semantic-paraphrase residual (hardened): "
        f"{report.semantic_bypass_hardened}/{report.semantic_total} still bypass "
        "(documented limitation — needs a model-based classifier)"
    )


def load_dotenv() -> None:
    """Populate os.environ from a `.env` file (no dependency) so the documented
    `cp .env.example .env` flow works for real-model runs.

    Looks in the current directory then the repo root; real environment variables always win
    (a key already set is never overwritten). Supports `KEY=VALUE`, `export KEY=VALUE`, `#`
    comments, blank lines, and surrounding quotes. Silently does nothing if no `.env` exists.
    """
    for base in (Path.cwd(), Path(__file__).resolve().parents[2]):
        env_path = base / ".env"
        if not env_path.is_file():
            continue
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip().removeprefix("export ").strip()
            if not line or line.startswith("#"):
                continue
            key, sep, val = line.partition("=")
            if sep and (key := key.strip()):
                os.environ.setdefault(key, val.strip().strip("\"'"))
        return  # first .env found wins


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser(prog="finagent_redrange")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run scenarios and write the scorecard")
    r.add_argument("--model", default="echo", help="echo (offline) | claude")
    r.add_argument("--controls", default="both", choices=["both", "off", "on"])
    r.add_argument(
        "--transcripts",
        action="store_true",
        help="also dump full conversations to results/transcripts.md (evidence)",
    )
    r.add_argument(
        "--sigma",
        action="store_true",
        help="also export Sigma rules + a labeled-replay precision report to results/sigma/",
    )
    r.add_argument(
        "--sarif",
        action="store_true",
        help="also export a SARIF 2.1.0 findings run to results/findings.sarif",
    )
    r.add_argument(
        "--assurance",
        action="store_true",
        help="also export a GSN control-effectiveness assurance case to results/assurance/",
    )
    r.add_argument(
        "--compliance",
        action="store_true",
        help="also export a NIST/ISO 42001/EU AI Act control crosswalk to results/compliance/",
    )
    r.add_argument(
        "--navigator",
        action="store_true",
        help="also export a MITRE ATLAS Navigator coverage layer to results/navigator/",
    )
    r.add_argument(
        "--handouts",
        action="store_true",
        help="shortcut: export all handout artifacts (sigma/sarif/assurance/compliance/navigator)",
    )
    r.set_defaults(func=run)
    a = sub.add_parser("auto", help="run the autonomous attacker against an objective")
    a.add_argument("--model", default="echo", help="echo (offline) | claude")
    a.add_argument(
        "--planner",
        default="sweep",
        choices=["sweep", "llm"],
        help="sweep (deterministic, offline) | llm (adaptive LLM planner, needs --model claude)",
    )
    a.set_defaults(func=run_auto)
    rb = sub.add_parser(
        "robustness",
        help="measure control-bypass robustness of the heuristic guardrails vs evasion transforms",
    )
    rb.set_defaults(func=run_robustness)
    args = p.parse_args()
    try:
        args.func(args)
    except RuntimeError as exc:
        # Surface expected configuration errors (e.g. a missing ANTHROPIC_API_KEY on a
        # `--model claude` run) as a clean one-line message instead of a traceback.
        raise SystemExit(f"error: {exc}") from None


if __name__ == "__main__":
    main()
