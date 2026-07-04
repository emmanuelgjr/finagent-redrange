"""Real-model landing-rate evaluation.

The scorecard reports ONE controls-off / controls-on outcome per scenario — a single anecdote.
Against a real (stochastic) model, whether an attack lands varies run to run, so a single pass can
under- or over-state risk. This harness runs each scenario N times against a model and reports the
LANDING RATE with a 95% Wilson score interval — the honest "how often does this actually land?".

Offline note: the ``EchoClient`` is deterministic, so every trial is identical and the rate is 0% or
100% with a degenerate interval. The statistics are meaningful only against a real model
(``--model claude``), where the harness surfaces run-to-run variance. The Wilson math and the
plumbing are CI-tested here; the variance is an opt-in real-model measurement.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from finagent_redrange.attacker.engine import run_campaign

if TYPE_CHECKING:
    from finagent_redrange.scenarios.base import Scenario
    from finagent_redrange.target.agent import BankingAgent

#: 95% two-sided standard-normal quantile.
_Z95 = 1.959963984540054


def wilson_interval(successes: int, n: int, z: float = _Z95) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion — well-behaved at 0/1 and small n where
    the normal approximation breaks. Returns (low, high) clamped to [0, 1]; n == 0 -> (0.0, 1.0)."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


@dataclass
class ScenarioEval:
    scenario_id: str
    title: str
    trials: int
    landed: int
    controls_on: bool

    @property
    def rate(self) -> float:
        return self.landed / self.trials if self.trials else 0.0

    @property
    def ci(self) -> tuple[float, float]:
        return wilson_interval(self.landed, self.trials)


def run_model_eval(
    scenarios: list[Scenario],
    make_agent: Callable[[], BankingAgent],
    trials: int,
    *,
    controls_on: bool,
) -> list[ScenarioEval]:
    """Run each scenario ``trials`` times against a FRESH agent per trial; count oracle firings.

    ``make_agent`` returns a clean agent (with the desired control state baked in) so no adversarial
    state leaks between trials. Under a real model the per-trial outcome varies; under EchoClient it
    is constant.
    """
    out: list[ScenarioEval] = []
    for scenario in scenarios:
        landed = sum(run_campaign(scenario, make_agent()).succeeded for _ in range(trials))
        out.append(ScenarioEval(scenario.id, scenario.title, trials, landed, controls_on))
    return out


def _pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def render_markdown(evals: list[ScenarioEval], model: str, controls_on: bool) -> str:
    state = "controls ON" if controls_on else "controls OFF"
    trials = evals[0].trials if evals else 0
    lines = [
        "# FinAgent-RedRange — model landing-rate eval",
        "",
        f"Landing rate over **{trials}** trials per scenario against `{model}` ({state}), with a",
        "95% Wilson score interval. The rate is *how often the oracle fired* across the runs.",
        "",
    ]
    if model in ("echo", "offline"):
        lines += [
            "> **Note:** the offline EchoClient is deterministic — every trial is identical, so a",
            "> rate is 0% or 100% and the interval is degenerate. Run `--model claude` for real",
            "> run-to-run variance; the numbers below only exercise the harness + interval math.",
            "",
        ]
    lines += [
        "| Scenario | Trials | Landed | Landing rate | 95% CI (Wilson) |",
        "|---|---|---|---|---|",
    ]
    for e in evals:
        lo, hi = e.ci
        lines.append(
            f"| {e.title} | {e.trials} | {e.landed} | {_pct(e.rate)} | {_pct(lo)}–{_pct(hi)} |"
        )
    return "\n".join(lines) + "\n"


def write(evals: list[ScenarioEval], out_dir: Path, *, model: str, controls_on: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "model_eval.md").write_text(
        render_markdown(evals, model, controls_on), encoding="utf-8"
    )
