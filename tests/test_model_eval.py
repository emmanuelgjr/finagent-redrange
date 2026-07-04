"""Tests for the model landing-rate eval: the Wilson-interval math and the harness plumbing.

The statistics only vary against a real (stochastic) model; against the deterministic EchoClient a
scenario lands every trial (controls off) or never (controls on), which is exactly what lets us
CI-test the harness end to end without a network call.
"""

from __future__ import annotations

from functools import partial

import pytest

from finagent_redrange.attacker.model_eval import run_model_eval, wilson_interval
from finagent_redrange.cli import build_agent
from finagent_redrange.scenarios.indirect_prompt_injection import IndirectPromptInjectionScenario


def test_wilson_degenerate_and_bounds() -> None:
    assert wilson_interval(0, 0) == (0.0, 1.0)  # no trials -> maximally uncertain
    lo0, hi0 = wilson_interval(0, 10)
    assert lo0 == pytest.approx(0.0, abs=1e-9) and 0.0 < hi0 < 1.0  # all-fail: lower bound ~0
    lo1, hi1 = wilson_interval(10, 10)
    assert hi1 == pytest.approx(1.0, abs=1e-9) and 0.0 < lo1 < 1.0  # all-land: upper bound ~1


def test_wilson_interval_brackets_the_estimate() -> None:
    lo, hi = wilson_interval(50, 100)
    assert lo < 0.5 < hi
    assert abs(lo - 0.404) < 0.01 and abs(hi - 0.596) < 0.01  # textbook Wilson bounds


def test_wilson_narrows_with_more_trials() -> None:
    lo_small, hi_small = wilson_interval(5, 10)
    lo_big, hi_big = wilson_interval(50, 100)  # same 50% rate, 10x the trials
    assert (hi_big - lo_big) < (hi_small - lo_small)


@pytest.mark.parametrize(("controls_on", "expected_rate"), [(False, 1.0), (True, 0.0)])
def test_harness_counts_deterministic_echo(controls_on: bool, expected_rate: float) -> None:
    """Against the deterministic echo client a landing scenario fires every trial (controls off) or
    never (controls on) — verifying the harness runs fresh agents and counts correctly."""
    trials = 5
    evals = run_model_eval(
        [IndirectPromptInjectionScenario()],
        partial(build_agent, "echo", controls_on),
        trials,
        controls_on=controls_on,
    )
    assert len(evals) == 1
    e = evals[0]
    assert e.trials == trials
    assert e.rate == expected_rate
    assert e.landed == int(expected_rate * trials)
