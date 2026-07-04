"""Tests for the control-bypass robustness eval.

These lock in the *measured* claims the eval makes, so they can't silently drift:
  1. the naive matcher is genuinely bypassed by every mechanical evasion (the gap is real),
  2. normalization closes ALL of them (the hardening works), and
  3. the semantic-paraphrase residual is honestly reported as still-open (not hidden).
"""

from __future__ import annotations

from finagent_redrange.attacker import robustness


def _report() -> robustness.RobustnessReport:
    return robustness.run_robustness_eval()


def test_naive_baseline_fully_bypassed_by_mechanical() -> None:
    """Every mechanical evasion slips past the naive (normalization-off) matcher — proving the gap
    the eval exists to measure is real, not strawman."""
    r = _report()
    assert r.mechanical_total > 0
    assert r.mechanical_bypass_naive == r.mechanical_total


def test_hardening_blocks_every_mechanical_evasion() -> None:
    """Normalization folds all mechanical evasions back: zero bypass under the hardened matcher."""
    r = _report()
    assert r.mechanical_bypass_hardened == 0
    for c in r.cells:
        if c.kind == "mechanical":
            assert c.bypassed_naive and c.blocked_hardened, (
                f"{c.guardrail}/{c.evasion}: expected naive-bypass, hardened-block"
            )


def test_negative_controls_never_bypass() -> None:
    """The `none`-kind rows (verbatim, alternating case) stay blocked in BOTH columns — the sweep
    isn't rigged by feeding payloads the filter already mishandles."""
    r = _report()
    none_cells = [c for c in r.cells if c.kind == "none"]
    assert none_cells
    for c in none_cells:
        assert c.blocked_naive and c.blocked_hardened, (
            f"{c.guardrail}/{c.evasion} unexpectedly bypassed"
        )


def test_semantic_paraphrase_is_reported_as_residual() -> None:
    """The honest limitation: a semantic paraphrase bypasses even the hardened matcher for every
    heuristic guardrail. A string normalizer cannot recover intent — only a classifier can."""
    r = _report()
    assert r.semantic_total == len(robustness.GUARDRAILS)
    assert r.semantic_bypass_hardened == r.semantic_total


def test_every_guardrail_and_evasion_covered() -> None:
    """The matrix is complete: one cell per (guardrail x evasion)."""
    r = _report()
    assert len(r.cells) == len(robustness.GUARDRAILS) * len(robustness.EVASIONS)
    pairs = {(c.guardrail, c.evasion) for c in r.cells}
    assert len(pairs) == len(r.cells)  # no duplicates


def test_report_writes_markdown(tmp_path) -> None:
    report = robustness.write(tmp_path)
    out = (tmp_path / "robustness.md").read_text(encoding="utf-8")
    assert "control-bypass robustness eval" in out
    assert "semantic paraphrase" in out
    # headline reflects the live numbers
    assert f"{report.mechanical_bypass_hardened}/{report.mechanical_total}" in out
