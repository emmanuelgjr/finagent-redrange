"""Shared fixtures for the export tests.

``findings_off`` / ``findings_on`` run the exact scenario set the CLI ships (``cli.SCENARIOS``)
through the production run path against the offline, deterministic EchoClient — so the export
tests validate the same artifacts a real ``python -m finagent_redrange run`` would produce.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from finagent_redrange.cli import _run_pass

if TYPE_CHECKING:
    from finagent_redrange.types import Finding


@pytest.fixture
def findings_off() -> list[Finding]:
    """One controls-OFF finding per scenario (each attack should land)."""
    return _run_pass("echo", controls_on=False)


@pytest.fixture
def findings_on() -> list[Finding]:
    """One controls-ON finding per scenario (each attack should be blocked)."""
    return _run_pass("echo", controls_on=True)
