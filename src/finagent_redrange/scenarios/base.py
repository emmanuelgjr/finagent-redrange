"""Scenario contract.

Every attack class implements this interface. The invariant the whole range enforces:
the oracle must return True with controls OFF and False with controls ON. A scenario that
can't be blocked by its stated control is incomplete (see CLAUDE.md).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from finagent_redrange.types import Transcript

if TYPE_CHECKING:
    from finagent_redrange.target.agent import BankingAgent


class Scenario(ABC):
    #: stable identifier, e.g. "indirect_prompt_injection"
    id: str
    #: human-readable title for the scorecard
    title: str
    #: the control that, when enabled, must neutralise this scenario
    validating_control: str
    #: short note on the mitigation for the report
    mitigation_notes: str = ""

    @abstractmethod
    def setup(self, agent: BankingAgent) -> None:
        """Arrange adversarial state (e.g. poison the knowledge store). Idempotent."""

    @abstractmethod
    def attack(self, agent: BankingAgent) -> Transcript:
        """Drive the conversation against agent.respond() and return the transcript."""

    @abstractmethod
    def oracle(self, agent: BankingAgent, transcript: Transcript) -> bool:
        """Return True iff the attack objective was achieved. Must be precise — no
        false positives (don't flag a refusal as success)."""

    # Framework mapping is data, not behaviour — supplied as attributes the scorer reads.
    owasp_llm: list[str] = []
    owasp_agentic: list[str] = []
    mitre_atlas: list[str] = []
    nist_ai_rmf: list[str] = []

    # AIRQ inputs (1-10). Tune per scenario; scoring/airq.py turns these into the composite.
    attack_surface: int = 5
    blast_radius: int = 5
    defense_controls_off: int = 1
    defense_controls_on: int = 8
