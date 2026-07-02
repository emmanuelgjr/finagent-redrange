"""Scenario contract.

Every attack class implements this interface. The invariant the whole range enforces:
the oracle must return True with controls OFF and False with controls ON. A scenario that
can't be blocked by its stated control is incomplete (see CLAUDE.md).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from finagent_redrange.types import DetectionSignature, Transcript

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
        """Arrange adversarial state (e.g. poison the knowledge store).

        Called exactly once against a *fresh* agent (engine.run_campaign builds one per run).
        It is NOT safe to re-invoke on the same agent — inject() appends, so a second call
        double-poisons the corpus.
        """

    @abstractmethod
    def attack(self, agent: BankingAgent) -> Transcript:
        """Drive the conversation against agent.respond() and return the transcript."""

    @abstractmethod
    def oracle(self, agent: BankingAgent, transcript: Transcript) -> bool:
        """Return True iff the attack objective was achieved. Must be precise — no
        false positives (don't flag a refusal as success)."""

    #: How a landed instance of this attack appears in a transcript — an oracle-faithful,
    #: portable description the detection exporters render (Sigma) and the labeled-replay harness
    #: validates against. Co-located with the oracle on purpose: a change to the oracle that isn't
    #: mirrored here is caught by the oracle-equivalence test (tests/test_export_sigma.py).
    detection: DetectionSignature | None = None

    # Framework mapping is data, not behaviour — supplied as attributes the scorer reads.
    owasp_llm: list[str] = []
    owasp_agentic: list[str] = []  # OWASP Agentic "Threats & Mitigations" T-codes (T1–T15)
    owasp_agentic_top10: list[str] = []  # OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)
    mitre_atlas: list[str] = []
    nist_ai_rmf: list[str] = []

    # AIRQ inputs (1-10). Tune per scenario; scoring/airq.py turns these into the composite.
    attack_surface: int = 5
    blast_radius: int = 5
    defense_controls_off: int = 1
    defense_controls_on: int = 8
