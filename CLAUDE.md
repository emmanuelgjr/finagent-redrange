# CLAUDE.md

Context for Claude Code working in this repository. Read this first.

## What this project is

**FinAgent-RedRange** is a self-contained sandbox for **defensive** AI security research.
It develops proof-of-concept (POC) exploits against a *mock* financial-services AI agent,
then validates that mitigations close them — end to end, from POC through regression test.

This is a portfolio piece demonstrating the work of a Principal AI Security Researcher:
identify how agentic AI systems could be attacked, build reproducible POCs, validate the
fixes, and map every finding to the frameworks engineering and risk teams already use.

The deliverable is **evidence that defenses work**, not an attack toolkit. Every scenario
exists to be *blocked* once the corresponding control is enabled.

## Hard scope boundaries (do not cross)

- The **only** target is the bundled mock agent in `src/finagent_redrange/target/`.
  Never add code that points attacks at real, third-party, or production systems.
- Keep payloads at the level of publicly documented technique *categories* (OWASP LLM Top 10,
  OWASP Agentic Top 10, MITRE ATLAS). The novelty is in the *harness, mapping, and
  mitigation-validation*, not in weaponizing novel zero-days against live targets.
- Every scenario must ship with (a) an oracle that detects success and (b) a mitigation
  that, when enabled, makes the oracle return `False`. No exploit without its fix.
- Preserve `SECURITY.md` (responsible-disclosure posture). Don't remove safety framing.

## Architecture

```
target/      The system under test: a mock retail-banking agent. agent.py runs a
             plan->act->observe tool loop over permission-checked tools, with TOGGLEABLE
             guardrails (input / retrieval / action / output) so you can run "controls off"
             (POC lands) vs "controls on" (POC blocked).
attacker/    The red-team engine. engine.run_campaign runs a Scenario's scripted campaign and
             judges it with the oracle. engine.run_autonomous composes seeds x transforms until
             an oracle fires (deterministic offline; an LLM-driven planner is the seam).
             seeds.py loads attack seeds (hook to pull from an external incident DB).
scenarios/   One file per attack class. v0.2 ships five: indirect prompt injection, data
             poisoning, excessive agency, system-prompt leakage, unsafe output handling.
             Each subclasses scenarios/base.Scenario.
scoring/     frameworks.py maps a Finding to OWASP/ATLAS/NIST IDs (the "crosswalk").
             airq.py scores Attack Surface / Blast Radius / Defense Controls.
             scorecard.py renders the results table (markdown + JSON) into results/.
llm/         Provider-agnostic client. EchoClient is deterministic + offline so tests
             run with no API key. AnthropicClient is the real one (wire it up).
types.py     Shared dataclasses (Finding, Turn, Transcript, ...). Import from here to
             avoid circular deps.
cli.py       One-command entrypoint: `python -m finagent_redrange run`.
```

Data flow: `cli.run()` → for each `Scenario`: `setup(target)` → `engine.run_campaign()` →
`scenario.oracle(transcript)` → `Finding` → `frameworks.map_finding()` + `airq.score()` →
`Scorecard` → `results/scorecard.md`.

## Status

**v0.1 — shipped.** A reviewer can clone, run one command, and see a scorecard proving each
attack lands with controls off and is blocked with controls on.

- [x] `llm/client.py`: `AnthropicClient.complete()` returns structured `ModelResponse`;
      `EchoClient` is deterministic + offline.
- [x] `target/`: 5 permission-checked tools; RAG over `knowledge/`.
- [x] `target/guardrails.py`: input / retrieval / action / output checks.
- [x] `scenarios/indirect_prompt_injection.py` + `scenarios/data_poisoning.py` with oracles.
- [x] `scoring/`: framework lookup tables + AIRQ weights; scorecard (md/json/html).
- [x] `tests/test_regression.py`: with guardrails ON, every scenario stays blocked.
- [x] `notebooks/` narrative walkthrough; CI workflow (ruff + mypy + pytest, 3.11/3.12).

**v0.2 — shipped.** Built on v0.1:

- [x] Permission-checked **tool-execution loop** in `target/agent.py` (`MAX_PLANNING_STEPS`);
      `EchoClient` deterministically emits tool calls so the loop is exercised offline.
- [x] Three more scenarios: **excessive agency** (action-authorization control),
      **system-prompt leakage** (output canary detector), **unsafe output handling** (link
      sanitiser). Five total: dedicated POC+control for 5 primary OWASP risks
      (LLM01/04/05/06/07), mapped across 7/10 once impact tags (LLM02, LLM09) are counted.
- [x] **Autonomous attacker** (`attacker/run_autonomous` + `auto` CLI): composes seeds ×
      transforms until an oracle fires; offline-deterministic.
- [x] Richer scorecard: summary, OWASP coverage matrix, AIRQ off→on, HTML report.
- [x] Hardened via a multi-agent **adversarial review** (oracle soundness, control
      attribution, framework accuracy, guardrail over-blocking). See `tests/test_guardrails.py`.

**Defer to later (the next roadmap):** an LLM-driven autonomous *planner* (replace the
deterministic composer), semantic oracles for real-model runs, the remaining OWASP scenarios
(LLM03 supply chain, LLM08 vector/embedding, LLM10 unbounded consumption), multimodal attacks,
and seeding the attacker from a real incident corpus (`SeedLibrary.from_incident_db`).

## Conventions

- Python 3.11+. Type hints everywhere. `dataclasses` for data, `Protocol` for seams.
- No network calls in tests — use `EchoClient`. Tests must pass offline.
- Keep `target/` and `attacker/` decoupled: the attacker only talks to the agent's public
  `respond()` surface, never reaches into its internals (black/grey-box discipline).
- Findings carry framework IDs and AIRQ sub-scores as structured fields, never free text only.
- Format with `ruff format`, lint with `ruff check`, type-check with `mypy src`.
- Run: `pip install -e ".[dev]"` then `python -m finagent_redrange run` and `pytest`.

## Useful commands

```bash
pip install -e ".[dev]"          # editable install with dev tools
python -m finagent_redrange run  # run all scenarios, write results/scorecard.md
python -m finagent_redrange run --controls on   # run with mitigations enabled
pytest -q                        # regression suite (attacks must stay blocked)
ruff check . && mypy src         # lint + types
```
