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
target/      The system under test: a mock retail-banking agent.
             agent.py wraps an LLM + tools + guardrails. Guardrails are TOGGLEABLE so
             you can run "controls off" (POC lands) vs "controls on" (POC blocked).
attacker/    The red-team engine. engine.py runs a Scenario over multi-turn conversations,
             records the transcript, and calls the scenario oracle to judge success.
             seeds.py loads attack seeds (hook to pull from an external incident DB).
scenarios/   One file per attack class. v0.1 ships indirect prompt injection + data
             poisoning. Each subclasses scenarios/base.Scenario.
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

## v0.1 milestone (ship this first)

Goal: a reviewer can clone, run one command, and see a scorecard proving an attack lands
with controls off and is blocked with controls on.

- [ ] `llm/client.py`: finish `AnthropicClient.complete()`; keep `EchoClient` deterministic.
- [ ] `target/`: implement the 5 tools with permission checks; wire RAG over `knowledge/`.
- [ ] `target/guardrails.py`: implement the input/output checks the two scenarios target.
- [ ] `scenarios/indirect_prompt_injection.py`: poison a retrieved policy doc; oracle =
      agent performs an action the injected text requested (e.g. discloses another
      account's data). Mitigation = output guardrail + retrieval provenance check.
- [ ] `scenarios/data_poisoning.py`: corrupt the trusted knowledge store; oracle = agent
      repeats attacker-controlled false policy. Mitigation = source allowlist + integrity check.
- [ ] `scoring/`: fill the framework lookup tables and AIRQ weights.
- [ ] `tests/test_regression.py`: with guardrails ON, both scenarios must be blocked.
- [ ] `notebooks/v0_1_demo.ipynb`: the narrative walkthrough (the recruiter-facing artifact).

Defer to later: the autonomous attacker-agent loop (`attacker/engine.py` has the seam),
multimodal attacks, model-theft / supply-chain scenarios, CI workflow.

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
