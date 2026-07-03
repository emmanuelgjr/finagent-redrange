# A guided walkthrough

A narrated tour for a first-time reader: what the range does, how to run it, and what each output
means. For reference-level detail see the [README](../README.md); for the handout exporters see
[docs/HANDOUTS.md](HANDOUTS.md).

## The idea in one minute

FinAgent-RedRange is a **defensive** red-team range. It's not an attack toolkit — it's **evidence
that defenses work**. For each attack class it does three things end to end:

1. **Builds a proof-of-concept exploit** against a bundled *mock* retail-banking AI agent.
2. **Proves a specific guardrail blocks it** — the same attack, run again with controls on, fails.
3. **Locks that in with a regression test**, so a future change that reopens the hole fails CI.

The invariant behind everything: each scenario must be **exploited with controls off** and
**blocked with controls on**. If a control can't flip its scenario's oracle, the scenario is
incomplete. That's the loop a bank actually needs — not "we found a bug," but "we found a bug,
shipped the fix, and proved it holds."

## Run it yourself (offline, no API key)

```bash
pip install -e ".[dev]"
python -m finagent_redrange run     # all 9 scenarios, controls off then on
pytest -q                           # the regression suite
```

Everything runs against a deterministic, offline `EchoClient`, so there's no API key and no network.
The run writes `results/scorecard.{md,json,html}`; open the HTML for a styled report.

## Reading the scorecard

Each row is one scenario. The columns tell a complete story:

- **Controls off / Controls on** — 🔴 exploited then 🟢 blocked. This pairing is the whole point.
- **OWASP LLM / Agentic / ATLAS / NIST** — the framework crosswalk, carried as structured data so a
  finding drops straight into a governance or audit workflow.
- **AIRQ (off → on)** — a risk heuristic that shifts (e.g. High → Medium) when the control engages.
- **Validating control** — the *named* control that blocks this scenario. It's blocked by *that*
  control, not incidentally by another — a property hardened by an adversarial review.

## Under the hood

The agent (`target/`) runs a **plan → act → observe** loop over permission-checked tools, wrapped in
four toggleable guardrail layers:

- **Input** — catches direct prompt-injection phrasing (narrow, so ordinary banking language passes).
- **Retrieval** — source allowlist + integrity hash, an instruction-in-document provenance check, and
  per-session audience scoping.
- **Action** — gates high-risk tool calls (large or unfamiliar transfers) for human confirmation, and
  caps per-request tool consumption.
- **Output** — redacts foreign-account PII, blocks system-prompt leaks, and neutralises links to
  non-allowlisted domains.

An **oracle** decides whether each attack landed by inspecting the transcript. For real-model runs a
semantic *adoption-vs-refutation* judge (`scenarios/judge.py`) avoids a classic false positive: a
model that quotes a poisoned claim only to *refute* it is scored as a refusal, not an exploit.

## The nine scenarios

Full OWASP LLM Top 10 coverage plus a multimodal input surface, each a dedicated POC + control pair:

| Attack | Blocked by |
|---|---|
| Indirect prompt injection → cross-account PII | Output PII filter (+ retrieval provenance) |
| Data poisoning → fabricated policy | Source allowlist + corpus integrity hash |
| Excessive agency → autonomous transfer | Action-authorization guardrail (human-in-the-loop) |
| System-prompt leakage | Output system-prompt-leak detector (canary) |
| Unsafe output handling → malicious link | Output link/markup sanitiser |
| Vector/embedding weakness → cross-session leak | Access-scoped retrieval |
| Unbounded consumption → tool-budget exhaustion | Per-request tool-call budget |
| Supply chain → malicious third-party tool | Verified-publisher tool allowlist |
| Multimodal injection → instruction hidden in an image | Multimodal input guardrail (OCR text as data) |

## The autonomous attacker

`python -m finagent_redrange auto` turns an attacker loose on an objective ("extract the hidden
system prompt"). It has a **pluggable planner**:

- `--planner sweep` (default) — a deterministic sweep over seed payloads × transforms
  (base64, role-play, crescendo). Offline and CI-friendly.
- `--planner llm` (pair with `--model claude`) — an adaptive planner that asks a model which
  seed + transform to try next, given what's already been tried and whether it landed.

The defensive punchline: with controls on, **layered defense holds even as the attacker works through
every strategy it has** — the base64-obfuscated probe slips past the input filter but is caught by the
output detector, and the direct phrasings are caught on the way in.

## Handouts for security teams

A range run can also emit five ready-to-use artifacts (`run --handouts`), each generated from the
run's own evidence and gated by a precision check in CI: a **Sigma** detection pack (with a measured
labeled-replay confusion matrix), a **SARIF 2.1.0** findings run, a **GSN** control-effectiveness
assurance case, a **regulatory crosswalk** (NIST / ISO 42001 / EU AI Act), and a **MITRE ATLAS
Navigator** coverage layer. See [docs/HANDOUTS.md](HANDOUTS.md) for what each provides per persona and
how its precision is validated.

## What it deliberately doesn't claim

Credibility comes from being honest about the edges:

- **AIRQ is an analyst heuristic** for ordering work, not a calibrated risk metric — the controls-on
  score is the control's *asserted* strength, so "High → Medium" is the intended effect, not a
  measured residual risk.
- The offline `EchoClient` models a **worst-case compliant agent**; a frontier model often refuses
  these attacks natively. Native resistance is probabilistic — the *control* is the deterministic
  guarantee, which is the point.
- The pattern-based filters are **heuristics**, bypassable by paraphrase or novel encoding. They raise
  the bar; they are one layer, not a guarantee.
- The Sigma pack's precision is **oracle-fidelity over a labeled corpus**, not a real-world
  false-positive rate. The regulatory crosswalk is **interpretive**, not legal advice.

## Where to go next

- [README](../README.md) — reference-level detail and the architecture map.
- [docs/HANDOUTS.md](HANDOUTS.md) — the five handout exporters in depth.
- [SECURITY.md](../SECURITY.md) — the responsible-disclosure posture.
- [CLAUDE.md](../CLAUDE.md) — design notes for contributors (human or agent).
