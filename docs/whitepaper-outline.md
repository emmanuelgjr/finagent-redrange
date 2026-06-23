# Whitepaper outline — "Validating Agentic AI Defenses in Financial Services: A Reproducible Red-Team Range"

Target length: 8–12 pages. Audience: AI security engineers and security leadership at a bank.
Purpose: frame the repo as research, not just code. Pairs with the FinAgent-RedRange scorecard.

This plays to your strength (you are a published OWASP author) while the repo answers the
JD's coding/POC must-have. Together they cover nearly the whole job description.

---

## 1. Abstract (½ page)
One paragraph: agentic AI in banking expands the attack surface from "bad text" to real
actions on customer accounts. Pen-test-style point-in-time testing doesn't keep pace with
model and prompt churn. This paper presents a reproducible range that develops POC exploits
against a representative banking agent and validates mitigations end to end, with every
finding mapped to OWASP / MITRE ATLAS / NIST AI RMF.

## 2. Why financial-services agents need their own threat model (1 page)
- From chatbots to tool-using agents: transfers, KYC, support actions = real-world impact.
- Regulatory and trust stakes specific to a bank (auditability, customer PII, fraud).
- The assurance gap: continuous model/prompt change vs point-in-time testing.

## 3. Threat model (1–2 pages)
- The reference agent: planner + tools (balance, transfer, KYC, ticket) + RAG + guardrails.
- Attack surfaces: indirect prompt injection, data poisoning, excessive agency, model theft,
  supply chain. Diagram (reuse the README Mermaid).
- Mapping each surface to OWASP LLM Top 10, OWASP Agentic Top 10 (ASI), MITRE ATLAS.

## 4. Method: a POC-to-validation range (1–2 pages)
- The core invariant: a finding is only "done" when its control is proven by a regression test.
- Black/grey-box discipline (attacker touches only the public surface).
- AIRQ scoring (Attack Surface / Blast Radius / Defense Controls) and why controls-on vs
  controls-off scoring makes the mitigation effect measurable.
- Seeding the attacker from a real-world incident corpus (your incident dataset) — the path
  from curated incidents to executable, framework-mapped test cases.

## 5. Case study 1 — Indirect prompt injection → cross-account disclosure (1 page)
- The poisoned-retrieval setup; the innocent user query; the leak.
- Mapping: LLM01 / ASI-01 / AML.T0051.
- The control (output PII filter + retrieval provenance) and the before/after scorecard rows.

## 6. Case study 2 — Data poisoning → fabricated transfer policy (1 page)
- Corrupting trusted knowledge; the agent confidently states false policy.
- Mapping: LLM04 / ASI-05 / AML.T0020.
- The control (source allowlist + integrity hash) and before/after rows.

## 7. Results (1 page)
- The scorecard: every scenario exploited with controls off, blocked with controls on.
- Where automated coverage is strong vs where human review is still required.
- Honest limitations: mock target, technique categories not novel zero-days, oracle precision.

## 8. From range to continuous assurance (½–1 page)
- Wiring the regression suite into CI; gating GA AI releases on it.
- The roadmap: autonomous attacker-agent for adaptive, multi-turn campaigns at scale.

## 9. Recommendations for AI engineering teams (½ page)
- Prioritised, practical controls keyed to the findings (this is the "advise engineering on
  the most critical threats first" part of the role).

## 10. References
- OWASP GenAI Security Project (LLM Top 10, Agentic Top 10), MITRE ATLAS, NIST AI RMF.
- Your own OWASP publications and incident dataset (cite them — they're differentiators).

---

### Notes
- Keep all numbers from real runs, not asserted — the credibility is in reproducibility.
- One tight blog-length version (~1,500 words) makes a good LinkedIn post to accompany the
  repo; the full paper is the portfolio/interview artifact.
