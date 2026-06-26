# Whitepaper outline — "Validating Agentic AI Defenses in Financial Services: A Reproducible Red-Team Range"

Target length: 8–12 pages. Audience: AI security engineers and security leadership at a bank.
Purpose: frame the repo as research, not just code. Pairs with the FinAgent-RedRange scorecard.

The paper frames the range as research; the repo is the reproducible artifact behind it. The
two are meant to be read together — the scorecard supplies every number the paper cites.

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
- The reference agent: a plan→act→observe tool loop over five permission-checked tools
  (balance, transfer, KYC, list-transactions, support ticket) + RAG + toggleable guardrails
  (input / retrieval / action / output).
- Attack surfaces (implemented): indirect prompt injection, data poisoning, excessive agency,
  system-prompt leakage, unsafe output handling; (roadmap) model theft, supply chain. Diagram
  (reuse the README Mermaid).
- Mapping each surface to OWASP LLM Top 10, OWASP Agentic AI Threats & Mitigations (T1–T15),
  MITRE ATLAS, and NIST AI RMF. Be explicit where a surface has no honest agentic mapping.

## 4. Method: a POC-to-validation range (1–2 pages)
- The core invariant: a finding is only "done" when its control is proven by a regression test.
- Black/grey-box discipline (attacker touches only the public surface).
- AIRQ scoring (Attack Surface / Blast Radius / Defense Controls) and why controls-on vs
  controls-off scoring makes the mitigation effect measurable.
- Two engines: scripted campaigns (the regression backbone) and an **autonomous attacker** that
  composes seeds × transforms until an oracle fires (deterministic offline; an LLM-planner seam).
- Self-validation as methodology: a multi-agent **adversarial review** of the harness itself
  (oracle soundness, control attribution, framework accuracy, guardrail over-blocking).
- Seeding the attacker from a real-world incident corpus (your incident dataset) — the path
  from curated incidents to executable, framework-mapped test cases.

## 5. Case study 1 — Indirect prompt injection → cross-account disclosure (1 page)
- The poisoned-retrieval setup; the innocent user query; the leak.
- Mapping: LLM01·LLM02 / Agentic T6 / AML.T0051.001 (+ AML.T0057).
- The control (output PII filter + retrieval provenance) and the before/after scorecard rows.

## 6. Case study 2 — Data poisoning → fabricated transfer policy (1 page)
- Corrupting trusted knowledge; the agent confidently states false policy.
- Mapping: LLM04·LLM09 / Agentic T1 / AML.T0070 (RAG Poisoning; AML.T0020 training-time rel.).
- The control (source allowlist + integrity hash) and before/after rows.

## 6b. Case studies 3–5 (brief, ~½ page each)
- **Excessive agency → autonomous high-value transfer.** LLM06·LLM01 / Agentic T2·T3 /
  AML.T0053 (AI Agent Tool Invocation) + AML.T0048.000. Control: action-authorization guardrail
  (human-in-the-loop for high-risk tool calls).
- **System-prompt leakage → hidden instructions disclosed.** LLM07·LLM01 / AML.T0056 (Extract
  LLM System Prompt). Control: output system-prompt-leak detector (canary token + verbatim-span
  block).
- **Unsafe output handling → malicious link relayed.** LLM05·LLM02 / AML.T0052.000. Control:
  output link/markup sanitiser (domain allowlist).

## 7. Results (1 page)
- The scorecard: every scenario exploited with controls off, blocked with controls on.
- Where automated coverage is strong vs where human review is still required.
- Honest limitations: mock target, technique categories not novel zero-days, oracle precision.

## 8. From range to continuous assurance (½–1 page)
- Wiring the regression suite into CI; gating GA AI releases on it.
- The roadmap: an LLM-driven autonomous *planner* for adaptive, multi-turn campaigns at scale
  (the deterministic composer already ships).

## 9. Recommendations for AI engineering teams (½ page)
- Prioritised, practical controls keyed to the findings (this is the "advise engineering on
  the most critical threats first" part of the role).

## 10. References
- OWASP GenAI Security Project (LLM Top 10, Agentic AI Threats & Mitigations), MITRE ATLAS, NIST AI RMF.
- Relevant OWASP publications and incident datasets, cited where they inform the mappings.

---

### Notes
- Keep all numbers from real runs, not asserted — the credibility is in reproducibility.
- A tight blog-length version (~1,500 words) works as a companion post to the repo; the full
  paper is the long-form writeup.
