# Recommendations to Engineering — Prioritized Controls for the FinAgent Agent

Audience: the engineering team shipping the banking agent. This is the *advisory* companion to
the scorecard — "here is what to fix, in what order, and what you'll still be exposed to after."
Ordered by **blast radius first, then likelihood** — fix top-down. Each control is the one this
range validates with a controls-on regression test; each **residual risk** is the gap an attacker
still has *after* the control ships, so the team doesn't over-trust it.

| # | Threat (OWASP) | Why ranked here | Control to ship | Owner | Residual risk | Tradeoff |
|---|---|---|---|---|---|---|
| 1 | **Excessive agency → autonomous transfer** (LLM06) | Highest blast radius — moves customer money; the per-tool permission check passes for a coerced *own-account* transfer | Action-authorization gate: human confirmation for transfers ≥ threshold or to unrecognised payees | Payments / agent-platform | Attacker stays just under the limit or drips many small transfers | Confirmation latency on high-value actions — gate narrowly (e.g. ≥$1k or new payee) so routine transfers are untouched |
| 2 | **Supply chain → malicious third-party tool** (LLM03) | Attacker code runs with the agent's full reach (data exfil); **demonstrated landing on a real model** ([real-model-note](real-model-note.md)) — it reads as "being helpful," so the model isn't refusing anything | Verified-publisher allowlist: expose/permit only tools from verified suppliers; refuse to register or invoke unverified components | Agent-platform / procurement | A verified-but-compromised upstream supplier; verification is of the *publisher*, not the tool's runtime behaviour | Slower tool/plugin onboarding — each new supplier needs verification |
| 3 | **Indirect prompt injection → cross-account PII** (LLM01/02) | Customer-data + regulatory exposure; rides in via trusted RAG content | Output PII filter (redact accounts/balances not owned by the session) + retrieval-provenance check | Agent-platform / data-gov | Ownership-scoped pattern match — novel PII formats or paraphrased data can slip | Possible over-redaction — scope to foreign-account identifiers, monitor false positives |
| 4 | **Vector/embedding weakness → cross-session leak** (LLM08) | Cross-tenant exposure — a shared vector store surfaces another customer's private record to this session | Access-scoped retrieval: tag records with an audience and drop any retrieved chunk whose audience isn't the asking session | Data-platform / retrieval | Only as good as the audience labels — a mis-tagged or untagged record still leaks | Every stored record must carry correct access metadata at ingest |
| 5 | **Data / knowledge poisoning → fabricated policy** (LLM04/09) | Agent states false policy ("transfers need no verification") — erodes trust, enables fraud | Source allowlist + corpus integrity hash (signed manifest); reject untrusted/tampered chunks pre-retrieval | Knowledge-base / ingestion | Allowlisted-but-compromised upstream source; integrity only catches post-load tampering | Slower content onboarding (sign + allowlist new sources) |
| 6 | **Multimodal injection → image-borne instruction** (LLM01) | An instruction hidden in an uploaded image's OCR text bypasses the text-only input filter entirely | Multimodal input guardrail: treat vision/OCR-extracted text as untrusted data; scan it for injected instructions and drop instruction-bearing images | Agent-platform / frontend | Heuristic OCR-injection scan — paraphrased or non-textual (steganographic) instructions can evade | A benign image carrying imperative phrasing may be dropped |
| 7 | **System-prompt leakage** (LLM07) | Leaks guardrail logic / secrets that enable better follow-on attacks | Output detector: block answers carrying a system-prompt canary or verbatim span (deliver-side, so indirect requests are caught) | Agent-platform | Canary/verbatim-based — a *paraphrased* disclosure of intent evades it | Rarely may suppress a legit answer that quotes policy verbatim |
| 8 | **Unsafe output handling → phishing/exfil link** (LLM05) | Agent becomes the delivery vehicle for attacker markup (image-beacon exfil, phishing link) | Output sanitiser: strip/neutralise links + media to non-allowlisted domains | Frontend / agent-platform | http(s) allowlist only — scheme-relative, `data:`/`javascript:`, punycode, bare hosts need coverage | Legit external links must be allowlisted explicitly |
| 9 | **Unbounded consumption → tool-budget exhaustion** (LLM10) | Cost/compute exhaustion + degraded availability (no data loss) — a coerced agent burns the whole budget in a loop | Per-request tool-call budget: cap successfully-executed calls per request; block further calls once spent | Agent-platform / SRE | A per-request cap isn't a per-user or global rate limit — many small requests still aggregate cost | A legitimately tool-heavy request may hit the cap |

## Cross-cutting guidance

- **Layer input + output controls on every channel.** No single filter suffices — the
  autonomous-attacker run demonstrates a base64-obfuscated request slipping past the *input*
  filter and being caught only by the *output* detector. Assume each layer is bypassable alone.
- **Treat retrieved content and model output as untrusted at both ends:** data (never
  instructions) on the way in; sanitise on the way out before rendering or chaining into a tool.
- **Make high-risk actions least-privilege, auditable, and reversible:** log every tool call
  with the authorizing session; require confirmation for irreversible/financial actions; prefer
  capability scoping over relying on the model to "decide" correctly.
- **Gate releases on the regression suite.** A model or prompt change that reopens a fixed hole
  should fail CI — this range already wires that in.

## Honest limitations (so the team calibrates trust)

- The pattern-based filters (input injection, output PII / link) are **heuristics** — they raise
  the bar but are bypassable by paraphrase or novel encoding. Use them as one layer, not a
  guarantee; pair with least-privilege tool design and human-in-the-loop for high-risk actions.
- **AIRQ scores are an analyst heuristic for ordering work, not a calibrated risk metric.** Use
  them to prioritize, not to assert residual-risk numbers to a risk committee.

> The scorecard is the *evidence* each control closes its threat; this page is the *prioritized
> action plan* an engineering org would execute first.
