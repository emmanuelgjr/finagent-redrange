# Handout artifacts — ready-to-use evidence for Security Engineers & AI Security Architects

FinAgent-RedRange doesn't just prove that controls work — it now *hands over* that proof in the
formats security teams already run. Every artifact below is **generated from a range run's own
`Finding`/`Transcript` objects** (never hand-written), is **offline and deterministic** (EchoClient,
no API key), and ships with a **machine-checked precision gate** in CI.

The design principle: the range is a **self-labeling corpus**. Each of the 8 scenarios produces a
*controls-off* transcript where the attack lands (a labeled positive) and a *controls-on* transcript
where it is blocked (a labeled negative). That paired ground truth is what lets a generated artifact
be *measured*, not merely asserted.

Generate them all:

```bash
python -m finagent_redrange run --handouts     # sigma + sarif + assurance + compliance (needs both passes)
# or individually:
python -m finagent_redrange run --sigma
python -m finagent_redrange run --sarif
python -m finagent_redrange run --assurance
python -m finagent_redrange run --compliance
```

---

## 1. Sigma detection pack — for Security / Detection Engineers

**Output:** `results/sigma/<scenario_id>.yml` (8 rules) + `results/sigma/precision_report.md`.

### What it is
One portable [Sigma](https://sigmahq.io) detection rule per scenario. Each rule's `detection:`
block re-expresses the exact observable the scenario's `oracle()` checks, over an agent-transcript
event stream (each turn is an event: `role`, `content`, `tool_name`, `tool_ok`, `tool_args`). The
rule is rendered from a typed `DetectionSignature` co-located with the oracle in `scenarios/*.py`, so
the shipped detection cannot silently drift from the validated oracle.

### What it provides
- **Security Engineer:** SIEM-agnostic detection content deployable as-is — `pySigma` converts to
  Splunk / Sentinel / Elastic — derived from real attack evidence rather than written from scratch.
- **AI Security Architect:** a "we can detect what we mitigate" coverage view: every validated
  control has a corresponding deployable detection, gated in CI.

### How it validates (precision)
`tests/test_export_sigma.py` runs a **full labeled-replay confusion matrix**: every rule is replayed
against all 16 transcripts (8 controls-off + 8 controls-on). A rule must fire on its own exploited
transcript (TP) and stay silent on its blocked transcript *and every other scenario's* transcripts
(TN). Any cross-fire (FP) or miss (FN) **fails the build**. It also asserts **oracle equivalence** —
`evaluate(signature) == finding.succeeded` on both labels — so the exported rule provably reproduces
the oracle verdict. Current result: **8 TP, 0 FP, 0 FN, 120 TN → precision = recall = 1.00.**

> **Honest scope.** This precision is *oracle/translation fidelity over the range's own labeled
> corpus* — it proves each rule faithfully reproduces its validated oracle and doesn't cross-fire.
> It is **not** a real-world false-positive rate: the corpus contains no benign/normal traffic.
> Tune against production telemetry before deploying.

**Accuracy notes:** Sigma is a community open specification (SigmaHQ), not an OASIS/ISO standard.
There is no standardized Sigma logsource for LLM/agent telemetry, so rules declare a self-described
`product: finagent_redrange, category: llm_agent` (a convention, not a standard). MITRE ATLAS ids use
a custom `atlas.` tag namespace because Sigma reserves `attack.` for MITRE ATT&CK. The
`unbounded_consumption` count rule uses legacy Sigma aggregation (`| count() > 2`), whose pySigma
backend support varies; the in-repo replay harness evaluates it exactly regardless.

---

## 2. Control-effectiveness assurance case — for AI Security Architects / GRC

**Output:** `results/assurance/assurance-case.json` (+ `.dot`) and `results/assurance/evidence/*.txt`.

### What it is
A machine-readable **assurance argument** in the vocabulary of Goal Structuring Notation (GSN
Community Standard v3). A top Goal ("guardrails mitigate the covered OWASP LLM Top 10 risks") is
decomposed by a Strategy into one Goal per control, each supported by **two evidence (Solution)
nodes**: the controls-off exploit (proving the threat is real) and the controls-on block (proving
the control holds). Each Solution is anchored to a real regression-test node id **and** a
deterministic SHA-256 of the exact transcript that evidences it. Honesty caveats ride as explicit
Assumption/Justification nodes.

### What it provides
- **AI Security Architect:** an auditable, standards-shaped conformity argument you can put in front
  of an architecture-review board or auditor — every safety claim clicks through to a specific
  reproducible test and transcript, instead of hand-written narrative.
- **Security Engineer:** a regression tripwire — a claim is only "supported" while its controls-on
  test is green, so the case degrades honestly the instant a control regresses.

### How it validates (precision)
`tests/test_export_assurance.py` enforces:
- **Zero orphan claims / zero orphan evidence** — every Solution resolves to a real regression node
  id + a 64-char hash, and every regression node id is cited (a bijection). This operationalizes the
  project invariant *"no exploit without its fix"* as a machine-checkable property.
- **Well-formedness** — exactly one root Goal, every link resolves, the graph is acyclic, no
  undischarged Goal.
- **Reproducibility** — re-running the range reproduces byte-identical transcript hashes (the
  EchoClient is deterministic); each evidence file on disk hashes to exactly the value in the case.
- **Evidence binding (greenness)** — the verdicts the case asserts are recomputed and confirmed
  (exploit lands off, control holds on), so anchoring is non-tautological.

**Accuracy notes:** there is no canonical GSN JSON interchange (OMG SACM is the metamodel), so this
is a defined-in-repo JSON serialization, labeled as such. It deliberately argues only over the
range's own evidence and verified framework tags — it does **not** bind to an ISO/IEC 42001 or EU AI
Act control catalog, avoiding interpretive regulatory-mapping risk.

---

## 3. SARIF 2.1.0 findings export — devsecops interoperability (both personas)

**Output:** `results/findings.sarif`.

### What it is
A single SARIF 2.1.0 (OASIS) run: the 8 scenarios as `rules[]`, each exploited finding as a
`result`, and the full OWASP/ATLAS/NIST crosswalk emitted once as `run.taxonomies[]` so every
framework code is a dereferenceable taxon.

### What it provides
AI red-team results drop straight into GitHub Code Scanning, Azure DevOps, and DefectDojo with zero
glue, alongside normal code findings.

### How it validates (precision)
`tests/test_export_sarif.py` enforces: **structural validity** (required SARIF fields, output is
deterministic — no timestamps/GUIDs); **serialization fidelity** (exactly the exploited findings
become active results, zero of the blocked ones); and **taxonomy referential integrity** — every
`result.taxa` pointer resolves into a declared taxonomy, and every framework id used by a finding
exists in `frameworks.REFERENCE`. That last check doubles as a **crosswalk-completeness CI gate**.

**Accuracy notes:** SARIF has no native "AI/agent finding" concept, so results map to transcript
evidence artifacts (not scanned source) — a documented adaptation importers accept. The referential-
integrity gate validates internal consistency/completeness, not accuracy against the external
standard. `security-severity` is derived from the AIRQ heuristic, clamped to SARIF's required
0.0–10.0 range and tagged as an illustrative, uncalibrated score — never a measured residual risk.

---

## 4. Regulatory control crosswalk — for AI Security Architects / GRC (financial services)

**Output:** `results/compliance/crosswalk.json` (+ `crosswalk.md`).

### What it is
A control-mapping table that takes each validated control and maps it onto the frameworks a
European FS risk/compliance function is asked about: **NIST AI RMF 1.0** and the **NIST AI 600-1
Generative AI Profile**, **ISO/IEC 42001:2023** (Annex A control themes), and the **EU AI Act**
(article references). It complements the assurance case — that argues effectiveness over the range's
evidence; this maps the evidence onto the regulations a board or auditor cites.

### What it provides
A ready starting point for the "which regulations does each control touch?" question, generated from
the range's own scenarios rather than assembled by hand — so it stays in sync as scenarios change.

### How it validates (precision)
Because a regulatory mapping is interpretive, the gate is honest about what it can prove
(`tests/test_export_compliance.py`): **completeness** (no scenario is left unmapped) and
**provenance labeling** — only the NIST AI RMF subcategories carried on the (verified) scenario
crosswalk are marked `basis: declared`; every ISO 42001 / EU AI Act / GenAI-Profile row is marked
`basis: interpretive`, and the test fails if any self-authored row is passed off as authoritative.
It also asserts the artifact carries its disclaimer and the correct EU AI Act timeline.

> **Not legal advice, not a conformity assessment.** ISO 42001 / EU AI Act / GenAI-Profile rows are
> self-authored, category-level suggestions (never reproducing copyrighted standard text). The EU AI
> Act timeline is carried in the artifact: GPAI provider obligations have applied **since 2 Aug
> 2025**; enforcement/penalties and most high-risk obligations apply **from 2 Aug 2026**. Verify
> against the current published standard text before use.

---

## Where this fits

These exporters live in `src/finagent_redrange/exports/` and consume `list[Finding]` exactly like
the scorecard renderer — no coupling to `target/` or `attacker/`. They are opt-in (the scorecard
still writes on every run). All output lands in `results/` and is regenerated on each run.
