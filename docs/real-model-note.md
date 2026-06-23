# Real-model evidence & methodology

**What the offline run proves — and what it doesn't.** The default `EchoClient` is a
deterministic *compliant-agent simulator*: it does not reason; it reproduces the failure mode
(naively surfacing retrieved/injected content, complying with an obvious tool directive) so the
guardrails have something concrete to neutralise. The offline pass therefore proves the
**harness and the controls work, deterministically, in CI** — it is a *regression fixture*, not
evidence that a frontier LLM is exploitable. By design its outputs are what the oracles are
tuned to detect, so an honest reviewer should read the offline scorecard as "the control closes
the hole," not "an LLM falls for this."

**To show the attack is real, run the same scenarios against Claude.** The `AnthropicClient`
drives the full agent (a real plan→act→observe tool loop with native `tool_use`/`tool_result`),
so the model genuinely decides whether to follow the injected instruction or call the tool — and
the *same* guardrail must block it with controls on.

## Reproduce (needs `ANTHROPIC_API_KEY`)

```bash
cp .env.example .env          # add ANTHROPIC_API_KEY (optionally ANTHROPIC_MODEL)
python -m finagent_redrange run --model claude --controls both --transcripts
```

This writes `results/scorecard.{md,json,html}` plus `results/transcripts.md` with the full Claude
conversation per scenario. Flagship evidence to capture (controls-off lands → controls-on
blocked): **indirect prompt injection** and **system-prompt leakage** (neither needs the
multi-step tool loop); **excessive agency** additionally exercises the tool loop.

> It's a single, *non-deterministic* run — a frontier model may refuse or vary run-to-run; that
> variance is itself worth discussing. The point is one genuine transcript where the model is
> coerced with controls off and the named control stops it with controls on.

## Captured run

> _Placeholder — run the command above, then paste the controls-off → controls-on excerpt from
> `results/transcripts.md` for `indirect_prompt_injection` and `system_prompt_leakage` here._
>
> ```
> (paste transcript excerpt)
> ```
