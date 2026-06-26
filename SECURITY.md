# Security policy & scope

FinAgent-RedRange is **defensive security research tooling**. It exists to find and close
weaknesses in AI agents before adversaries do.

## Scope

- The only system this project attacks is the **bundled mock banking agent** in
  `src/finagent_redrange/target/`. All accounts, balances, and policies are synthetic.
- Techniques are limited to publicly documented categories (OWASP LLM Top 10, OWASP Agentic
  Top 10, MITRE ATLAS). The contribution is the harness, the framework mapping, and the
  mitigation-validation loop — not novel offensive capability against live systems.
- Every attack scenario ships with the control that blocks it and a regression test proving
  the block holds. There are no exploits here without a corresponding fix.

## Responsible use

Do not point this harness, or code derived from it, at systems you do not own or are not
explicitly authorised to test. Findings about real systems should follow coordinated
disclosure with the affected vendor.

## Reporting

If you find an issue in this project (e.g. a scenario whose oracle is unsound, or a leak of
non-synthetic data):

- For non-sensitive issues, open a GitHub issue.
- For anything security-sensitive, use **GitHub's private vulnerability reporting** on this
  repository (Security ▸ *Report a vulnerability*) so the report stays private until it's
  resolved, rather than opening a public issue.

Please don't include real personal or account data in reports — this project only ever uses
synthetic data, and reports about it should too.
