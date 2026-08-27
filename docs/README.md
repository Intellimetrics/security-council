# Documentation

**New here? Start with the [tutorial](tutorial.md)** — 15 hands-on minutes
on a safe practice repo, no cost, no accounts.

## Find your path

**"I want to try it"**
[tutorial.md](tutorial.md) → [getting-started.md](getting-started.md) →
[faq.md](faq.md)

**"I don't know what these words mean"**
[concepts.md](concepts.md) — every term (arm, cluster, SARIF, disposition,
baseline…) in plain language.

**"I want it in my CI pipeline"**
[ci/github.md](ci/github.md) · [ci/azure-devops.md](ci/azure-devops.md) ·
[ci/gitlab.md](ci/gitlab.md) — then [triage.md](triage.md) for making an
existing repo's backlog manageable (`baseline set`).

**"I run this day to day"** (triage, suppressions, ground truth)
[triage.md](triage.md) → [signing.md](signing.md) to sign those decisions
with your SSH key so CI can verify who made them →
[verify-fix.md](verify-fix.md) to check a patch against the scanners before
you open the pull request →
[serve.md](serve.md) to browse and share the reports in a browser

**"I want the AI reviewers"**
[arms.md](arms.md) for setup and costs — but read
[data-boundaries.md](data-boundaries.md) first: those arms send source code
to AI vendors.

**"I work in government / a regulated environment"**
[data-boundaries.md](data-boundaries.md) →
[compliance/emass.md](compliance/emass.md) →
[safety-model.md](safety-model.md)

**"Prove to me the automation is safe"** (auditors, security engineers)
[safety-model.md](safety-model.md) → [architecture.md](architecture.md) →
the council design reviews under [reviews/](reviews/)

**"I want my AI assistant to drive it"**
[mcp.md](mcp.md)

## Page list

| Page | One line |
|---|---|
| [tutorial.md](tutorial.md) | Hands-on first scan → report → triage, with real output |
| [concepts.md](concepts.md) | Glossary in plain language |
| [faq.md](faq.md) | Cost, privacy, "why did my build fail?", and more |
| [getting-started.md](getting-started.md) | Install, config file reference, run-folder contents, exit codes |
| [arms.md](arms.md) | Every scanner/AI arm: cost, prerequisites, options, attestation |
| [data-boundaries.md](data-boundaries.md) | Exactly what leaves your machine, per arm |
| [triage.md](triage.md) | Baselines, suppressions, outcome marks, shadow mode, team sharing |
| [signing.md](signing.md) | Sign decisions with your SSH key; what `enforce`/`warn` do; what signing does and does not buy |
| [serve.md](serve.md) | `security-council serve`: browse and download reports (loopback by default; LAN with a token) |
| [verify-fix.md](verify-fix.md) | `--verify-patch`: apply your patch to a scratch copy, re-run the scanners, get fixed / not fixed / unproven as evidence |
| [ci/](ci/) | GitHub · Azure DevOps Server · GitLab guides |
| [compliance/emass.md](compliance/emass.md) | DoD eMASS static-code-scans export |
| [safety-model.md](safety-model.md) | Invariants, guardrails, scoring — with code pointers |
| [architecture.md](architecture.md) | Pipeline, finding model, fingerprints, repo map |
| [mcp.md](mcp.md) | The MCP server for AI assistants |
| [reviews/](reviews/) | Council design-review records (R1–R4) |
