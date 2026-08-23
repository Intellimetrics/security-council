# security-council

**Parallel multi-agent security scanning with cross-validated findings.**
security-council runs deterministic scanners *and* agentic LLM security
reviewers as independent "arms" against an isolated copy of your repository,
normalizes everything into one finding model, clusters by root cause,
corroborates across vendors, and emits spec-valid SARIF 2.1.0, a markdown
executive summary, and CI exit codes — with a fail-closed disposition policy
designed so that **a true positive is never silently suppressed**.

**The problem it addresses:** every scanner floods you with false positives,
and each one misses what the others catch. Agentic LLM triage can cut the
noise dramatically — but published research also found naive agentic triage
*wrongly suppressed 22% of true vulnerabilities, over 50% for crypto*. This
project is an answer to both halves: multi-vendor corroboration and an
adversarial validator panel to kill false positives, and structural guardrails
(demote-never-close, crypto never auto-suppressed, full attribution on every
decision) so the cure can't become the disease. See
[docs/safety-model.md](docs/safety-model.md).

## Quickstart — $0, no API keys

The default arm set is deterministic and local (docker or local binaries;
nothing leaves your machine except scanner rule/DB downloads):

```bash
pip install git+https://github.com/Intellimetrics/security-council
security-council doctor                 # which arms are ready
security-council scan .                 # semgrep + gitleaks + osv-scanner
security-council report <run_dir> --format md
```

Exit codes: `0` clean · `1` gating finding at/above `fail_on_severity` ·
`2` usage · `3` degraded/partial. Run artifacts land in
`.security-council/runs/<id>/`: `merged.sarif`, `raw.sarif`, `findings.json`,
`summary.md`, `policy.json`, `manifest.json`.
Full tour: [docs/getting-started.md](docs/getting-started.md).

## CI

```yaml
# GitHub Actions
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: Intellimetrics/security-council@v0.1.0
    with: { fail-on-severity: high, gate-baseline: new }
```

| Platform | How | Guide |
|---|---|---|
| GitHub | `action.yml` — native SARIF upload → code-scanning alerts + PR annotations | [docs/ci/github.md](docs/ci/github.md) |
| Azure DevOps Server | `templates/security-council.yml` — CodeAnalysisLogs SARIF artifact, file/line annotations, PR threads | [docs/ci/azure-devops.md](docs/ci/azure-devops.md) |
| GitLab | `templates/security-council.gitlab-ci.yml` — native SAST report (Ultimate) + Code Quality MR annotations (all tiers) | [docs/ci/gitlab.md](docs/ci/gitlab.md) |

All three share the same shape: capture the scan exit code, always publish
reports, re-raise the gate last. Brownfield adoption is one command —
`security-council baseline set` then `--gate-baseline new` gates only *new*
findings. *Status honesty: every CI surface is schema-validated and tested
locally; none has yet run on customer infrastructure — issue reports from real
pipelines are especially welcome.*

## The LLM arms (opt-in, costs money, sends code to vendors)

> **Data boundary:** the agentic arms and the validator panel send source
> code and findings to vendor-hosted LLM APIs (Anthropic, OpenAI, Google —
> whatever your CLIs are configured for). Vendor origin is **not** the same
> as FedRAMP/IL authorization or an enterprise data-handling approval. Do not
> point them at CUI, classified, or otherwise restricted code without your
> own approvals. The deterministic default profile keeps everything local.
> Full details per arm: [docs/data-boundaries.md](docs/data-boundaries.md).

```yaml
# .security-council.yaml — the "deep" profile (~$12–15 and ~20 min on a small repo)
arms:
  enabled: [semgrep, gitleaks, osv-scanner, claude-security, codex-security]
  options:
    claude-security: {effort: low, max_budget_usd: 10}
    codex-security: {mode: standard, max_cost_usd: 8}
```

Why bother: agentic arms find cross-file logic flaws pattern scanners
structurally cannot. On this repo's own 12-file test fixture, both agentic
vendor families independently found the seeded IDOR (CWE-639) that no
deterministic arm reported — corroboration across two vendors, exactly the
signal the scoring model rewards. (Fixture-scale demo, not a benchmark.)
Add `--validate` to cross-examine findings with an adversarial
prosecutor/defender/adjudicator panel across three vendors.
Arm catalog, costs, and prerequisites: [docs/arms.md](docs/arms.md).

## The safety model, briefly

- **Demote, never auto-close.** A panel-refuted finding is demoted out of the
  gate but stays open, visible, and listed in the report appendix.
- **Auto-suppression is off by default** — enabling it takes two explicit
  config flags *and* five shadow-mode runs; crypto and critical findings are
  never auto-suppressed regardless.
- **Every hidden finding carries verifiable attribution** (model id, prompt
  hash, panel hash, expiry) — enforced structurally: a suppressed finding
  without attribution cannot even be constructed.
- **Suppressions expire (90 days) and reopen on code drift.** Human decisions
  are recorded per root cause, never per rule or CWE.
- **A replay-based eval gate runs in CI**: zero tolerance for wrongful
  suppression of ground-truth true positives (currently a 7-case corpus —
  stated honestly; the scoring stays labeled "prior", not calibrated, until
  fitted on a larger corpus).

Details with code pointers: [docs/safety-model.md](docs/safety-model.md) ·
[docs/architecture.md](docs/architecture.md)

## Operating it

Operators triage with an auditable loop —
[docs/triage.md](docs/triage.md):

```bash
security-council baseline set                      # accept the brownfield backlog
security-council suppress <id> --operator you --justification "..."   # expiring, root-cause-scoped
security-council outcome mark <id> --verdict fp    # ground truth; feeds the scoring prior
```

Government/DoD: `report --format emass` renders the eMASS
static-code-scans POST body (CWE-keyed, verified against the official API
spec) — [docs/compliance/emass.md](docs/compliance/emass.md).
An MCP server exposes the whole surface to AI assistants
(`pip install .[mcp]`) — [docs/mcp.md](docs/mcp.md).

## Status & honest limitations

Working v1: 233 tests + a live-verified end-to-end run of all arm families.
Not yet: calibration fitting (scores are labeled `prior`), OpenVEX/OSCAL/CKLB
exporters, real-infrastructure CI runs, decision-store sync/signing. The
`tests/fixtures/seedrepo/` tree is **intentionally vulnerable** with fake
credentials — see [SECURITY.md](SECURITY.md) before pointing tools at it.

Derived from [llm-council](https://github.com/Intellimetrics/llm-council)
(the validator panel is a specialization of its `consensus` mode).
License: source-available, evaluation use permitted — [LICENSE.md](LICENSE.md).
