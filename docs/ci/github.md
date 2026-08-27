# GitHub Actions

**Who this is for:** anyone wiring security-council into GitHub Actions. **You'll need:** repo admin (for the workflow + permissions), nothing else — the runner images have python and docker.

```yaml
name: security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write        # required for SARIF upload
jobs:
  scan:
    runs-on: ubuntu-latest      # python3 + docker are preinstalled
    steps:
      - uses: actions/checkout@v4
      - uses: Intellimetrics/security-council@v0.2.0
        with:
          path: '.'
          arms: 'semgrep,gitleaks,osv-scanner'
          fail-on-severity: 'high'
          gate-baseline: 'new'          # brownfield: see docs/triage.md
          upload-sarif: 'true'
```

Pin a released tag (as above) rather than `@main`.

## What you get

- **Code-scanning alerts and PR annotations** via GitHub's native SARIF
  pipeline (`github/codeql-action/upload-sarif@v3`, category
  `security-council`) — no bespoke comment bot, and alerts auto-resolve when
  findings disappear from later uploads.
- The run's `summary.md` in the **job step summary**.
- Action outputs `exit-code`, `run-dir`, `sarif-file` for downstream steps.

## How the gate behaves

The action captures the scan's exit code, always uploads the SARIF and the
summary, and re-raises the exit code in its final step — so a failing gate
never robs you of the report. `0` clean · `1` gating finding · `3` degraded
(an arm failed).

Suppressed and demoted findings are withheld from the SARIF results per the
disposition rules ([../triage.md](../triage.md)); demoted findings appear as
`suppressions[underReview]` so code scanning shows them as such rather than
as open alerts.

## LLM arms in CI

Possible but deliberate: the vendor CLIs need credentials in the runner and
**source code will be sent to vendor APIs from CI**
([../data-boundaries.md](../data-boundaries.md)) — plus token spend per run.
Most teams run deterministic arms on every PR and the deep profile on a
schedule.

## Signed decisions

A team that commits `.security-council/decisions/` and `baseline/` so the
gate honours its suppressions should also commit `store.json` and
`allowed_signers`, and put all four paths behind CODEOWNERS + required
review. The action passes `--require-signatures enforce` (input
`require-signatures`): a suppression or baseline whose `ssh-keygen`
signature does not verify is not applied, and the finding gates. `security-council decisions verify` in a PR check makes
a bad record fail early. Setup and what it does (and does not) buy:
[../signing.md](../signing.md).

*Status: the action is schema-validated and tested locally; it has not yet
run in a real customer workflow — early issue reports welcome.*
