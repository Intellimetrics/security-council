# Getting started

## Install

```bash
pip install git+https://github.com/Intellimetrics/security-council   # Python >= 3.11
```

Runtime dependencies are deliberately minimal: the Python package needs only
`pyyaml`. Beyond that:

- **docker** — the deterministic scanner arms run `semgrep/semgrep`,
  `zricethezav/gitleaks`, and `ghcr.io/google/osv-scanner` images when the
  binaries aren't on PATH. Local binaries are used when present.
- **llm-council CLI** (optional) — the `--validate` adversarial panel shells
  out to `llm-council run --json`. Without it, everything except validation
  works.
- **vendor CLIs** (optional) — the LLM arms drive `claude`, `codex`, or `agy`
  and the dedicated `claude-security` / `codex-security` scanners. See
  [arms.md](arms.md) and read [data-boundaries.md](data-boundaries.md) first.
- **`.[mcp]` extra** (optional) — the MCP server ([mcp.md](mcp.md)).

## First scan

```bash
security-council doctor          # every arm, ready or not, with the reason
security-council scan .          # default arms: semgrep, gitleaks, osv-scanner
```

`scan` copies your repo to an isolated scratch workspace (excluding VCS and
runtime dirs), fans the arms out in parallel against the copy, and discards it
afterward — write-happy tools never touch your tree. Use `--inplace` to skip
the copy on huge repos.

**Exit codes** (the CI gate): `0` clean · `1` a finding at/above
`policy.fail_on_severity` is open and unresolved · `2` usage error ·
`3` degraded (an arm failed or `min_arms_ok` unmet). Validated false
positives and suppressed findings do not gate.

## The run directory

Each scan writes `.security-council/runs/<timestamp>/`:

| File | What it is |
|---|---|
| `summary.md` | Human-readable executive summary: gate verdict, at-a-glance counts, **method & model attestation** (which arm, which model, cost), findings register, per-finding detail, and a demoted-not-hidden appendix |
| `merged.sarif` | One SARIF 2.1.0 run of root-cause clusters (validated against the official schema; lossless round-trip via `properties.securityCouncil`) |
| `raw.sarif` | One SARIF run per arm, unmerged |
| `findings.json` | The canonical finding model — system of record for all exports |
| `policy.json` | Per-finding scoring + disposition audit trail (log-odds terms, clamps, guardrails consulted) |
| `manifest.json` | What ran, on what revision, arm status/cost, degradations, baseline delta, exit code |

Re-render or export any prior run without rescanning:

```bash
security-council report <run_dir> --format md
security-council report <run_dir> --format emass --app-name X --app-version 1.0
security-council report <run_dir> --format gitlab-sast
```

## Configuration

`.security-council.yaml` at the repo root (all keys optional; defaults shown):

```yaml
defaults:
  max_concurrency: 4          # parallel arms
  min_distinct_vendors: 2     # clustering corroboration knob
arms:
  enabled: [semgrep, gitleaks, osv-scanner]
  options:                    # per-arm constructor options, e.g.:
    claude-security: {effort: low, max_budget_usd: 10}
    codex-security: {mode: standard, max_cost_usd: 8}
policy:
  fail_on_severity: high      # the gate threshold
  min_arms_ok: 1
  gate_baseline: all          # "new" gates only unbaselined findings
  auto_suppress: false        # see docs/safety-model.md before touching
  accept_suppression_risk: false
  shadow_runs: 5
  suppress_below: 0.10
  suppression_expiry_days: 90
reports:
  outdir: .security-council/runs
```

CLI flags (`--fail-on-severity`, `--gate-baseline`, `--min-arms`) override the
file per run.

## Next steps

- Adopting on an existing codebase: [triage.md](triage.md) — set a baseline
  so only *new* findings gate.
- Adding LLM arms and the validator panel: [arms.md](arms.md) +
  [data-boundaries.md](data-boundaries.md).
- Wiring CI: [ci/github.md](ci/github.md), [ci/azure-devops.md](ci/azure-devops.md),
  [ci/gitlab.md](ci/gitlab.md).
