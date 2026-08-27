# Getting started

**Who this is for:** you've seen the [tutorial](tutorial.md) (or don't need one) and want the reference details — install, configuration, run outputs, exit codes.

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

## Guided setup (recommended first command)

```bash
security-council setup           # one question, a written config, your next 3 commands
```

The wizard detects your repo (languages, CI system, git), asks what you're
trying to do, and writes a commented `.security-council.yaml` using one of
four **profiles** — the same presets `scan --profile` applies ad hoc:

| Profile | What it sets up | Cost |
|---|---|---|
| `quick` | free deterministic scanners, defaults everywhere | $0 |
| `ci` | same arms + `gate_baseline: new` (only findings new since `baseline set` fail the build) | $0 |
| `deep` | adds the `claude-security`/`codex-security` AI reviewers (budget-capped) + the validation panel | real vendor spend per scan |
| `gov` | `ci` posture; pair with `report <run> --bundle gov` for the compliance paperwork | $0 scan |

Explicit keys in the config always win over the profile; `setup` never
overwrites an existing config unless you pass `--force` (without it, it just
prints the cheat sheet). `--yes` makes it non-interactive for scripts.

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
| `summary.html` | **Open this one.** The same report as a self-contained page: gate banner, what-to-do-next, tiles, degradations, a "Where to look" block linking every file below, then the full summary. No scripts, no external assets; print for a PDF |
| `summary.md` | Human-readable executive summary: gate verdict, at-a-glance counts, **method & model attestation** (which arm, which model, cost), findings register, per-finding detail, and a demoted-not-hidden appendix |
| `merged.sarif` | One SARIF 2.1.0 run of root-cause clusters (validated against the official schema; lossless round-trip via `properties.securityCouncil`) |
| `raw.sarif` | One SARIF run per arm, unmerged |
| `findings.json` | The canonical finding model — system of record for all exports |
| `policy.json` | Per-finding scoring + disposition audit trail (log-odds terms, clamps, guardrails consulted) |
| `manifest.json` | What ran, on what revision, arm status/cost, degradations, baseline delta, exit code |

### Finding your reports

```bash
security-council runs                 # every run, newest first, with exit code and counts
security-council report --open        # render + open the latest run's summary.html
security-council scan . --open        # same, straight after a scan
security-council serve [--bind 0.0.0.0]   # browse every run in a browser; LAN needs a token (docs/serve.md)
cat .security-council/runs/latest/summary.md   # `latest` always points at the newest run
```

`report` with no run directory means the latest one; `--out DIR` on `scan`
puts a run somewhere other than the repo's hidden folder.

Re-render or export any prior run without rescanning:

```bash
security-council report <run_dir> --format md
security-council report <run_dir> --format emass --app-name X --app-version 1.0
security-council report <run_dir> --format gitlab-sast
```

## Change-scoped (diff) scans

For fast PR/CI checks, scan only what changed instead of the whole repo. Diff
scanning uses the vendors' native change-scan workflows, so it needs a
diff-capable agentic arm (`claude-security` or `codex-security`):

```bash
security-council scan . --arms claude-security --diff origin/main          # committed range
security-council scan . --arms codex-security --working-tree --diff HEAD    # uncommitted changes (codex)
```

A diff run is **partial** by design and treated safely as such: it runs only
diff-capable arms (other arms are reported as `diff_skipped`, never run against
the whole tree, so corroboration stays honest), the summary is stamped
`⚠ partial — change-scoped`, and the run **cannot be used to set a baseline**
(a partial scan would wrongly treat unscanned findings as resolved). Pair it
with `--gate-baseline new` so a PR only fails on newly-introduced problems.
Add `--deep` to run the dedicated arms in their deeper (slower, costlier) mode.

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
decisions:
  require_signatures: enforce # enforce | warn | auto | off — docs/signing.md
  signing_key: null           # e.g. ~/.ssh/id_ed25519; --signing-key and
                              # $SECURITY_COUNCIL_SIGNING_KEY override it
reports:
  outdir: .security-council/runs
```

CLI flags (`--fail-on-severity`, `--gate-baseline`, `--min-arms`) override the
file per run.

## Reports: one format or one audience

Every format renders from the same run directory, after the fact:

```bash
security-council report <run_dir> --format md          # readable summary (stdout)
security-council report <run_dir> --format html        # self-contained page; print for PDF
security-council report <run_dir> --format csv         # full triage spreadsheet
security-council report <run_dir> --format cklb        # STIG Viewer 3 checklist (ASD V6R4)
security-council report <run_dir> --format cyclonedx   # CycloneDX 1.6
# also: emass, openvex, oscal-ar, oscal-poam, gitlab-sast, gitlab-codequality
```

When you need a *set* of reports rather than one, bundles write everything an
audience expects into `<run_dir>/exports/` in one command:

```bash
security-council report <run_dir> --bundle triage      # findings.csv + summary.html + summary.md
security-council report <run_dir> --bundle gov \
    --app-name myapp --app-version 1.0                 # openvex + oscal-ar + oscal-poam
                                                       # + checklist.cklb + cyclonedx + emass
```

**SBOM:** `security-council scan . --sbom` runs syft ($0, no network) and
attaches a CycloneDX inventory to the run. When one exists, `--format
cyclonedx` merges the findings into that real inventory; without it you get a
vulnerabilities-only VDR that makes no inventory claim.

Compliance formats withhold suppressed/demoted findings (they live in the
summary's appendix); the triage CSV deliberately includes everything with its
state spelled out. The CKLB is a *partial* checklist — only the SAST-informable
subset of the 286 ASD rules, statuses only ever `open` or `not_reviewed` (an
automated scan can never claim `not_a_finding`).

## Next steps

- Adopting on an existing codebase: [triage.md](triage.md) — set a baseline
  so only *new* findings gate.
- Adding LLM arms and the validator panel: [arms.md](arms.md) +
  [data-boundaries.md](data-boundaries.md).
- Wiring CI: [ci/github.md](ci/github.md), [ci/azure-devops.md](ci/azure-devops.md),
  [ci/gitlab.md](ci/gitlab.md).
