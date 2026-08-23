# security-council

Parallel, multi-agent security scanning for government and commercial codebases.
Runs deterministic scanners and agentic LLM CLIs as independent "arms" against an
isolated copy of a repo, normalizes their output into one finding model, clusters
by root cause, computes category-aware cross-vendor corroboration, optionally
cross-validates each finding with an adversarial LLM panel, and emits spec-valid
SARIF 2.1.0, a markdown executive summary, and a run manifest with CI exit codes.

Status: **v1 (Blue profile) — working end to end**, live-verified 2026-08-21
including both dedicated agentic arms. The agentic arms caught a cross-file
IDOR (CWE-639) that pattern scanners cannot, corroborated across two vendor
families.

## Quickstart

```bash
python3 -m security_council.cli doctor                    # which arms are ready
python3 -m security_council.cli scan <path>               # deterministic arms (free, fast)
python3 -m security_council.cli scan <path> --validate    # + adversarial validator panel
python3 -m security_council.cli report <run_dir> --format md
python3 -m pytest tests/ -q
```

Exit codes: `0` clean · `1` gating finding at/above `fail_on_severity` · `2` usage ·
`3` degraded/partial run.

## Arms

| Arm | Kind | Cost | Notes |
|---|---|---|---|
| `semgrep`, `gitleaks`, `osv-scanner` | scanner | free | via docker or local binary; the default set |
| `claude`, `codex`, `agy` | LLM house-prompt | ~$0.5–3 | our prompt over the vendor CLI |
| `claude-security` | dedicated agentic | ~$7 (effort `low`) | Anthropic claude-security plugin; 3-voter panel + verification stamp ingested |
| `codex-security` | dedicated agentic | ~$5 fuse | OpenAI codex-security CLI; sealed canonical bundle ingested |

Recommended deep profile (`.security-council.yaml` in the scanned repo — costs
real tokens, ≈ $12–15 and ~20 min per run):

```yaml
arms:
  enabled: [semgrep, gitleaks, osv-scanner, claude-security, codex-security]
  options:
    claude-security: {effort: low, max_budget_usd: 10}
    codex-security: {mode: standard, max_cost_usd: 8}
```

Note: `codex-security`'s default `$5` fuse cost-stops its final attack-path phase
even on a small repo (the core scan still seals complete); give it ~$8 headroom
when you want that phase.

## CI integrations

| Platform | How | What you get |
|---|---|---|
| **Azure DevOps Server** | copy `templates/security-council.yml` | CodeAnalysisLogs SARIF artifact (SARIF SAST Scans Tab), `logissue` file/line annotations, build summary, PR comment threads |
| **GitHub** | `uses: Intellimetrics/security-council@main` (`action.yml`; needs `security-events: write`) | code-scanning alerts + PR annotations via native SARIF upload, step summary |
| **GitLab** | `include: templates/security-council.gitlab-ci.yml` | `gl-sast-report.json` (Security Dashboard/MR widget, Ultimate) + `gl-code-quality-report.json` (inline MR diff annotations, **all tiers**), MR summary note |

All three capture the scan exit code, always publish artifacts/reports, and
re-raise the gate last (0 clean · 1 gating finding · 3 degraded). Exports render
from dispositions: suppressed/demoted findings are withheld everywhere.
`--gate-baseline new` + `security-council baseline set` makes brownfield
adoption sane (gate only what's new).

Design: see `security-council-is-to-be-snoopy-prism.md` in the author's plan
store; `HANDOFF.md` is the live status + resume document.

Derived from [llm-council](https://github.com/Intellimetrics/llm-council); the
validator panel is a specialization of llm-council's `consensus` mode.
