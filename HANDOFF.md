# security-council — session handoff

_Last updated: 2026-08-21. Read this first when resuming; it is the single entry point._

## 0. TL;DR

`security-council` is a working v1 (Blue-profile) multi-agent security scanner. It runs
deterministic scanners **and** agentic LLM CLIs in parallel against an isolated copy of a repo,
normalizes their disparate output into one finding model, clusters by root cause, computes
category-aware cross-vendor corroboration, optionally cross-validates each finding with an
adversarial LLM panel, and emits spec-valid SARIF + a **markdown executive summary** + a run manifest with CI exit codes.

**It runs today.** From the repo root:

```bash
python3 -m security_council.cli doctor
python3 -m security_council.cli scan tests/fixtures/seedrepo --arms claude,semgrep,gitleaks,osv-scanner
python3 -m security_council.cli scan tests/fixtures/seedrepo --validate --validate-max 2
python3 -m security_council.cli report <run_dir> --format md      # print summary md (stdout)
python3 -m pytest tests/ -q        # 141 tests, ~0.8s
```

Proven live twice: the claude house arm found the cross-file **IDOR (CWE-639)** that deterministic
scanners cannot, corroborated by semgrep on injection/secrets — and on 2026-08-21 the **dedicated
arms run** (`claude-security,codex-security,semgrep`, run `20260821_130516`) had all three arms ok,
the IDOR corroborated by **both agentic vendor families**, secret snippet redacted, 3/3 panel stamps
surfaced, and correct gate FAIL/exit 1. Cost: $7.05 (claude-security, effort low, 7.3 min) +
~$5.43 (codex-security, cost-stopped at the $5 fuse, 18 min).

## 1. Where everything lives

| Thing | Path |
|---|---|
| Code + tests | `/development/projects/active/security-council` (git, branch `main`) |
| **Full research + design plan** | `/home/clindell/.claude/plans/security-council-is-to-be-snoopy-prism.md` (R1–R4 research, 3 design agents, locked decisions) |
| M0 spike results | `docs/spikes/M0-results.md` |
| Council reviews | `docs/reviews/R1-model-and-envelope.md`, `docs/reviews/R2-validator.md` |
| Auto-memory (loads each session) | `/home/clindell/.claude/projects/-development-projects-active-security-council/memory/` (`security-council-project.md` is the live status) |
| llm-council (the validator backend; user's own project) | `/development/projects/active/llm-council` (installed v0.22.0; MCP wired into this repo) |

The plan file is the authority on the *why*; this doc is the authority on *current state + how to resume*.

## 2. What it is (one paragraph)

Derived from the user's own `llm-council`, but narrower and purpose-built for security/vulnerability
scanning for **government + commercial + DoD** users. Value proposition: individual scanners produce
many false positives and each misses what others catch; running several arms (deterministic + agentic,
across vendors) and **cross-validating** every finding removes FPs while catching logic bugs (IDOR,
authz) that pattern scanners can't. Output is a standards-based, actionable report set.

## 3. Status — what is DONE (all committed, tested)

14 commits, ~3,600 LOC (package), **141 tests green, ruff clean**. The full v1 Blue pipeline runs end to end:

```
isolate(copy) → parallel arms → normalize → cluster(root-cause) → category-aware coverage
  → [optional] cross-vendor validation → merged+raw SARIF + findings.json + summary.md + manifest.json → exit code
```

| Layer | Module(s) | State |
|---|---|---|
| **Finding model + guardrails** | `model.py` (I1–I12 invariants), `jsonio.py` | done, council-reviewed (R1) |
| **Fingerprints + clustering** | `fingerprint.py` (line-drift-stable), `cluster.py` (union-find, 4 tiers) | done |
| **Normalization** | `normalize/{paths,snippets,cwe,cwe_table,severity,base,coverage}.py`, `normalize/sources/{sarif_generic,agent_envelope}.py`, `normalize/registry.py` | done |
| **SARIF export** | `export/sarif.py` (merged+raw, lossless round-trip, validated vs official 2.1.0 schema) | done |
| **Markdown exec summary** | `export/markdown.py` (`summary.md`: gate, at-a-glance, method & model attestation incl. D8 substitution, register, details, demoted-not-hidden appendix; one hardened escaping boundary for all LLM/repo-derived text) | done |
| **Scanner arms** | `arms/scanner.py` (semgrep/gitleaks/osv via docker or local), `proc.py` | done |
| **LLM-CLI arms** | `arms/llm_cli.py` (claude/codex/agy house-prompt), `arms/registry.py` | done |
| **Dedicated agentic arms** | `arms/claude_security.py` (Anthropic claude-security plugin, headless gate-collapse prompt, budget fuse, ingests its SARIF+panel+verification stamp) · `arms/codex_security.py` (OpenAI codex-security CLI, private 0700 output dir, ingests the sealed canonical bundle, cost from stderr progress lines) · adapters `normalize/sources/{claude_security,codex_security}.py` · fixtures `tests/fixtures/raw/{claude-security,codex-security}/` (validation shape matches live producer 0.1.22) | **done — live-verified 2026-08-21** |
| **Isolation** | `workspace.py` (scratch copy; arms/validator write there, discarded) | done |
| **Validator panel** | `validate/{council_client,prompts,panel}.py` (via `llm-council run --json`) | done, council-reviewed (R2) |
| **Orchestrator + CLI** | `orchestrator.py`, `cli.py` (`scan`/`doctor`/`report`), `config.py`, `manifest.py` | done |
| **Seed fixture** | `tests/fixtures/seedrepo` (vulns across families + FP decoy + injection payload), `EXPECTED.yaml` | done |
| **Envelope schema** | `security_council/schemas/agent_finding_envelope.v1.json` (portable strict-mode subset) | done |

### The finding model is the trust surface
`model.py` enforces I1–I12 in `assert_invariants`, called at every ingress/egress boundary. The
safety guarantees are **structural, not conventions**: a suppressed finding that isn't fully
attributed (model id + prompt hash + panel hash + decision_ref + expiry) cannot be constructed (I6);
crypto can never be auto-suppressed, even via a secondary CWE (I7 + crypto-sticky I4); the id is
derived from fingerprints and verifiable (I9). Don't weaken these without re-reading R1.

## 4. Locked decisions (do not re-litigate — see plan §"Decisions locked")

- **D1** New repo + new MCP; **depend on llm-council, don't fork.**
- **D2** Validator transport = `llm-council run --json` **subprocess**, never `import llm_council`. Vendor-copy small files if needed (not yet done — we shell out instead).
- **D4** CLI core + MCP wrapper; **Azure DevOps Server** is the first-class CI target (GHAzDO is Server-unavailable → `CodeAnalysisLogs` build artifact + PR-thread REST). GitHub Action secondary.
- **D5** Blue first; Red (daybreak-red / sandboxed PoC) gated behind a validated `authorization` block, last.
- **D7** `findings.jsonl` is the system of record; SARIF/VEX/OSCAL/eMASS are exports from one `render_decision`. Fingerprints never contain raw line numbers. **Auto-demote, never auto-close.**
- **D8** **Fail loudly on model substitution** (claude silently reroutes cyber-flagged Fable 5 → Opus 4.8; hard-refuses in `-p`). The LLM arm reads claude's served model from `modelUsage` keys and fails the arm on mismatch.

## 5. How to run / test / demo

```bash
cd /development/projects/active/security-council
python3 -m pytest tests/ -q                              # all unit/integration tests (no network)
ruff check security_council/ tests/                       # lint

python3 -m security_council.cli doctor                    # which arms are available
python3 -m security_council.cli scan <path> [--arms a,b] [--validate] [--fail-on-severity high]
python3 -m security_council.cli scan <path> --inplace     # skip the isolated copy (faster on huge repos)
python3 -m security_council.cli report <run_dir>          # summarize a prior run (json)
python3 -m security_council.cli report <run_dir> --format md [--detail-limit N]   # print summary md to stdout
```

Arms: scanners `semgrep`, `gitleaks`, `osv-scanner` (docker or local binary); LLM house-prompt `claude`, `codex`, `agy`; dedicated agentic scanners `claude-security`, `codex-security`.
Per-arm options come from `.security-council.yaml` → `arms.options.<name>` (constructor kwargs), e.g.
`arms: {options: {claude-security: {effort: low, max_budget_usd: 10, model: claude-fable-5}, codex-security: {mode: standard, max_cost_usd: 5}}}`.
Default arms if `--arms` omitted: `semgrep,gitleaks,osv-scanner` (see `config.py:DEFAULT_CONFIG`).

**Exit codes:** 0 clean · 1 gating finding at/above `fail_on_severity` (excludes validated FPs) ·
2 usage · 3 degraded/partial (arm failed or `min_arms_ok` not met).

Run outputs land in `<target>/.security-council/runs/<id>/` (or `--out DIR`): `merged.sarif`,
`raw.sarif`, `findings.json`, `manifest.json`, `raw/<arm>/…`. All `.security-council/` and `.spikes/`
paths are gitignored. `summary.md` is the human-readable report (also regenerable from `findings.json`+`manifest.json`).

## 6. Environment specifics / gotchas (READ before running live)

- **Scanners run via docker** (none installed on PATH); `docker` 29.1.3 present. semgrep/osv need network (rules/DB); gitleaks runs `--network=none`.
- **`~/.codex` was chmod'd to `700`** (was 775) because `@openai/codex-security` requires it. Harmless; revert with `chmod 775 ~/.codex` if desired.
- **LLM arms cost real tokens/time.** claude arm ≈ 2–3 min. `codex-security` (not yet an arm) is heavy (~$4 / >7 min per M0). Native CLI council peers are ~$0 but ~1–2 min each.
- **Gated models:** Mythos (`claude-mythos-5`) = Fable 5 with safeguards lifted, invite-only. Daybreak Blue = gated alias over GA `gpt-5.6-sol`; Red = distinct `gpt-5.6-cyber`. **Not provisioned on this machine** (checked). Design supports declaring entitlements per (CLI, tier, model) but routing to them is unbuilt.
- **`~/.codex/config.toml` model is `gpt-5.6-sol`** with reasoning `ultra`; the codex arm passes `--ignore-user-config` to shed the operator's memories/skills (without it, codex hangs trying to patch `~/.codex/memories`).
- **claude-security arm** (`arms/claude_security.py`): runs `claude -p "/claude-security scan-codebase --effort E …"` with the plugin's documented gate-collapse (job + shape + effort + the sentence *"I understand it may take a while and use a significant number of tokens"*), `--max-budget-usd` fuse (default 10), `--dangerously-skip-permissions --no-session-persistence --strict-mcp-config`. Needs the plugin installed (`claude plugin install claude-security@claude-plugins-official`, v0.10.1 here) and the **Workflow tool** in the session. It writes `CLAUDE-SECURITY-<ts>/` into the scanned dir → the arm moves it to `raw/claude-security/`. A run that exhausts the budget before `render_report.py` runs leaves **no report** → arm fails loudly (raw unverified findings salvaged). The scratch copy has no `.git`, so the plugin stamps `UNVERSIONED`; our manifest carries git provenance from the original. **Live 2026-08-21:** $7.05 / 7.3 min at effort `low` on the 12-file fixture (above the M0 $3–5 estimate); served model `claude-fable-5` correctly picked from `modelUsage` even with opus subagent entries present; 5 findings, all panel-confirmed 3/3.
- **codex-security arm** (`arms/codex_security.py`): resolves the CLI as env `SECURITY_COUNCIL_CODEX_SECURITY_CMD` > `codex-security` on PATH > the **npx cache** (`~/.npm/_npx/*/node_modules/@openai/codex-security/bin/codex-security.mjs` via `node`, v0.1.16 cached here) — it never auto-installs. Output dir must be outside the worktree, 0700, with trusted ancestors → the arm scans into `mkdtemp` and copies the sealed bundle to `raw/codex-security/`. `--max-cost` fuse (default 5 USD). Needs `~/.codex` at 700 (done). Exit 2 = incomplete coverage *or* runtime error → success is decided by the sealed `scan-manifest.json`. **Live 2026-08-21:** stdout is **empty** — progress + cost go to stderr (`--format json` shapes the bundle only), so cost is parsed from stderr lines and full stderr is kept as `raw/codex-security/stderr.log`; the served model is reported **nowhere** → `model_unattested` in coverage (a D8 pin can't be positively attested); 18 min on the 12-file fixture, cost-stopped at $5.43 est. during the post-seal "analyzing attack paths" phase while the core bundle still sealed `completed`+`complete` (surfaced as `cost_stopped`) — give it `max_cost_usd: 8` to keep that phase; sealed producer stamps `codex-security-plugin` **0.1.22** (≠ CLI 0.1.16), which is what lands in `tool_version` provenance.
- **Trivy is banned as a default** (supply-chain compromised Mar 2026, GHSA-69fq-xp46-6x23). Use cdxgen/syft/grype for future SBOM/SCA.

## 7. Known limitations / deferred (honest list)

1. **Validator prompt is SAST-shaped; doesn't fit SCA/dependency findings** → `supply_chain` is skipped from LLM validation (osv is authoritative). A dep-reachability validator is a future lane. (See R2.)
2. **Validator verdict fidelity**: parses an explicit `VERDICT:` line from the transcript (S2 pattern). Works, but a redacted-secret finding validates to `needs_human` (no snippet to cite) — safe but blunt.
3. **codex-security served model is unattestable** — the CLI reports it nowhere (stdout empty, not in stderr or the sealed bundle), so a D8 model pin can only fail open: the arm sets `model_unattested` in coverage and the summary renders "unattested", but a silent substitution by the vendor would be invisible. Revisit if a future CLI version surfaces the model.
4. **No `score.py`/`policy.py`** → v1 sets `disposition.state` but **never auto-suppresses** (lifecycle stays `open`; refuted findings render as SARIF `suppressions[underReview]`). The calibrated confidence function, shadow mode, decision store, and OpenVEX suppression are deferred — safe, because nothing is hidden yet.
5. **Reports:** SARIF + JSON + manifest + `summary.md`. Missing: OpenVEX, OSCAL AR/POA&M, **eMASS static-code-scans** (DoD, CWE-keyed — high value/low effort), CKLB (ASD STIG V6R4), SBOM, CSV, HTML/PDF.
6. **No MCP server yet** (`mcp_server.py`), no Azure DevOps template (`ci/azure_devops.py`), no GitHub Action.
7. **No Red-tier / PoC** (deferred by design; needs the authorization block + sandbox).
8. **Baseline/delta, decision store, `outcome mark` feedback loop** not built.
9. **gitleaks/osv can't path-exclude via CLI** — isolation (scratch copy excluding runtime dirs) is what keeps scans clean; don't remove it.
10. **`coverage.CATEGORY_POLICY` is keyed by arm name** (`POLICY_ALIASES` maps `claude`/`codex` → `house`). A new arm without an entry/alias is `unknown` for every family → never eligible → its findings mislabel as singleton/uncovered. Add a policy row when adding an arm.

## 8. Recommended next steps (in rough priority)

1. **`score.py` + `policy.py` + decision store + shadow mode** — the calibrated confidence + suppression machinery (the `true_positive_suppression_rate` CI gate, crypto carve-out already structural in the model).
2. **Gov/DoD exporters** — eMASS static-code-scans first (CWE-keyed, no STIG mapping), then OpenVEX, OSCAL, CKLB.
3. **`mcp_server.py`** (copy llm-council's `_serve` pattern, root env `SECURITY_COUNCIL_MCP_ROOT`) + **Azure DevOps template**.
4. **Eval harness** (`eval/metrics.py` + seeded corpus): restore llm-council's deleted `eval/metrics.py` (`git -C ../llm-council show ce8acd1^:llm_council/eval/metrics.py`); wire `true_positive_suppression_rate ≤ 5%` / crypto `0%` as CI gates.

(§8.1 live verification of the dedicated arms was completed 2026-08-21 — run `20260821_130516`,
kept under `tests/fixtures/seedrepo/.security-council/runs/` (gitignored) as the live reference.
The recommended deep profile now lives in `README.md`.)

## 9. How to resume (checklist for a new session)

1. Read this file, then skim the plan file §"Decisions locked" and §"Design".
2. `cd /development/projects/active/security-council && python3 -m pytest tests/ -q` (expect 141 green).
3. `git log --oneline` (expect to be at `f134516` live-verified dedicated arms or later).
4. `python3 -m security_council.cli doctor` to confirm arms.
5. Pick a next step from §8. Keep the working style: build a module + tests, run the suite + ruff, commit with the `Co-Authored-By` trailer, update the memory status line. Use the llm-council `council_run` MCP tool for design/code review at milestones (it found real guardrail bugs twice).

## 10. Working conventions in this project

- stdlib-only runtime (dataclasses + json + hashlib + re); `pyyaml` for config; Python ≥3.11; pytest + ruff.
- Every arm/normalizer output goes through `assert_invariants` at the boundary (fail-closed).
- Live LLM/scanner work costs money — spike read-only first, batch install-consenting steps, cap budgets.
- Commits are milestone-sized, each with tests green + ruff clean. Amend if a lint/pyc slip lands.
