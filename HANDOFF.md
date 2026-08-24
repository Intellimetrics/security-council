# security-council — session handoff

> **Internal engineering status doc** for the maintainer's development
> environment — machine-local paths and vendor cost observations included.
> User documentation lives in [README.md](README.md) and [docs/](docs/).

_Last updated: 2026-08-24. Read this first when resuming; it is the single entry point._

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
python3 -m security_council.cli scan . --arms claude-security --diff origin/main   # change-scoped (M-V1)
python3 -m security_council.cli report <run_dir> --format md      # print summary md (stdout)
python3 -m security_council.cli eval                              # replay eval gate (deterministic, $0)
python3 -m security_council.cli calibrate .corpora/BenchmarkJava  # fit calibration record from a Benchmark scan (R7)
python3 -m pytest tests/ -q        # 360 green + 1 skip (~1.2s); .venv/bin/python runs all 361 incl. MCP handshake
python3 -m security_council.cli report <run_dir> --format emass --app-name X --app-version Y   # eMASS POST body
security-council-mcp                                              # MCP stdio server (pip install .[mcp])
python3 -m security_council.ci.azure_devops <run_dir> [--post-pr-thread] [--dry-run]   # ADO annotations
# ADO pipeline: copy templates/security-council.yml into the repo and extend it
# operator loop: baseline + human decisions (persist under <target>/.security-council/)
python3 -m security_council.cli baseline set --target <path>          # gate_baseline: "new" gates only new findings
python3 -m security_council.cli suppress <finding_id> --operator NAME --justification "..." --target <path>
python3 -m security_council.cli outcome mark <finding_id> --verdict tp|fp --target <path>   # feeds score history
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

51 commits, ~8,600 LOC (package), **320 tests green (+1 skip), ruff clean**. Published: github.com/Intellimetrics/security-council (public). The full v1 Blue pipeline runs end to end:

```
isolate(copy) → parallel arms → normalize → cluster(root-cause) → category-aware coverage
  → decision-store replay (reapply human/auto suppressions; expiry/drift reopen)
  → [optional] cross-vendor validation → score(log-odds p_true, history from outcome marks)
  → disposition policy (G1–G8) → baseline delta (baselineState)
  → merged+raw SARIF + findings.json + summary.md + policy.json + manifest.json → exit code
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
| **Score + disposition policy** | `score.py` (transparent log-odds p_true: prior −1.2, 7 named terms, fail-safe clamps — crypto floor 0.50, deterministic floor 0.60, unreliable cap + human flag; `calibration: prior` until fitted) · `policy.py` (guardrails G1–G8: demote-never-close, double-gated auto-suppress + 5 shadow runs, crypto/critical never suppressed, G2 deterministic refutation needs a fully-verified defender else escalates `needs_human`, root-cause-scoped 90-day suppressions, `assert_invariants` on every mutation) · `policy.json` audit artifact every run | done |
| **Eval gate** | `eval/{metrics,runner}.py` (replay recorded fixtures through the real pipeline; path + exact-CWE-over-family matcher vs `EXPECTED.yaml`; zero-tolerance wrongful-suppression gate, crypto rate reported; panel-verdict fixture exercises demote/suppress branches; adversarial-history + wrong-panel meta-test) · CLI `eval` subcommand · runs inside pytest = the CI gate | done, council-directed (R3) |
| **Decision store + baseline** | `decisions.py` (per-root-cause records, append-only `history[]`, atomic writes; reapply on scan with **G6 expiry→reopen** and **G8 drift→reopen+deactivate**; anti-poisoning: score `history` term fed ONLY by human `outcome mark`; armed-run shadow counter resets on suppression-config change; baseline snapshot + greedy 1:1 root_cause→context_hash→path_cwe_sink delta, SARIF `baselineState`, `policy.gate_baseline: "new"`) · CLI `outcome mark` / `baseline set\|show` / `suppress` (human, I6-attributed, expiring) | done, live-verified |
| **eMASS exporter** | `export/emass.py` (`report --format emass`): CWE-keyed rows, stable `codeCheckName` "CWE-n (family)", numeric-string `cweId` (no prefix), medium→`Moderate`, D7 disposition withholding (suppressed/refuted never exported), noinfo skipped loudly, clear-findings body; contract verified against the official `eMASSRestOpenApi.yaml` + emasser client BEFORE coding (R3), conformance schema vendored in `tests/fixtures/schemas/` | done, live-verified |
| **MCP server** | `mcp_server.py` (`security-council-mcp`, optional `.[mcp]` extra): `sc_scan/doctor/report/last_run/baseline/suppress/outcome_mark/config`; `SECURITY_COUNCIL_MCP_ROOT` scoping (absolute-only, in-root), presence-based nesting guard (`SECURITY_COUNCIL_NESTED` ⇒ `sc_scan` refuses); transport-independent handlers, llm-council `_serve` pattern for the mcp-2.x adapter; `tests/test_mcp_handshake.py` drives the real stdio transport where `.[mcp]` is installed | done, **transport live-handshaken** (mcp 2.0.0) |
| **Azure DevOps CI** | `ci/azure_devops.py` (`##vso[task.logissue]` w/ documented escaping + exit-gate-consistent error/warning split incl. `gate_baseline`, `uploadsummary`, PR thread REST api-version=6.0, active/closed by gate) · `templates/security-council.yml` (capture-exit → stage SARIF → publish **CodeAnalysisLogs** → annotate → re-raise gate) · `scan --gate-baseline` flag | done; not yet run on a real ADO Server (§7.6) |
| **GitLab CI** | `export/gitlab.py` (native SAST report validated against the **official vendored schema 15.2.4** — timezone-less times, ≥1 identifier, CWE ids w/ MITRE urls; + Code Quality report, CodeClimate subset, inline MR annotations on all tiers, fingerprint = derived finding id) · `ci/gitlab.py` (writes both reports, MR note via project access token, shares `split_findings` gate semantics) · `templates/security-council.gitlab-ci.yml` (`artifacts:reports:` sast+codequality) · `report --format gitlab-sast\|gitlab-codequality` | done; not yet run on a real GitLab (§7.6) |
| **GitHub Action** | `action.yml` composite (`uses: Intellimetrics/security-council@main`): install from action_path → scan (captured exit) → native SARIF upload (`codeql-action/upload-sarif@v3`, category security-council, needs `security-events: write`) → step summary → gate re-raise; outputs exit-code/run-dir/sarif-file | done; not yet run in a real workflow (§7.6) |
| **Orchestrator + CLI** | `orchestrator.py`, `cli.py` (`scan`/`doctor`/`report`), `config.py`, `manifest.py` | done |
| **Seed fixture** | `tests/fixtures/seedrepo` (vulns across families + FP decoy + injection payload), `EXPECTED.yaml` | done |
| **Envelope schema** | `security_council/schemas/agent_finding_envelope.v1.json` (portable strict-mode subset) | done |
| **Calibration lane (R7)** | `eval/import_owasp.py` (converter-only importer — BenchmarkJava is GPL-2.0, NEVER vendored; user clones to `.corpora/`, gitignored) · `eval/calibrate.py` (case-level labels via the shared eval matcher; per-family Laplace fit + Wilson + dual ECE; caveats in-record) · `calibration.py` (runtime loader = trust boundary: schema/scope validation, ±2.5 logit clamp, min-n, fail→prior; `auto` enforces scanner version+ruleset pins; Java-language scope gate) · `score.py` fitted_base (replaces PRIOR+W_DETERMINISTIC only; label `fitted` ONLY strict-scope, composed stays `prior`) · CLI `calibrate` · packaged record `data/calibration-owasp-benchmark-java-1.2.json` (crypto .995→clamped, xss .654, injection .549+floored, path_traversal .500+floored; held-out ECE .022/.018) · summary/manifest surfaces, banned-word tests, adversarial-record gate test | done, council-reviewed (R7), live-verified (284 findings fitted under `auto`) |

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
2 usage · 3 degraded/partial (arm failed or `min_arms_ok` not met) · 4 entitlement (undeclared gated tier) · 5 preflight refused (Daybreak Red).

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
- **Project venv at `.venv`** (gitignored; `uv venv .venv && uv pip install -p .venv/bin/python -e ".[mcp,dev]"`): system python3 is PEP-668 externally managed, so the `mcp` SDK (2.0.0) lives only there. The suite runs on both — the MCP handshake test skips wherever `mcp` is absent.
- **OWASP Benchmark checkout at `.corpora/BenchmarkJava`** (gitignored — GPL-2.0, converter-only per R7; shallow clone, sha `0db793a`; `results/`+`scorecard/`+`data/` deleted locally to keep semgrep runs clean/fast). Its local `.security-council.yaml` enables `score.calibration: auto` — the live smoke config for the fitted record. Re-fit after a semgrep version bump: scan the checkout, run `calibrate`, copy the record into `security_council/data/` (the `auto` pin check refuses stale records loudly).

## 7. Known limitations / deferred (honest list)

1. **Validator prompt is SAST-shaped; doesn't fit SCA/dependency findings** → `supply_chain` is skipped from LLM validation (osv is authoritative). A dep-reachability validator is a future lane. (See R2.)
2. **Validator verdict fidelity**: parses an explicit `VERDICT:` line from the transcript (S2 pattern). Works, but a redacted-secret finding validates to `needs_human` (no snippet to cite) — safe but blunt.
3. **codex-security served model is unattestable** — the CLI reports it nowhere (stdout empty, not in stderr or the sealed bundle), so a D8 model pin can only fail open: the arm sets `model_unattested` in coverage and the summary renders "unattested", but a silent substitution by the vendor would be invisible. Revisit if a future CLI version surfaces the model.
4. **Calibration is fitted but deliberately narrow (R7).** Default stays `"prior"`; the opt-in record covers ONLY semgrep deterministic singletons, Java, four families — everything else (panel terms, other languages/arms) is still hand-set. Known honest gaps: fitted p is prevalence-conditional (~50%-real corpus); templated near-twins leak across the train/test split (CIs/ECE flatter); the 0.60 floor censors injection/path_traversal fitted values. The word "calibrated" stays banned everywhere (tested). Next corpora: a negative corpus, a non-Java benchmark, panel-sample fitting for the panel terms.
5. **Reports:** SARIF + JSON + manifest + `summary.md` + **eMASS static-code-scans** + **OpenVEX** + **OSCAL AR/POA&M** (`report --format emass|openvex|oscal-ar|oscal-poam`; all spec-verified, schema-validated in tests). Missing: CKLB (ASD STIG V6R4), SBOM (CycloneDX), CSV, HTML/PDF.
6. **CI surfaces built for all three platforms (ADO / GitHub / GitLab) but none has run on real infrastructure yet**: the ADO template needs an ADO Server instance, the GitHub Action (`action.yml`, `uses: Intellimetrics/security-council@main`) needs a workflow run in a real repo, and the GitLab job template + MR notes need a GitLab project (+ a project access token — `CI_JOB_TOKEN` can't post notes). Local halves are live-verified (annotations, schema-valid reports, REST payloads via fake openers). ~~MCP transport unproven~~ — live-handshaken 2026-08-22 (mcp 2.0.0, protocol 2025-11-25); `tests/test_mcp_handshake.py` keeps it verified wherever `.[mcp]` is installed.
7a. **Fix lane (M-V4a) is offline-built; live vendor patch-generation unproven.** The bwrap
   fence, canary, patch validator, and fail-closed `FenceCertificate` are live-verified here
   (bwrap 0.11.0); but no real vendor fix run has been made through `arms/fix.py` — the vendor
   `$fix-finding`/`suggest-patches` invocation is best-effort and needs spend to verify (degrades
   to `no_patch`). Also verify: whether `codex-security patch` honours the passed `--sandbox` vs
   spawning its own `codex exec`; whether suggest-patches' verifier needs network (→ `tests_ran:
   false`, never open egress). **M-V4b (verify-fix evidence) not built.** The CLI/MCP nesting
   guards are cooperative (the real boundary is the fence's write-denial on the original tree).
7. **No Red-tier / PoC** (deferred by design; needs the authorization block + sandbox). The
   entitlement layer (M-V2) *knows* Daybreak Red and **positively refuses** it (exit 5) for every
   workflow — routing to `gpt-5.6-cyber`/`daybreak-red-latest` stays blocked until that block lands.
   Gated Blue tiers (Mythos, Daybreak Blue) route + probe but are **not provisioned on this
   machine**, so only rung-1 (catalog, zero-network) is live-verified; deep-rung probes are
   injectable and default to "unverifiable" — live-verify with real entitled creds.
8. **The decision store is target-local and unsigned** (`<target>/.security-council/decisions/`). Our own gitignore excludes all of `.security-council/`, so a team that wants shared suppressions/baselines must un-ignore `decisions/` + `baseline/` in *their* repo (run outputs should stay ignored) — a decision-sync/central-store + record-signing lane is future work. (Baseline/delta, the store, and `outcome mark` themselves landed 2026-08-22.)
9. **gitleaks/osv can't path-exclude via CLI** — isolation (scratch copy excluding runtime dirs) is what keeps scans clean; don't remove it.
10. **`coverage.CATEGORY_POLICY` is keyed by arm name** (`POLICY_ALIASES` maps `claude`/`codex` → `house`). A new arm without an entry/alias is `unknown` for every family → never eligible → its findings mislabel as singleton/uncovered. Add a policy row when adding an arm.

## 8. Recommended next steps (in rough priority)

_Ordering council-reviewed 2026-08-22 (R3, `docs/reviews/R3-scope-eval-first.md`): eval gate
before the decision store — never wire the history feedback loop onto an unmeasured scorer._

1. ~~**Eval gate (minimal, replay-based)**~~ — **DONE 2026-08-22** (`security_council/eval/`,
   `tests/test_eval_gate.py`, `security-council eval`): replays `tests/fixtures/raw/` (all arm
   families; new `house-claude.envelope.json` closes the AES-ECB + decoy coverage gap) with
   panel verdicts from `tests/fixtures/eval/panel_verdicts.yaml`; **zero-tolerance gate** on TP
   demotion/suppression (≤5% not resolvable at n=7; keep 5% as the target for a larger corpus).
   Pinned: recall 7/7, decoy demoted-not-hidden even fully-armed past-shadow, adversarial
   history moves nothing, wrong-panel meta-test caught. Calibration fitting stays deferred (§8.5).
2. ~~**`decisions.py` decision store + `outcome mark` + baseline/delta**~~ — **DONE 2026-08-22**
   (`decisions.py`, CLI `outcome mark` / `baseline set|show` / `suppress`; live-verified
   scan → baseline → human suppress → rescan exit 1→0). Original scope, all delivered: persist suppressions/human
   decisions per root cause (append-only `history[]`, atomic writes,
   `.security-council/decisions/by-root-cause/`), feed the score `history` term, make G6
   expiry/reopen and G8 context-drift explicit, store the shadow-run counter (**reset it on
   policy-config change** — a stored counter flips the census's fail-safe direction; and don't
   burn shadow runs on uncalibrated scores). **Baseline/delta folded in** (R3 found it in §7.8
   but missing from this roadmap; it is the CI-template adoption blocker on brownfield repos).
   Re-run the eval gate with adversarial history counts (`W_HISTORY` must not push a decoy past
   `suppress_below`).
3. ~~**eMASS static-code-scans exporter**~~ — **DONE 2026-08-22** (`export/emass.py`,
   `report --format emass`; contract verified against the official spec + emasser client first,
   conformance schema vendored, live-verified on the reference run). Remaining exporter lane:
   OpenVEX, OSCAL AR/POA&M, CKLB — on demand.
4. ~~**`mcp_server.py`** + **Azure DevOps template**~~ — **DONE 2026-08-22** (`mcp_server.py`
   `sc_*` tools root-scoped + nesting-guarded; `ci/azure_devops.py` + `templates/security-council.yml`
   with CodeAnalysisLogs artifact, logissue annotations, PR threads). Remaining to close the lane:
   live-handshake the MCP transport with the real `mcp` SDK, run the template once on a real
   ADO Server, GitHub Action (secondary per D4).
5. **VENDOR-WORKFLOW SURFACE (the current focus)** — expose the vendors' *full* built-in
   security-workflow surface, not just the single `scan`/`scan-codebase` we wrap today. Scope +
   ordering council-reviewed 2026-08-23 (**R5**, `docs/reviews/R5-vendor-workflow-scope.md`;
   claude+antigravity converged). Shape = per-vendor **job-parameterized dedicated arms** (scan
   jobs) + an **artifact runner** (analysis/fix jobs); NOT a generic passthrough, NOT
   MCP-mount-as-primary (both fracture the finding-model trust surface). Three lanes: SCAN→finding
   model, ANALYSIS→attached artifact, FIX→`.patch` never applied. Skip the state-management
   overlaps (vendor triage/validate/track/findings/export — they fork our panel/baseline/decision
   store/exporters). Verified: codex `scan --diff/--head/--working-tree/--mode deep/--model/--effort`
   all exist (diff + deep + tier knob are params on the existing arm); analysis skills
   (threat-model/attack-path/writeup) have no CLI subcommand → session/MCP, artifact lane.
   Sub-milestones:
   - ~~**M-V1 Diff lane**~~ — **DONE 2026-08-23** (`arms/base.py:DiffSpec`, `test_diff_lane.py`,
     `scan --diff/--diff-head/--working-tree/--deep`): codex `--diff`/`--working-tree` + claude
     `scan-changes`; a diff run executes ONLY diff-capable arms (others → informational
     `diff_skipped` degradation) so corroboration stays scope-coherent — this made per-job
     `CATEGORY_POLICY` rows unnecessary; manifest `scan_scope`; `baseline set` refuses partial
     runs; `annotate_baseline(partial=True)` never marks out-of-scope findings absent; summary
     shows a partial banner. 243 tests.
   - ~~**M-V2 `entitlements.py` + tier knob**~~ — **DONE 2026-08-23** (`entitlements.py`,
     `test_entitlements.py`, `scan --tier`, `entitlements` command): KNOWN_TIERS (mythos /
     daybreak-blue / daybreak-red); classify_model (alias, + snapshot only when snapshot is
     itself gated — GA gpt-5.6-sol stays GA); rung-1 catalog probe real (codex cache), rungs 2–4
     injectable/unverifiable-by-default (never reads keys); preflight refuses **Red (exit 5)** and
     **undeclared gated tiers (exit 4)** before any arm runs; provenance stamps
     `entitlement`/`safeguard_posture`, summary flags relaxed-safeguard use; `config.entitlements`.
     Blue scope: Red known so it is positively refused. Live-verified probe on this
     (unprovisioned) machine. **Not live-verifiable against a real gated model here.**
   - ~~**M-V3 Artifact lane**~~ — **DONE 2026-08-23** (`artifacts.py`, `arms/artifact_runner.py`,
     `test_artifacts.py`, `scan --analyze`): Artifact model + manifest `artifacts` index +
     summary appendix; ANALYSIS_JOBS (threat-model, attack-path[dual], hardening, policy,
     writeup[dual]) attach as artifacts, never findings; dual-use → export-excluded, `raw/`-only;
     analysis arms kept out of coverage/gate (failure = informational degradation). Runner drives
     the verified `$skill` Codex trigger — **built offline (fake-proc), live invocation pending
     codex+plugin session spend** (same status the dedicated arms had pre-live).
   - **M-V4 Fix lane (gated)** — council-reviewed twice (R6, both degraded/single-peer, both
     go-with-conditions). **M-V4a DONE 2026-08-23** (`fence.py`, `patches.py`, `arms/fix.py`,
     `tests/test_{fence,patches,fix_lane}.py`, `scan --fix <ids> [--fix-job]`): orchestrator-owned
     **bwrap** kernel fence (ro system, rw only the scratch copy, tmpfs HOME, no net,
     --die-with-parent) with a **deterministic canary certified live here** (bwrap 0.11.0);
     `FenceCertificate` fail-closed (no cert, no run); env allowlist drops CI/cloud tokens;
     git-neutered copy + safe `git diff --no-index` extraction (MV4-10); patch validator refuses
     agent/VCS-meta + symlink/binary, redacts secrets both sides; MCP+CLI nesting guards (MV4-4/12);
     killpg-adjacent via the fence. Fix jobs run serial/post-scan/own-copy, only open non-refuted
     findings, `--inplace` refused. **.patch artifacts are NEVER applied.** **M-V4b DONE 2026-08-23**
     (`arms/verify_fix.py`, `scan --fix ... --verify-fix`, `test_verify_fix.py`): orchestrator
     applies the patch to a fresh copy (never the agent), runs vendor verify-fix READ-ONLY in the
     same fence, verdict bound to patch_sha256+base_commit, recorded as machine evidence
     (kind=vendor_verify_fix, decided_by machine) — L1 `history_counts` ignores it (hardened to
     reject any decided_by=machine even if forged as outcome_mark), L3 never a panel vote / never
     auto-closes (finding stays open; summary renders "requires human review"). Also fixed a real
     bug: `extract_patch` now snapshots content with `.git` stripped so the work copy's git can't
     pollute a patch. **M-V4 (a+b) complete.** Offline/fake-proc; live vendor run needs spend
     (degrades to no_patch/unproven).
   - ~~**M-V5 (optional)**~~ — **DONE 2026-08-23** (`validate/panel.py`, `scan --validate
     --vendor-validate`, `test_vendor_validate.py`): vendor validate/triage join the panel as
     `role=vendor`, `independent=False`, weight 0 — the verdict tally and the ≥2-voice quorum
     exclude them; they're surfaced + summarized in `evidence_check.vendor_advisory`
     (verdicts + disagrees_with_panel) as a human signal, never deciding. `make_vendor_runner`
     shells out to the vendor `validate` skill (offline/injectable). **The vendor-workflow
     surface is COMPLETE: M-V1 diff · M-V2 entitlements · M-V3 artifacts · M-V4 fix+verify ·
     M-V5 voters.**
   Must NOT build: fix application to user code (no `--apply`), PoC generation/execution (Red,
   D5), vendor decision/tracking state or export egress, default-mounted vendor MCP servers.
6. ~~**Calibration fitting**~~ — **DONE 2026-08-24** (R7, `docs/reviews/R7-calibration-corpus.md`;
   council quick-mode quorum met, claude+antigravity converged, codex timeout again).
   OWASP Benchmark importer (converter-only — GPL-2.0, checkout at `.corpora/BenchmarkJava`,
   gitignored) + per-family fit + trust-boundary loader + scoped score integration +
   packaged opt-in record; `security-council calibrate`. Default remains `prior`; §7.4 has
   the honest-scope caveats. **§8 roadmap is now complete.** Remaining project work is in
   §7 (real-infra CI runs, live vendor fix/verify spend runs, decision-store sync/signing,
   CKLB/SBOM/CSV/HTML exporters, further calibration corpora).

(§8.1 live verification of the dedicated arms was completed 2026-08-21 — run `20260821_130516`,
kept under `tests/fixtures/seedrepo/.security-council/runs/` (gitignored) as the live reference.
The recommended deep profile now lives in `README.md`.)

## 9. How to resume (checklist for a new session)

1. Read this file, then skim the plan file §"Decisions locked" and §"Design".
2. `cd /development/projects/active/security-council && python3 -m pytest tests/ -q` (expect 320 green + 1 skipped;
   `.venv/bin/python -m pytest tests/ -q` runs all 244 incl. the live MCP handshake).
3. `git log --oneline` (expect to be at the gov-exporters commit or later; remote `origin` = github.com/Intellimetrics/security-council, push after committing).
4. `python3 -m security_council.cli doctor` to confirm arms.
5. Pick a next step from §8. Keep the working style: build a module + tests, run the suite + ruff, commit with the `Co-Authored-By` trailer, update the memory status line. Use the llm-council `council_run` MCP tool for design/code review at milestones (it found real guardrail bugs twice).

## 10. Working conventions in this project

- stdlib-only runtime (dataclasses + json + hashlib + re); `pyyaml` for config; Python ≥3.11; pytest + ruff.
- Every arm/normalizer output goes through `assert_invariants` at the boundary (fail-closed).
- Live LLM/scanner work costs money — spike read-only first, batch install-consenting steps, cap budgets.
- Commits are milestone-sized, each with tests green + ruff clean. Amend if a lint/pyc slip lands.
