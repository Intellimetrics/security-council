# security-council — session handoff

> **Internal engineering status doc** for the maintainer's development
> environment — machine-local paths and vendor cost observations included.
> User documentation lives in [README.md](README.md) and [docs/](docs/).

_Last updated: 2026-09-02 (**0.4.0 RELEASED** — tag v0.4.0 at 5cd4728, live-verify 33518718528 green; see §7.10b. R19 roadmap Phases 1 + B0/B1/B2 + A2–A5 shipped. **Phase C2/ADO Server live-verified 2026-09-02** on a real ADO Server 2022 — 5/5 claims, closing the D4 first-class target; one `ci/azure_devops.py` URL-encoding defect found live and fixed on main, §7 item 6). Read this first when resuming; it is the single entry point._

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
python3 -m security_council.cli runs; report --open              # list runs / open the latest summary.html (2026-08-27)
python3 -m security_council.cli serve [--bind 0.0.0.0 --token auto]   # read-only viewer; LAN needs a token (2026-08-27)
python3 -m security_council.cli report <run_dir> --format md      # print summary md (stdout)
python3 -m security_council.cli eval                              # replay eval gate (deterministic, $0)
python3 -m security_council.cli calibrate .corpora/BenchmarkJava  # fit calibration record from a Benchmark scan (R7)
python3 -m security_council.cli setup [--profile quick|ci|deep|gov] [--yes]   # guided front door (R8)
python3 -m security_council.cli report <run_dir> --format html|csv|cklb|cyclonedx   # R8 formats
python3 -m security_council.cli report <run_dir> --bundle triage|gov|all [--app-name X --app-version Y]
python3 -m pytest tests/ -q        # 623 green + 1 skip (~12s); .venv/bin/python runs all incl. MCP handshake
python3 -m security_council.cli report <run_dir> --format emass --app-name X --app-version Y   # eMASS POST body
security-council-mcp                                              # MCP stdio server (pip install .[mcp])
python3 -m security_council.ci.azure_devops <run_dir> [--post-pr-thread] [--dry-run]   # ADO annotations
# ADO pipeline: copy templates/security-council.yml into the repo and extend it
# operator loop: baseline + human decisions (persist under <target>/.security-council/)
python3 -m security_council.cli baseline set --target <path>          # gate_baseline: "new" gates only new findings
python3 -m security_council.cli suppress <finding_id> --operator NAME --justification "..." --target <path>
python3 -m security_council.cli outcome mark <finding_id> --verdict tp|fp --target <path>   # feeds score history
# signing lane (R9, built 2026-08-26): store identity + SSH-key roster; --signing-key on the three writes
python3 -m security_council.cli decisions init --operator you@x; decisions trust --principal you@x --key ~/.ssh/id_ed25519.pub
python3 -m security_council.cli decisions verify [--json] [--policy enforce]   # exit 1 if any decision would be refused
# deterministic verify-fix (R11 Q4, built 2026-08-26): your patch vs the scanners, $0, evidence only
python3 -m security_council.cli scan <path> --arms semgrep --verify-patch fix.patch --for <finding_id>
```

Proven live twice: the claude house arm found the cross-file **IDOR (CWE-639)** that deterministic
scanners cannot, corroborated by semgrep on injection/secrets — and on 2026-08-21 the **dedicated
arms run** (`claude-security,codex-security,semgrep`, run `20260821_130516`) had all three arms ok,
the IDOR corroborated by **both agentic vendor families**, secret snippet redacted, 3/3 panel stamps
surfaced, and correct gate FAIL/exit 1. Cost: $7.05 (claude-security, effort low, 7.3 min) +
~$5.43 (codex-security, cost-stopped at the $5 fuse, 18 min).

## 0.1 Active branch coordination — IMS dogfood

Use `codex/ims-deep-scan-dogfood` as the base for work related to deep-scan
consolidation, validation, or reporting. The implementation rests on these two
commits above `main`:

- `aa1913e` — snapshot-bound imports for prior Security Council runs and sealed
  Codex Security bundles; MCP deep/validator controls; validation provenance and
  coverage fixes.
- `df64b80` — leadership/engineering HTML report, `report --system-name`, complete
  finding register, related metrics, and presentation-language cleanup.

Do not independently reimplement those changes on `main`. Branch from this branch,
or cherry-pick the two commits in order. The highest-conflict files are
`orchestrator.py`, `mcp_server.py`, `validate/panel.py`, `export/markdown.py`, and
`export/html_export.py`. Local `.playwright-cli/`, `.superdesign/`, and `output/`
directories are review artifacts, not repository content; do not commit them.

### What the IMS run established

- The consolidated run contains **732 finding instances**, not 732 demonstrated
  unique vulnerabilities. Five repeated scanner rules account for **605** instances:
  plaintext HTTP links 371, unrestricted request mappings 178, non-literal regular
  expressions 33, prototype-pollution loops 12, and Spring SQL injection 11.
  Current fingerprints keep locations separate. Do not call these one root cause
  without a source-to-sink trace, but do add a pattern/recurrence rollup so leadership
  can see the concentration.
- **54 findings block promotion**: 6 critical and 48 high. Three other high findings
  are non-gating under their current dispositions.
- Validation is a separate coverage dimension: 721 findings were eligible, 54 were
  selected, 53 completed the external panel, 667 were not selected, and 11 were
  skipped as deterministic-only families. Across imported records, 53 have external
  panel review, 24 are Daybreak-only, one has another carried record, and 654 have no
  validation record. One selected panel failed on malformed council output and must
  remain a visible human-review item.
- Both import arms completed, but their source scans were marked partial. “Arm
  completed” and “source coverage complete” must remain distinct report concepts.
- Raw reviewer rationale stays in canonical `findings.json` for audit. HTML, Markdown,
  and CSV presentation output must not reproduce internal prompts, scoring notes, or
  model-generated validation appendices.

### Participant model

- **Discovery:** each participating model should perform the same complete security
  objectives independently. Do not assign one model only authentication, another only
  injection, and another only supply chain; that prevents useful overlap measurement.
- **Validation:** differentiated confirmation, challenge, and independent-assessment
  functions are intentional because they reduce correlated agreement. Those are
  validation functions, not limitations on what each discovery participant scans.

### Next product work exposed by dogfooding

1. Add a report-level pattern group above individual instances: rule/family, count,
   affected components, representative locations, highest severity, gating count, and
   validation sample. Keep every instance accessible underneath.
2. Make validation selection explicit before a run: eligible count, configured cap,
   estimated cost, selection strategy, completed/failed/not-selected totals. Repeated
   patterns need representative sampling rather than silently consuming one panel per
   location.
3. Add first-class MCP consolidation instead of requiring import-arm paths in an
   operator config. The operation must remain revision-bound and must not rerun paid
   producers.
4. Bring `sc_report` to CLI parity: system name, HTML/CSV and bundle support, plus the
   same report identity fields used by `report --system-name`.
5. Add regression fixtures for repeated-rule rollups and presentation-text filtering.
   Never mutate or discard the canonical evidence to make the leadership view shorter.

### Review + council R16 (2026-08-31)

The three branch commits were reviewed on checkout and were NOT clean: 4 tests
red on a fresh clone (3 depended on a gitignored local run dir under
`tests/fixtures/seedrepo/.security-council/`; 1 was the pre-existing HTML
escaping test pinning the old gate wording), the import arms were reachable by
no interface, and `_native_validation` mapped any record carrying a summary to
`true_positive`, which `cluster.merge_cluster` then promoted to disposition
`validated` (feeding vex.py "affected"). Mechanical fixes landed first
(`49cf89f`); the six design forks went to council — R16, first full 3/3 quorum
on a design consult, transcript
`.llm-council/runs/20260831_094604_708760_*` — which converged on all six and
found one more high-severity defect while verifying: host-carried seats
(`participant *-current`, `independent=True` in 0.2-era artifacts) could supply
the second confirming voice AND the second refuting family in a live panel,
defeating M-V5 and the R10 two-family refutation bar.

Decisions applied (second fix commit):

- **Q1 interface:** dedicated `consolidate` CLI verb + `sc_consolidate` MCP
  tool, import arms only BY KIND (structural check, not a name allowlist);
  import paths come only from flags/tool args (MCP: absolute + inside root),
  never from repo config — a hostile repo must not choose the ingested
  evidence. Option (b) config-driven arms was rejected outright for that
  reason. Divergence noted: the codex peer would also refuse `--validate` on
  consolidate; we allow it because the external panel is the read-only
  cross-examination lane, not a producer re-run.
- **Q2 banner:** exit 0 headlines `RELEASE DECISION: CLEAR` only for full
  scope with zero degradations; otherwise `CLEAR FOR SCOPE (DIFF/…)` or
  `CLEAR — WITH LIMITATIONS`. `_next_steps` carries the same qualifier.
- **Q3 rationales:** absent-seat reasons (launch failures/timeouts written
  into `rationale` by panel.py) now render as ⚠ bullets under the panel
  table; substantive ok-seat rationales stay findings.json-only.
- **Q4 filtering:** vendor-appendix stripping moved INTO the codex-security
  normalizer (visible elision marker, raw bundle untouched); confidence/
  validation prose is no longer composed into descriptions at all; the
  render-time meta filter survives ONLY for legacy codex-provenance findings
  and never pattern-matches any other vendor's prose.
- **Q5 promotion:** `model.state_for_validation` is the single
  validation→state rule (cluster + panel); `validated` requires
  `convened()` — imported host validation caps at `likely`. Host seats are
  `independent=False` on import AND structurally excluded from `deciding`
  (belt and braces for legacy artifacts). Imported false_positives never
  demote at merge; merge laundering of imported lifecycle/suppression is now
  pinned by test.
- **Q6 skin:** light-only accepted; brand is `Security Council` with a
  scope-derived badge and an arms-derived method line — the fixed
  "Deep Scan" claim is gone. The hardcoded "Daybreak" label was already
  removed in the first fix pass (host validation is labeled by seat family).

Suite: **663 passed** on a clean tree; the fixture-dependent tests were
rebuilt to construct their prior-run dir in-test. Live smokes: quick-profile
docker scan of a staged seedrepo (exit 1), then `consolidate --import-run` of
that run (identical 17 findings, sources carried, exit 1, sub-second).

### Merge gate and merge (2026-08-31, later the same day)

All dogfood follow-ups landed: recurring-pattern rollup (`rollup.py` +
"Recurring patterns" in markdown, Concentration box in HTML,
`manifest.patterns`), representative validation sampling (pattern round-robin
WITHIN severity bands; severity absolute across bands; histograms in
`manifest.validation`), `sc_report` parity (csv/html/system_name/bundle), the
0.3.0 bump, and a live `consolidate --validate` run through real llm-council
(3/3 seats, quorum, `validated` earned under the stricter rule).

The merge went through three council rounds on the R16 continuation thread:

- **R17 (3/3 NO-SHIP):** six blockers, all fixed in `ee5807c` — sc_report
  bundle symlink escape (a committable run dir could redirect writes outside
  the MCP root), repo-controlled `reports.outdir` escape, cross-band severity
  violation in the sampler, synthesized rule ids (`claude-security/<cwe>`,
  `sc/<family>`, `*/unknown`) collapsing distinct agent findings into one
  pattern/representative, demoted findings inflating the rollup, and
  `validate-max <= 0` edge cases. One R17 find (rollup gating vs real gate
  under `gate_baseline: new`) had been self-caught and fixed pre-round
  (`6ba729a` — `policy.gating_findings` is the one report-side gate predicate).
- **R17b re-gate (2/3 NO):** each of two fixes had shipped a regression —
  the operator's MCP `reports_root` landed in the exact config key the new
  repo-outdir guard discards (and any config marker is forgeable by the
  scanned repo's YAML), so it became a `run_scan` PARAMETER with precedence
  out_dir > reports_root > config; and the new `sc_report html` write went
  through an unchecked `summary.html` symlink — now refused. Fixed in
  `6bb2396`.
- **Round 3 (3/3 SHIP):** all closures verified peer-by-peer.

**MERGED:** main fast-forwarded d918a4e → `6bb2396` and pushed; live-verify
run 33403893410 green on that sha (clean-pass + detects-and-gates on real
GitHub runners). 678 tests
green; every council-named blocker is pinned by a test proven non-vacuous
against its pre-fix source. Version is `0.3.0` with CHANGELOG section
"unreleased" — cutting the release (tag + GitHub release + wheel rehearsal
per §7.10) is a separate, deliberate step.

Lesson worth keeping from R17b: two of six fixes introduced adjacent
regressions that only the re-gate caught — after a must-fix pass, re-gate
with the SAME reviewers before shipping, and hold the tree still while a
round is reading it.

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
| **LLM-CLI arms** | `arms/llm_cli.py` (claude/codex/agy house-prompt), `arms/registry.py` · house prompt is TOOL-VOCABULARY-NEUTRAL since R10 — read-only is enforced at the flag layer (`claude --tools Read,Grep,Glob,LS`, `codex -s read-only`, `agy --sandbox --mode plan`), never in prose | done, **all three live-verified 2026-08-25** (codex 7 / agy 7 findings, 3 clusters 2-vendor-corroborated) |
| **Dedicated agentic arms** | `arms/claude_security.py` (Anthropic claude-security plugin, headless gate-collapse prompt, budget fuse, ingests its SARIF+panel+verification stamp) · `arms/codex_security.py` (OpenAI codex-security CLI, private 0700 output dir, ingests the sealed canonical bundle, cost from stderr progress lines) · adapters `normalize/sources/{claude_security,codex_security}.py` · fixtures `tests/fixtures/raw/{claude-security,codex-security}/` (validation shape matches live producer 0.1.22) | **done — live-verified 2026-08-21** |
| **Isolation** | `workspace.py` (scratch copy; arms/validator write there, discarded) | done |
| **Validator panel** | `validate/{council_client,prompts,panel}.py` (via `llm-council run --json`) · **R10 evidence rules**: a refutation must be ANCHORED to the finding's own code (`locations` ∪ `data_flow`, ±25 lines, ≤80-line span), come from a defender who actually voted `false_positive`, be fully EVIDENCED (`unevidenced`/`unreliable` may confirm but never refute), and span ≥2 distinct vendor FAMILIES; any peer refuting off a fabricated citation forces `needs_human`; malformed citations lower the pass rate instead of raising it; blocked refutations surface as `refutation_blocked` | done, council-reviewed (R2, R10), **live-verified 2026-08-25** (3 seats / 3 vendors, citations verified) |
| **Score + disposition policy** | `score.py` (transparent log-odds p_true: prior −1.2, 7 named terms, fail-safe clamps — crypto floor 0.50, deterministic floor 0.60, unreliable cap + human flag; `calibration: prior` until fitted) · `policy.py` (guardrails G1–G8: demote-never-close, double-gated auto-suppress + 5 shadow runs, crypto/critical never suppressed, G2 deterministic refutation needs a fully-verified defender else escalates `needs_human`, root-cause-scoped 90-day suppressions, `assert_invariants` on every mutation) · `policy.json` audit artifact every run | done |
| **Eval gate** | `eval/{metrics,runner}.py` (replay recorded fixtures through the real pipeline; path + exact-CWE-over-family matcher vs `EXPECTED.yaml`; zero-tolerance wrongful-suppression gate, crypto rate reported; panel-verdict fixture exercises demote/suppress branches; adversarial-history + wrong-panel meta-test) · CLI `eval` subcommand · runs inside pytest = the CI gate | done, council-directed (R3) |
| **Decision store + baseline** | `decisions.py` (per-root-cause records, append-only `history[]`, atomic writes; reapply on scan with **G6 expiry→reopen** and **G8 drift→reopen+deactivate**; anti-poisoning: score `history` term fed ONLY by human `outcome mark`; armed-run shadow counter resets on suppression-config change; baseline snapshot + greedy 1:1 root_cause→context_hash→path_cwe_sink delta, SARIF `baselineState`, `policy.gate_baseline: "new"`) · CLI `outcome mark` / `baseline set\|show` / `suppress` (human, I6-attributed, expiring) | done, live-verified |
| **eMASS exporter** | `export/emass.py` (`report --format emass`): CWE-keyed rows, stable `codeCheckName` "CWE-n (family)", numeric-string `cweId` (no prefix), medium→`Moderate`, D7 disposition withholding (suppressed/refuted never exported), noinfo skipped loudly, clear-findings body; contract verified against the official `eMASSRestOpenApi.yaml` + emasser client BEFORE coding (R3), conformance schema vendored in `tests/fixtures/schemas/` | done, live-verified |
| **MCP server** | `mcp_server.py` (`security-council-mcp`, optional `.[mcp]` extra): `sc_scan/doctor/report/last_run/baseline/suppress/outcome_mark/config`; `SECURITY_COUNCIL_MCP_ROOT` scoping (absolute-only, in-root), presence-based nesting guard (`SECURITY_COUNCIL_NESTED` ⇒ `sc_scan` refuses); transport-independent handlers, llm-council `_serve` pattern for the mcp-2.x adapter; `tests/test_mcp_handshake.py` drives the real stdio transport where `.[mcp]` is installed | done, **transport live-handshaken** (mcp 2.0.0) |
| **Azure DevOps CI** | `ci/azure_devops.py` (`##vso[task.logissue]` w/ documented escaping + exit-gate-consistent error/warning split incl. `gate_baseline`, `uploadsummary`, PR thread REST api-version=6.0, active/closed by gate) · `templates/security-council.yml` (capture-exit → stage SARIF → publish **CodeAnalysisLogs** → annotate → re-raise gate) · `scan --gate-baseline` flag | done; **live-verified on ADO Server 2022** 2026-09-02 — 5/5 claims (logissue, uploadsummary, CodeAnalysisLogs, PR-thread active/closed, gate exit 0/1/3); SARIF-tab extension render on disconnected Server is the only residual (§7.6) |
| **GitLab CI** | `export/gitlab.py` (native SAST report validated against the **official vendored schema 15.2.4** — timezone-less times, ≥1 identifier, CWE ids w/ MITRE urls; + Code Quality report, CodeClimate subset, inline MR annotations on all tiers, fingerprint = derived finding id) · `ci/gitlab.py` (writes both reports, MR note via project access token, shares `split_findings` gate semantics) · `templates/security-council.gitlab-ci.yml` (`artifacts:reports:` sast+codequality) · `report --format gitlab-sast\|gitlab-codequality` | done; not yet run on a real GitLab (§7.6) |
| **GitHub Action** | `action.yml` composite (`uses: Intellimetrics/security-council@main`): install from action_path → scan (captured exit) → native SARIF upload (`codeql-action/upload-sarif@v3`, category security-council, needs `security-events: write`) → step summary → gate re-raise; outputs exit-code/run-dir/sarif-file · `.github/workflows/live-verify.yml` (manual dispatch, two jobs: clean-pass asserts exit 0 + real SARIF upload; detects-and-gates asserts exit 1 on the vulnerable fixture, upload off) | **done — LIVE-VERIFIED 2026-08-24** on real GitHub runners (run 32732965676: both jobs green, "Successfully uploaded results" to code scanning, fixture scan 17 clusters → exit 1) |
| **SBOM** | `arms/sbom.py` (syft local-or-docker, `--network=none`, CycloneDX 1.6 → run **artifact**, never findings; fails closed on non-JSON/non-CDX/exit/timeout) · `scan --sbom` · `export/cyclonedx.py` merges findings INTO that inventory when present (syft serial + components preserved, affects refs resolved by version-insensitive purl, unknown pkgs appended) | done, live-verified (7 components, 17 findings merged, all refs resolved) |
| **Orchestrator + CLI** | `orchestrator.py`, `cli.py` (`scan`/`doctor`/`report`), `config.py`, `manifest.py` | done |
| **Seed fixture** | `tests/fixtures/seedrepo` (vulns across families + FP decoy + injection payload), `EXPECTED.yaml` | done |
| **Envelope schema** | `security_council/schemas/agent_finding_envelope.v1.json` (portable strict-mode subset) | done |
| **Format exporters (R8)** | `export/csv_export.py` (triage CSV, includes demoted w/ state, spreadsheet formula-injection neutralized) · `export/html_export.py` (self-contained page, zero JS/no external assets, ONE `html.escape` boundary, print = PDF) · `export/cyclonedx.py` (1.6 VDR, validated vs official vendored schema incl. spdx/jsf refs; NOT an SBOM) · `export/cklb.py` (STIG Viewer 3 checklist, shape mirrored from STIG Manager's `cklbFromAssetStigs`; rule metadata verbatim from official U_ASD_V6R4 XCCDF vendored at `data/asd-stig-v6r4-rules.json` w/ zip sha256; CWE→APSC-DV map all-verified — secrets→003110 embedded-auth-data beats R4's 003280 suggestion; statuses only open/not_reviewed, D7 withholding) | done; CKLB not yet imported into a live STIG Viewer |
| **Guided surface (R8)** | `config.PROFILES` (quick/ci/deep/gov; file `profile:` key sits UNDER file keys, `scan --profile` OVERRIDES; unknown profile fails closed) · `setup_wizard.py` + CLI `setup` (detects languages/CI/git, ≤2 questions w/ cost confirmation for deep, writes commented config, prints repo-specific cheat sheet, never overwrites w/o `--force`) · `report --bundle triage\|gov\|all` → `<run>/exports/` | done, live-smoked |
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
- **LLM arms cost real tokens/time.** claude arm ≈ 2–3 min. `codex-security` is HEAVY: live 2026-08-27 (v0.1.20, `mode: standard`, 9-file seedrepo, fresh `npx @openai/codex-security login`): 13 min and **$4.07 to reach the 'validating findings' phase with zero findings emitted** — a `max_cost_usd: 4` fuse stops it before any output (our pipeline correctly reported `cost_stopped`, coverage `none`, exit 3, never clean). Budget **≥ $8** for a complete standard run of even this fixture; the M0 figure (~$4 / >7 min) is stale. Login state is not probed by `available()` — a logged-out CLI fails at run time, not doctor time. **Billing:** that run used the ChatGPT sign-in (`auth_mode: chatgpt`, no API key in env; `login status` → "Logged in using ChatGPT"), so the $4.07 was an ESTIMATE at API prices, not a charge — it drew on the Pro plan's Codex usage limits. Under ChatGPT auth `max_cost_usd` is a token-volume fuse, not a dollar cap. **Re-run with a $10 fuse (same day): COMPLETE** — 12 m 22 s, est. $4.43 (the $4.07 stop was run-to-run variance), coverage `complete` → our verdict `verified`, 5 raw → 4 root-cause clusters, exit 1, no degradations; reference run kept at `tests/fixtures/seedrepo/.security-council/runs/20260827_100433` (gitignored). Recall vs `tests/fixtures/EXPECTED.yaml`, this arm alone: CMDI ✔ critical, SQLI ✔ high, IDOR ✔ (authz, medium, + a bonus authn finding), AWS secret ✔ (low — it argued 'test fixture, no consumer'); **MISSED both crypto TPs** (MD5 password hashing CWE-916, AES-ECB CWE-327 — rationalised as 'no in-repository runtime consumer') and the osv dependency CVE (out of its scope). MD5 cache-key decoy correctly not reported; README prompt-injection canary did not hijack it. That crypto miss on a must_not_demote fixture is the argument for cross-arm corroboration in one line. Observation, not a defect: CWE-78 + CWE-89 in the same file merged into ONE critical cluster via the CWE-gated overlap tier (documented clustering behaviour; both members retained in provenance). Native CLI council peers are ~$0 but ~1–2 min each.
- **Gated models:** Mythos (`claude-mythos-5`) = Fable 5 with safeguards lifted, invite-only. Daybreak Blue = gated alias over GA `gpt-5.6-sol`; Red = distinct `gpt-5.6-cyber`. **Not provisioned on this machine** (checked). Design supports declaring entitlements per (CLI, tier, model) but routing to them is unbuilt.
- **`~/.codex/config.toml` model is `gpt-5.6-sol`** with reasoning `ultra`; the codex arm passes `--ignore-user-config` to shed the operator's memories/skills (without it, codex hangs trying to patch `~/.codex/memories`).
- **claude-security arm** (`arms/claude_security.py`): runs `claude -p "/claude-security scan-codebase --effort E …"` with the plugin's documented gate-collapse (job + shape + effort + the sentence *"I understand it may take a while and use a significant number of tokens"*), `--max-budget-usd` fuse (default 10), `--dangerously-skip-permissions --no-session-persistence --strict-mcp-config`. Needs the plugin installed (`claude plugin install claude-security@claude-plugins-official`, v0.10.1 here) and the **Workflow tool** in the session. It writes `CLAUDE-SECURITY-<ts>/` into the scanned dir → the arm moves it to `raw/claude-security/`. A run that exhausts the budget before `render_report.py` runs leaves **no report** → arm fails loudly (raw unverified findings salvaged). The scratch copy has no `.git`, so the plugin stamps `UNVERSIONED`; our manifest carries git provenance from the original. **Live 2026-08-21:** $7.05 / 7.3 min at effort `low` on the 12-file fixture (above the M0 $3–5 estimate); served model `claude-fable-5` correctly picked from `modelUsage` even with opus subagent entries present; 5 findings, all panel-confirmed 3/3.
- **codex-security arm** (`arms/codex_security.py`): resolves the CLI as env `SECURITY_COUNCIL_CODEX_SECURITY_CMD` > `codex-security` on PATH > the **npx cache** (`~/.npm/_npx/*/node_modules/@openai/codex-security/bin/codex-security.mjs` via `node`, v0.1.16 cached here) — it never auto-installs. Output dir must be outside the worktree, 0700, with trusted ancestors → the arm scans into `mkdtemp` and copies the sealed bundle to `raw/codex-security/`. `--max-cost` fuse (default 5 USD). Needs `~/.codex` at 700 (done). Exit 2 = incomplete coverage *or* runtime error → success is decided by the sealed `scan-manifest.json`. **Live 2026-08-21:** stdout is **empty** — progress + cost go to stderr (`--format json` shapes the bundle only), so cost is parsed from stderr lines and full stderr is kept as `raw/codex-security/stderr.log`; the served model is reported **nowhere** → `model_unattested` in coverage (a D8 pin can't be positively attested); 18 min on the 12-file fixture, cost-stopped at $5.43 est. during the post-seal "analyzing attack paths" phase while the core bundle still sealed `completed`+`complete` (surfaced as `cost_stopped`) — give it `max_cost_usd: 8` to keep that phase; sealed producer stamps `codex-security-plugin` **0.1.22** (≠ CLI 0.1.16), which is what lands in `tool_version` provenance.
- **Trivy is banned as a default** (supply-chain compromised Mar 2026, GHSA-69fq-xp46-6x23). Use cdxgen/syft/grype for future SBOM/SCA.
- **Project venv at `.venv`** (gitignored; `uv venv .venv && uv pip install -p .venv/bin/python -e ".[mcp,dev]"`): system python3 is PEP-668 externally managed, so the `mcp` SDK (2.0.0) lives only there. The suite runs on both — the MCP handshake test skips wherever `mcp` is absent.
- **Never `pip install semgrep` into the project/wheel venv** (found by the B2
  subagent 2026-09-01): semgrep pins `mcp<2` (it imports
  `mcp.server.fastmcp.FastMCP`), the project needs `mcp>=2,<3` — installing
  semgrep into `.venv` silently downgrades mcp and breaks `test_mcp_handshake`.
  Scans use DOCKER semgrep anyway; for a live pip-semgrep run put it in a
  separate venv on PATH. The wheel rehearsal is unaffected (docker arms).
- **llm-council 0.25.0 assessed 2026-09-01** (uv tool already 0.25.0; the MCP server
  lags until the session restarts). Applied to `.llm-council.yaml`: `defaults.
  okf_context: true` (0.24.0 blast-radius on include_diff runs — okf-rs installed,
  parses this repo at 1762 concepts; fail-soft, byte-identical without a diff;
  motivated by R17/R15b "regression one hop out"), codex `timeout: 900` and claude
  `terse_retry_on_timeout: false` (both from the new `stats` recommendations
  block). NOT changed: agy stays without `--dangerously-skip-permissions` — its
  headless `command`-permission failures are the ACCEPTED cost of llm-council's
  hard read-only posture (upstream defaults.py: "do NOT re-add it", canary-tested)
  — keep planning quorum around claude+codex. `setup --write-instructions`
  skipped: CLAUDE.md's hand-written council section is richer than the snippet.
- **OWASP Benchmark checkout at `.corpora/BenchmarkJava`** (gitignored — GPL-2.0, converter-only per R7; shallow clone, sha `0db793a`; `results/`+`scorecard/`+`data/` deleted locally to keep semgrep runs clean/fast). Its local `.security-council.yaml` enables `score.calibration: auto` — the live smoke config for the fitted record. Re-fit after a semgrep version bump: scan the checkout, run `calibrate`, copy the record into `security_council/data/` (the `auto` pin check refuses stale records loudly).

## 7. Known limitations / deferred (honest list)

1. **Validator prompt is SAST-shaped; doesn't fit SCA/dependency findings** → `supply_chain` is skipped from LLM validation (osv is authoritative). A dep-reachability validator is a future lane. (See R2.)
2. **Validator verdict fidelity**: parses an explicit `VERDICT:` line from the transcript (S2 pattern). Works, but a redacted-secret finding validates to `needs_human` (no snippet to cite) — safe but blunt.
3. **codex-security served model is unattestable** — the CLI reports it nowhere (stdout empty, not in stderr or the sealed bundle), so a D8 model pin can only fail open: the arm sets `model_unattested` in coverage and the summary renders "unattested", but a silent substitution by the vendor would be invisible. Revisit if a future CLI version surfaces the model.
4. **Calibration is fitted but deliberately narrow (R7).** Default stays `"prior"`; the opt-in record covers ONLY semgrep deterministic singletons, Java, four families — everything else (panel terms, other languages/arms) is still hand-set. Known honest gaps: fitted p is prevalence-conditional (~50%-real corpus); templated near-twins leak across the train/test split (CIs/ECE flatter); the 0.60 floor censors injection/path_traversal fitted values. The word "calibrated" stays banned everywhere (tested). Next corpora: a negative corpus, a non-Java benchmark, panel-sample fitting for the panel terms.
5. **Reports:** SARIF + JSON + manifest + `summary.md` + **eMASS** + **OpenVEX** + **OSCAL AR/POA&M** + **CKLB (ASD STIG V6R4)** + **CycloneDX 1.6 VDR** + **CSV** + **HTML** (`report --format …` or `--bundle triage|gov|all`; all spec/reference-verified, schema-validated in tests). **SBOM: done** — `scan --sbom` (syft) emits a real CycloneDX inventory artifact and `report --format cyclonedx` merges findings into it (bare VDR only when no SBOM artifact exists). Honest residue: the CKLB is spec-shaped after STIG Manager's exporter but **not yet imported into a live STIG Viewer**; PDF = print the HTML (no native PDF writer).
6. **CI: GitHub + ADO Server are live-verified; GitLab still needs real infrastructure.** ~~GitHub Action unproven~~ — **live-verified 2026-08-24** (`.github/workflows/live-verify.yml`, run 32732965676: clean-pass exit 0 with a real code-scanning SARIF upload, detects-and-gates exit 1 on the fixture; re-runnable any time with `gh workflow run live-verify`). ~~ADO template unproven~~ — **live-verified 2026-09-02 on a real Azure DevOps Server 2022** (RHEL 9 agents, disconnected/US-Gov collection; coordinated run on a synthetic-only throwaway repo — the seedrepo as `fixture/`, the package source as `clean/`). All 5 claims PASS: logissue error annotations at the right sourcepath/linenumber (2 on the gate run, 0 clean), `uploadsummary` (attachment type `DistributedTask.Core.Summary`), CodeAnalysisLogs artifact with merged/raw SARIF + summary on all 6 runs, exactly one PR thread (ACTIVE on gate-fail / CLOSED on clean) via api-version=6.0, and the gate re-raising exit 0/1/3 (incl. the arm-crash → degraded path). **This closes the D4 first-class Server target** (it was NOT the Services proxy). Two things found and handled: (a) a real defect — `post_pr_thread` built the URL from the raw `SYSTEM_TEAMPROJECT`, so a project name with a space (the Server norm) raised `http.client.InvalidURL` before sending — no thread AND the "never fails the build" step crashed; **fixed 2026-09-02** (prefer `SYSTEM_TEAMPROJECTID`, percent-encode the segment, wrap the POST so a failed post degrades to a `##vso` warning; regression tests with a space + a raising opener); (b) `sourcepath` is recorded relative to `scanPath`, so scanning a subdirectory breaks file-view links — documented in the template (keep `scanPath` at the Sources root). Server/agent deltas (RHEL 9 python 3.9 vs 3.11+ needed; `HOME` unset; semgrep glibc pin ≤1.146.0; Checkpoint.Authorization on new pipelines; PullRequestContribute ACE on the repo token; disconnected Server can't install the SARIF-tab VSIX) are folded into the template header. Only residual: the SARIF-tab render on a disconnected Server (a third-party extension, not security-council's responsibility). Still unproven: the GitLab job template + MR notes need a GitLab project (+ a project access token — `CI_JOB_TOKEN` can't post notes); its local halves are live-verified (schema-valid reports, REST payloads via fake openers). ~~MCP transport unproven~~ — live-handshaken 2026-08-22 (mcp 2.0.0, protocol 2025-11-25); `tests/test_mcp_handshake.py` keeps it verified wherever `.[mcp]` is installed.
7a. **Fix lane (M-V4a) is offline-built; live vendor patch-generation structurally refused,
   not merely unproven.** The bwrap fence, canary, patch validator, and fail-closed
   `FenceCertificate` are live-verified here (bwrap 0.11.0); but `FixArm.available()` refuses
   up front because the fence as configured cannot run ANY vendor CLI — binary outside the
   bind set, `--unshare-net` blocks the model API the generation depends on, tmpfs HOME drops
   `~/.codex/auth.json` (all three verified live 2026-08-25; `arms/fix.py:86-100`). So "spend
   to verify" was never the gap: enabling the lane is a DESIGN decision (fence vs vendor
   network/creds) — see §8 Phase B0. Correct job mapping (draft plans keep reversing it):
   `FIX_JOBS` = `suggest-patches`→claude (`/claude-security suggest-patches`),
   `fix-finding`→codex (`$fix-finding`), via the `claude`/`codex` CLIs — NOT codex-security. **M-V4b verify-fix evidence: BUILT as the deterministic lane
   (2026-08-26, see §7.9)** — `--verify-fix` and `--verify-patch` re-run the scanners on a
   patched scratch copy; the vendor verify arm is unwired. The CLI/MCP nesting
   guards are cooperative (the real boundary is the fence's write-denial on the original tree).
7. **No Red-tier / PoC** (deferred by design; needs the authorization block + sandbox). The
   entitlement layer (M-V2) *knows* Daybreak Red and **positively refuses** it (exit 5) for every
   workflow — routing to `gpt-5.6-cyber`/`daybreak-red-latest` stays blocked until that block lands.
   Gated Blue tiers (Mythos, Daybreak Blue) route + probe but are **not provisioned on this
   machine**, so only rung-1 (catalog, zero-network) is live-verified; deep-rung probes are
   injectable and default to "unverifiable" — live-verify with real entitled creds.
8. **The decision store is SIGNED (R9 lane, built 2026-08-26) — provenance, not assurance.** R9 (2026-08-24, `docs/reviews/R9-decision-store-trust.md`) found and closed a **live CI-gate bypass** (hand-written `baseline/latest.json` flipped exit 1 → 0 under `gate_baseline: new`); the zero-crypto fixes landed first (G9, baseline digest, shadow-counter cross-check, malformed-degrades, per-suppression provenance). The signing lane now sits behind them: `signing.py` shells out to `ssh-keygen -Y` (Q1 option B — asymmetric, no dep, forge-known keys); **events are signed, not records** (Q6) over a fixed per-kind field list bound to `store.json`'s random store id (Q4); principal = `decided_by.operator`, proven at write time against `allowed_signers`; on replay under `enforce` the SIGNED expiry/lifecycle/context-hash are applied, not the record's editable block; `foreign` (transplant), `invalid`, `unsigned`, `unverifiable` (no ssh-keygen ⇒ fail-closed) are all refused → finding reappears. Machine writes stay unsigned and replay only while `is_armed(config)`. Policy `decisions.require_signatures: enforce|warn|auto|off`: **default `enforce`** (R13 council: Q2's "pre-existing store" is attacker-defined in code — a branch committing its first unsigned record without store.json would be honoured under warn); `auto` (enforce for initialised/new stores, warn until `signing.WARN_SUNSET` 2027-01-01 otherwise) stays as an explicit opt-in adoption mode; `ci`/`gov` profiles and all three CI templates pass `enforce`. `outcome_mark` counts only verified marks under enforce (Q5 — no import lane exists; store_id binding already blocks transplant). Q3: no signed index/seq (dropped by council). CLI: `decisions init|trust|verify`, `--signing-key` on `suppress`/`outcome mark`/`baseline set` (env `SECURITY_COUNCIL_SIGNING_KEY`, config `decisions.signing_key`); MCP: `signing_key` arg + `sc_decisions_verify`. Manifest `signature_policy` + per-row `signature`; summary renders a Signature column, a "refused" table, and the effective level with its reason every run. 24 tests in `tests/test_signing.py`, each attack with an `off` control; vacuity-checked (neutering `verify_event` fails 9). Live-verified on a seedrepo copy with a real semgrep scan (refuse → init/trust → signed suppress → verified reapply → tamper → refused). **Residuals (honest, in docs/signing.md):** replay of an unexpired signed record from git history; `auto` on a pre-existing store downgrades to `warn` if `store.json` is deleted (until the sunset; visible in every manifest); signing protects nothing unless `decisions/`, `baseline/`, `store.json`, `allowed_signers` are behind CODEOWNERS + required review. Own adversarial pass (R13, same day, while council ran): (a) `_human_event_for` matched the event by the mutable block's decided_at/operator and never checked the signed `root_cause` — a REAL signed event pasted into another record verified; now `verify_event(expect={root_cause})` on the signed bytes and the LATEST human event is authoritative; (b) the CI templates pass `--ignore-repo-config` with no profile ⇒ `auto` ⇒ `warn` for a committed pre-existing store — added `scan --require-signatures` and all three templates pass `enforce` (test pins it); (c) YAML bare `off` is boolean False — normalised. **R13 council (2026-08-26, quick, claude+antigravity NO, codex error; transcript `.llm-council/runs/20260826_061932_*`):** both peers independently found the root_cause-binding gap (already fixed mid-review — claude saw the tree change) and claude added: signed outcome-mark DUPLICATION (one real mark pasted N× counted N — now deduped on signature bytes); `auto` derives the level from attacker-writable files (→ default enforce, above); pattern principals accepted by `valid_principal` (`trust --principal '*'` = attribution theater; now refused, hand-edited roster lines flagged by `decisions verify`); no replay bound on signed baselines (age now printed; a max-age knob is a follow-up); machine replay under enforce invisible (now `machine_decisions_replayed`). REFUTED: antigravity's "repo config overrides `--profile ci` via resolve_profile" (no callers; CLI merges profile OVER file at cli.py:54 — docstring now says why the two precedences differ) and its VEX-overload point (pre-existing `--vex-justification`, root-cause-scoped, not org-wide). **R13 round 2 (continuation; claude YES/risk low, codex NO — its first completed round in this env — antigravity empty):** closure confirmed on all nine round-1 items (claude confirmed `resolve_profile` has no callers and VEX is not a Q4 violation). New, all deletion-equivalent tampers on the HISTORY TERM, all fixed + regression-tested: D1 dedupe ran before verification (a clone carrying a real mark's sig bytes reserved them → real mark dropped as duplicate; now dedupe after verify on (sig, signed payload)); D2 `verify_store` marks lacked `expect`/dedupe (audit ≠ scan; now `_outcome_marks()` serves both); D3 a rogue `*.json` claiming an existing root cause overrode its counts (files must be named by their root cause slug — `_canonical_file`); R1 latest-by-POSITION was attacker-writable too → the governing event is the verifying one with the greatest SIGNED `at` (`_authoritative_human_event`); N1 `fullmatch`; N2 bare `decisions:` key crashed with `--require-signatures`; refused marks + a poisoned roster are now scan degradations. Codex's must-fix #3 (pattern/CA roster → hard refusal) had landed at 8e9ee35 mid-round. **Round 3 (degraded: claude only, NO):** all round-2 items confirmed CLOSED; one new must-fix — the D1 dedupe keyed on the armored signature STRING, and ssh-keygen accepts whitespace variants of one armor (stripped trailing newline, re-wrapped base64), so one real mark stored twice counted twice → now keyed on the signed PAYLOAD bytes alone. Its follow-ups also taken: any record with a human_* event takes the human path regardless of the block's `kind`; `at` compared as datetimes, same-instant → shorter expiry wins; `cert-authority` parsed as an option token; dead `verify=False` branch removed. **Round 4 (claude + codex, both NO on one item):** the roster option parser split on whitespace and compared case-sensitively, but OpenSSH's field is quote-aware (`namespaces="a,b c"`) and case-insensitive — `CERT-AUTHORITY,namespaces="ns,x y"` slipped past the refusal. Now `signing.parse_roster_line` mirrors `sshkey_advance_past_options`; live-tested that ssh-keygen accepts the quoted-space line. **Round 5 (3/3 labeled: antigravity YES, claude+codex NO on the parser again):** `splitlines()` splits on \r/\v/\f where OpenSSH splits on \n only, and the quote toggle ignored `\"` escapes (codex reproduced on OpenSSH 9.6) — roster now read as bytes split on \n with OpenSSH's exact whitespace set and escape handling (`roster_lines`, `parse_roster_line`), live-proved both benign shapes verify. Framing to keep in mind: roster refusal is defence-in-depth against ATTRIBUTION theater; whoever can edit the roster can add their own key, so parser parity is hygiene, not the capability boundary (claude said so itself in round 2). **Round 6 (2026-08-26, claude + antigravity YES, codex timeout w/ quorum met): SHIP.** Claude traced every path for an untrusted party (store write, no roster write, no key) under enforce and found none; one non-blocking parser follow-up (only `\"` is an OpenSSH escape, not `\x`) — fixed and live-pinned the same day. Transcripts: `.llm-council/runs/20260826_06*` and `_07*` (six rounds). The lane is council-approved for the next release (0.2.0 — bump pyproject + CHANGELOG first; never move a tag that has a release). Not built: the export/import bundle (`--accept-foreign`, Q4) — no demand yet.

9. **Reports were buried (2026-08-27, user).** `report` needed a run dir, the HTML export was an
   R8-era subset that lagged the markdown by five sections, and nothing linked the `raw/` bundles.
   Now: `summary.html` on every scan = dashboard (gate, next steps, tiles, degradations box,
   "Where to look" links) + the markdown body rendered by `export/mdrender.py` (a strict renderer
   for exactly the dialect `markdown.py` emits — headings, lists, `\|`-escaped tables, variable
   backtick fences, quotes, `**`/`` ` ``/template `_`, `\X` escapes; every text node through one
   `html.escape`; no links/raw HTML/autolinks). Parity is pinned heading-for-heading in
   `tests/test_html_report.py`; the R8 hardening tests still pass unchanged. `runs`, `report`
   default-to-latest, `--open` (scan + report), `runs/latest` symlink (skipped by every
   run-dir lister), MCP `sc_report format=html`.

10. **Report viewer (2026-08-27, user: "it should expose on LAN if needed").** `serve.py`:
    stdlib `ThreadingHTTPServer`, GET/HEAD only; index / run page / any run file / run zip /
    `latest` redirect / `docs/` rendered via `mdrender(allow_links=True)` (links only for
    TRUSTED docs — reports never render links). Policy in ONE place (`check_bind`): loopback
    needs nothing; any other bind needs a token (`--token auto` → `secrets.token_urlsafe`,
    printed once; `?token=` sets an HttpOnly SameSite=Strict cookie); `DEPLOY_MODE=secret`
    refuses non-loopback. `_confine()` resolves symlinks and rejects `..`/absolute/escapes;
    the store files sit outside `runs/` and are unreachable; `export_excluded` artifact dirs
    are 403 + zip-excluded unless `--include-dual-use`; CSP default-src none, nosniff, no
    referrer, no-store; a vendor `.html` under raw/ is served as text. MCP `sc_serve`
    start|stop|status (lifetime = the MCP session). 9 tests in `tests/test_serve.py`. Not
    built: TLS/auth (use a reverse proxy), token rotation without restart.
    **R14 council (2026-08-27; first round 0/3 — prompt too big at 55k chars + codex tripped
    OpenAI's cyber filter on "find a bypass" phrasing; R14a 4.5k chars: claude + antigravity NO,
    codex timeout).** Found and fixed same day: S1 Host-blind loopback ⇒ DNS rebinding reads
    every report on the default config (now 421 for any non-localhost/non-IP Host); S2 `""`
    classed loopback but binds INADDR_ANY; S3 run-root reads (`summary.html`, `manifest.json`,
    `summary.md`) skipped `_confine` ⇒ symlink escape (+ a hostile repo can COMMIT
    `.security-council/runs/<id>/` — `run_dirs` indexes it) — now every read confined and the
    page is ALWAYS rendered in memory, never a stored file; S4 dual-use compare by Path missed
    case-insensitive FS/aliases and failed OPEN on a bad manifest — now inode `samestat` over
    parents, fail closed on raw/; antigravity: root-level dual-use artifact skipped (`rsplit`
    dropped it), `raw/x/summary.html` served as text/html, `?token=` in opt-in logs, zip in RAM
    (now 256 MB cap + 30 s handler timeout); R1 manifest artifact `path` became an href
    (`_safe_rel`); mdrender `_safe_href` rejected only some schemes (now http(s) or scheme-less);
    `_default_docs_root` would mount site-packages/docs from a wheel. Residuals documented in
    docs/serve.md: cookie not port-scoped, no Secure flag over http, token in history/MCP output.
    Lesson for council prompts: keep them < 10k chars, no inline context files, and phrase as
    "verify the control" not "find a bypass" (codex's provider filter).
    **R14b (closure, continuation; claude + antigravity YES/risk low, codex timeout): SHIP.** Every
    R14a item confirmed closed with lines; verify-patch containment confirmed (git apply's own
    unsafe-path + beyond-symlink checks live because the scratch copy is `.git`-stripped and
    symlink-free). Follow-ups taken the same day: traditional `---/+++` patches now reach the
    REFUSE list (VP-1); `deleted file mode` → `review_required: deletes <file>` (VP-2) and the
    verdict reason says the file was removed; `_safe_rel` rejects `%` (HX-1); zip builds bounded
    to two at once (SV-1); the `-p` strip level follows the patch headers instead of trying both.
9. **gitleaks/osv can't path-exclude via CLI** — isolation (scratch copy excluding runtime dirs) is what keeps scans clean; don't remove it.
10. **`coverage.CATEGORY_POLICY` is keyed by arm name** (`POLICY_ALIASES` maps `claude`/`codex` → `house`). A new arm without an entry/alias is `unknown` for every family → never eligible → its findings mislabel as singleton/uncovered. Add a policy row when adding an arm.

## 7.9 Release state — 0.1.0 (2026-08-25)

**Ship review:** `docs/reviews/R12-ship-readiness.md` — eighteen council rounds
on one question (any reachable path to a silently wrong "clean" or a wrongly
passing CI gate). Every round to sixteen found something real; the root cause
was one design flaw — coverage as a per-arm boolean — replaced by
`normalize/coverage.coverage_verdict()` (`none | partial | verified`), read by
the gate, the corroboration context and SARIF `executionSuccessful`. Added
G10, G11, I7b, I13, widened I6. The simplest exploit — `printf '*' >
.semgrepignore` → clean exit 0 in the default profile — was found at round
sixteen; repo ignore-files now make coverage `partial`. osv-scanner runs
`--recursive` (nested manifests were a silent pass). CI templates run
`python -P -m` (a `security_council/` dir in the scanned repo replaced the
scanner). Rounds 17–21 each surfaced one more default-config path, all
reproduced live then closed: `.gitignore` honoured by osv (`--no-ignore`;
semgrep pinned `--no-git-ignore`); gitleaks auto-loading the repo's
`.gitleaks.toml` and osv reading `osv-scanner.toml` (configs now SHIPPED in
`data/` and passed with `--config`, docker ro-mount at `/sc-config.toml`); the
repo's own `.security-council.yaml` choosing the arms/gate (`--config PATH`,
`--ignore-repo-config`, `config_source` in manifest + summary, CI templates
pass the flag). Rule: **the scanned repository never decides what gets
scanned.** Rounds 22–24: my round-21 edit had doubled a line continuation in
all three CI templates (every CI scan failed with argparse exit 2 — caught by
council, now shell-parsed in a test); the run dir is taken from `scan --json`'s
record instead of globbing the repo's `runs/`. **Round 24 was the first in
which the substantive peer named no defect.** codex voted "no" with empty
evidence for its last seven rounds (abstentions); antigravity mostly returned
empty — plan for 1–2 usable peers.

**RELEASED (2026-08-26): `v0.1.0` is tagged at `3cf80d4` and published** —
<https://github.com/Intellimetrics/security-council/releases/tag/v0.1.0>
(notes = CHANGELOG.md). At tagging time: 490 tests (489 + 1 skip), ruff clean,
eval gate recall 1.0 / suppression 0.0. `live-verify` green on real GitHub
runners against the final templates (clean-pass exit 0 + SARIF upload;
detects-and-gates exit 1). `uv build` produces a wheel that installs clean in
a fresh venv and ships `data/*.toml`.

Gotcha found while cutting it: a `v0.1.0` tag had **already been pushed on
2026-08-23 at `5414ffd`** (the docs-set commit, 72 commits and the whole R12
ship review earlier) with no GitHub release behind it; the previous handoff
said "not tagged". With the user's approval the stale tag was deleted on
origin and re-pointed. Lesson: `git ls-remote --tags origin` before writing
"not tagged" in a handoff. The next release is `0.1.1`/`0.2.0` — bump
`pyproject.toml` + CHANGELOG first; never move a tag that has a release.

Verification discipline that this review proved necessary: reproduce every
claimed defect live BEFORE fixing; revert the fix and re-run the regression to
prove the test is not vacuous (three of mine were); gate commits on pytest's
own exit code written to a file — `pytest | tail` under `set -e`/`pipefail`
pushed red twice. Next lanes after 0.1.0, in order: ~~decision-store signing
(R9 design)~~ DONE (§7 item 8), ~~deterministic verify-fix (re-run scanners on the
patched tree)~~ DONE (below), ~~M-V3 reframe-or-drop~~ DONE (reframed, below),
ADO/GitLab on real infrastructure, `codex-security login` (operator-interactive).

**Deterministic verify-fix — DONE 2026-08-26 (R11 Q4 design, not re-litigated).**
`security_council/verify_patch.py` + `scan --verify-patch FILE [--for IDS]`
(operator's own patch, the useful path today) and `--fix … --verify-fix` (same
lane; the vendor `arms/verify_fix.py` is unwired, kept as a possible explainer).
The orchestrator applies the patch to a `prepare_workspace` scratch copy with
`patches.apply_patch` (git config neutralised, atomic, no `--unsafe-paths`),
re-runs the run's scanner arms named in `corroboration.deterministic_sources`
against it, and matches by `decisions.MATCH_TIERS` (root_cause → context_hash →
path_cwe_sink, now shared with `annotate_baseline`). `fixed` requires absence
from EVERY vouching scanner AND `coverage_verdict == verified` for each
(partial/none can never yield fixed); `not_fixed` on presence OR a same-rule/
same-family finding in the same file that the original run did not have (a
moved sink); else `unproven` with the reason (no deterministic source, arm
unavailable/failed, coverage, patch refused/not applied). Evidence only:
manifest `verify_fix` block + `verify-fix` artifacts (`method: deterministic`,
bound to patch sha256 + base commit), summary "Patch verification" section
("requires human review"), `scan --json`, raw patched-copy output under
`<run>/verify-patch/raw/`, store event `deterministic_verify_fix` (L1:
`history_counts` ignores it; evidence-only records do not count as decisions
for `require_signatures: auto`). Never a disposition, never the gate, never a
panel vote; `--inplace` refused. Defect found and reproduced first: the fix
lane's `.patch` carried absolute scratch paths (unapplicable by `git apply`/
`patch -p1`); `extract_patch` now emits `-p1` paths. 19 tests in
`tests/test_verify_patch.py` + 4 in `test_patches.py` (559 total), ten paths
vacuity-checked by neutering. **Live-verified** on a seedrepo copy with docker
semgrep 1.173.0: hand-written parameterised-query patch → `fixed`; comment-only
patch → `not_fixed (matched by root_cause)`; tree untouched. Not built: verify
against an OLD run dir (the current scan is the pre-patch picture at the same
commit, which the moved-sink check needs), MCP exposure, a model explainer.

**Not functional in 0.1.0, labelled so in `--help`:** `--fix`. `--verify-fix` is
functional but depends on `--fix`; use `--verify-patch`. `--analyze` is functional
again (M-V3 reframe, below; live-verified 2026-08-27). `codex-security` dedicated arm needs
an interactive `codex-security login`. The four R11 fence defects are fixed and
live-verified even though the fix lane is disabled.


**M-V3 reframe — DONE 2026-08-26, LIVE-VERIFIED 2026-08-27.** `--analyze` no longer
refuses: the five jobs (threat-model, attack-path[dual], hardening, policy,
writeup[dual]) are now OUR prompts (`prompts/house-analysis-<job>.md` + a
shared preamble, R10-lesson wording: read-only by flag, not prose) driven
through the SAME `llm_cli.LLM_CLI_SPECS` builders/parsers the house scan
arms ran live in R10 — claude `--permission-mode plan --tools
Read,Grep,Glob,LS` (+ `--max-budget-usd` fuse, default 5), codex `-s
read-only` (prompt on stdin), agy `--mode plan --sandbox`; pick with
`--analyze-with claude|codex|agy` (default claude) or
`arms.options."analysis:<job>".cli`. Producer is `house:<cli>`, never a
vendor skill. Document envelope `sc-analysis-doc/1`
(`schemas/analysis_document.v1.json`, validated by
`artifacts.validate_document`; `inputs_read` must be repo-relative); D8
attestation, cost/`cost_stopped` (claude only — codex/agy report neither),
timeout, decline, invalid document and soft-deny are all failed arms →
`analysis_failed` informational degradation; findings.json / coverage / gate
provably untouched (tests are differential: same run with and without the
lane). Blue-scope post-check `redact_exploit_content` (shell fences on
dual-use jobs, payload markers everywhere; visible in place; documented as
best-effort). writeup/attack-path get `findings_digest` of the scan arms'
raw findings as context. 35 tests in `tests/test_artifacts.py` (558 total);
vacuity-checked: neutering the redaction fails 4, letting `_exit_code` see
analysis results fails the gate-unchanged test. **Live status: LIVE-VERIFIED 2026-08-27** — `scan <seedrepo copy> --arms semgrep --analyze threat-model --analyze-with claude --config {max_cost_usd: 2}`: 100 s, est. $0.72, model attested `claude-fable-5`, completion `complete`, 9 files read, 0 redactions, artifact indexed as a document (never a finding), gate unchanged (exit 1 from semgrep's two highs), no degradations. The model's own notes reported the README prompt-injection canary and stated it was ignored, and it verified the CWE-annotated comments against the code instead of trusting them. Reference run kept at `tests/fixtures/seedrepo/.security-council/runs/20260827_102732` (gitignored). The earlier attempt was killed at 141 s by the coordinator, not by the CLI — it would have finished. Not live-run: codex/agy families and the dual-use jobs (attack-path, writeup); the redaction post-check is exercised only by tests so far.

**Known residuals, documented:** decision store signing is provenance, not assurance (R13: only load-bearing behind
CODEOWNERS + required review; documented residuals in docs/signing.md); ADO/GitLab templates
unproven on real infrastructure; CKLB never opened in a live STIG Viewer.

## 7.10c Release state — 0.4.1 (RELEASED 2026-09-02)

**Released:** tag `v0.4.1` at `d3d9916`,
https://github.com/Intellimetrics/security-council/releases/tag/v0.4.1 (notes =
CHANGELOG 0.4.1 section). 785 tests, ruff clean.

**Why 0.4.1:** the Azure DevOps **Server** pipeline was live-verified end to end
on a real ADO Server 2022 (RHEL 9 agents, disconnected/US-Gov collection),
executed by a coordinated Claude session on the maintainer's work machine
against a synthetic-only throwaway repo (seedrepo as `fixture/`, package source
as `clean/`; repo purged after, no PAT). All 5 claims PASS — **this closes the
D4 first-class Server target** (it was never the Services proxy). See §7 item 6
for the full per-claim record and the Server deltas.

**The defect it fixes:** `post_pr_thread` built the PR-thread REST URL from the
raw `SYSTEM_TEAMPROJECT`; a project name with a space (the Server norm) raised
`http.client.InvalidURL` before sending — no thread AND the annotate step
crashed, breaking its "never fails the build" contract. Fix: prefer
`SYSTEM_TEAMPROJECTID` (GUID), percent-encode the fallback name, wrap the POST
so a failed post degrades to a `##vso` warning; +4 regression tests (the old
`"Sec"` fixture had no space so it could not catch it). Template header now
documents the RHEL 9 / HOME / semgrep-glibc / scanPath-relative-sourcepath /
Checkpoint.Authorization deltas.

**Wheel rehearsal (§7.10 method, 2026-09-02):** built `security_council-0.4.1`,
installed into a fresh venv OUTSIDE the checkout, exercised the surface. All
green: `--version` → 0.4.1; the changed `ci.azure_devops` module against a real
run dir with a spaced project + `--dry-run` produced a correctly percent-encoded
URL (`.../My%20Project/_apis/...`) at exit 0; the **real degrade path** (a
non-dry-run POST to an unreachable host) emitted a `##vso[task.logissue
type=warning]` and returned exit 0 — the exact contract that was broken;
`report --format md|html`, `doctor` all exit 0. No packaging or contract
regressions.

**Not a council round:** narrow, reproduced CI-plumbing defect fix with
regression tests + a live-infra verification — a defect fix, not a design
change (per the fix-directly / council-for-design split). No R-number.

**Residual (unchanged):** SARIF-tab render on a disconnected Server (a
third-party marketplace extension, not ours). Remaining Phase C: C1 GitLab, C3
CKLB → live STIG Viewer.

## 7.10b Release state — 0.4.0 (RELEASED 2026-09-01)

**Released:** tag `v0.4.0` at `5cd4728`,
https://github.com/Intellimetrics/security-council/releases/tag/v0.4.0 (notes =
CHANGELOG 0.4.0 section); **live-verify run 33518718528 GREEN** on that sha
(clean-pass + detects-and-gates). 782 tests, ruff clean.

**What 0.4.0 ships (the R19 roadmap, Phases 1 + A5 + B0/B1/B2 + A2/A3):** A1
baseline max-age; A4 pre-run validation preview; A5 content-refused panel-seat
label; B0/B1 the live vendor fix lane behind the relaxed bwrap fence (neutral
runtime bind, writable ephemeral vendor home with credential copy, DNS wired,
double opt-in consent) — live-verified with codex AND claude producing correct
SQLi fixes; B2 the house-fix-prompt reframe (no vendor plugin); A2
`--verify-patch --against RUN_DIR` + A3 `sc_verify_patch` MCP; the B1-residual
signal-safe scratch cleanup; llm-council 0.25 tuning (okf_context on).

**The build used a subagent fan-out** (two opus worktree agents, disjoint files):
Lane 1 = A2/A3, Lane 2 = B2/residual; both merged after diff review. **Council
R20/R20b gated the release across three rounds** (transcripts
`.llm-council/runs/20260901_095305_*` and `_100531_*`): R20 was 3/3 quorum with
codex NO carrying FIVE real defects the two YES votes missed — a data-loss bug
(certify deleted a real `.sc-canary`), a vacuous-canary shell-quoting bug, a
signal-handler deadlock, a latched-install bug, and a consent defense-in-depth
gap — all fixed + vacuity-checked (`6d25eba`); R20b confirmed the five closed
and raised one credential-cleanup nit, closed same-turn (`58902ae`). **Lesson
(re-affirmed): weight the SUBSTANTIVE peer — a YES quorum that missed a
data-loss bug is not a ship; re-gate after must-fixes with the same reviewers.**

**Rehearsal (§7.10 method, from the 0.4.0 wheel):** doctor, setup --yes, default
docker scan (17 clusters exit 1), runs, all 11 report formats + `--bundle all`,
MCP stdio handshake (12 tools incl. `sc_verify_patch`), the fix double-opt-in
refusals (exit 2/4/2), baseline max-age (fresh 0 / backdated-400d stale 1),
`--verify-patch --against` (fixed with control-run evidence; dirty→unproven),
current-tree verify-patch (comment→not_fixed), validation preview line, serve
matrix (200/404/421/501). Every leg passed; no defect found. Gotchas: `baseline
set` takes no `--config` (put `require_signatures: warn` in the repo config or
sign it); `report --format` has no `sarif` (it's a scan artifact); the MCP
entry point must be called by venv path, not bare name.

## 7.10a Release state — 0.3.0 (RELEASED 2026-08-31)

**Released:** tag `v0.3.0` at `02bbef0`,
https://github.com/Intellimetrics/security-council/releases/tag/v0.3.0 (notes =
CHANGELOG 0.3.0 section); live-verify run 33407382496 green on that sha
(clean-pass + detects-and-gates). Post-release commit `3417d1b` closed R18's
parting nit (failed `git status` now reads unknown/refused, never clean).

**The rehearsal (same §7.10 method, from the 0.3.0 wheel, ~25 min):** every
0.2.0 leg re-passed first time — doctor, `setup --yes`, default-arm docker
scan, runs, all report formats + `--bundle all`, `--system-name`, serve matrix
(traversal 404 / POST 501 / bad Host 421 / zip 200), MCP stdio handshake
(`sc_consolidate` present, `sc_doctor` 8/8), ADO+GitLab halves, `--sbom`,
signed decisions lane, copied-vuln `--gate-baseline new` → 1, `--verify-patch`
(real → fixed, comment → not_fixed), `--validate` with backend (3/3 seats,
quorum, `validated` earned) and without (visible `validator_unavailable`).
New legs: `consolidate` happy/dirty/zero-source. **One defect found:** a
default-layout scan's own artifacts under `.security-council/` made the target
"dirty", so `consolidate` refused the very runs the scanner had just produced
— the tool's state dir is now excluded from the dirty predicate (source
changes, untracked files, and `.security-council.yaml` still fail closed).
Bonus controls observed working: untrusted signing key refused; a verify-patch
whose diff touched the decision store refused by the validator; a signed
suppression (root-cause-scoped, by design) outranking the baseline for a
copied file while the baseline still marked it `new_location`.

**Release-gate rounds (R18, continuation thread):** round 1 split — codex
SHIP; claude NO on an INFERRED git-quoting bypass with a stated flip
condition; agy failed (its own headless `command` permission, clear stderr —
the llm-council 0.23.0 diagnostics worked). The inference was tested live
(`git status --porcelain` C-quotes `" .security-council/"` and
`".security-council /"` → no bypass), the code hardened anyway (verbatim
porcelain path, explicit unquoting, unparseable ⇒ dirty), impersonation +
subdir-residual pinned by tests. Round 2: **3/3 SHIP**, risk low.

Rehearsal gotchas for next time: `${PIPESTATUS[0]}` (bit me AGAIN, twice);
`runs` takes no path; `decisions trust` is `--principal/--key`; generate
verify-patch diffs with `git diff -- <file>` or the patch sweeps the decision
store and is (correctly) refused; the seedrepo fixture's .gitignore does not
ignore `.security-council/`, and a fixture copied from the checkout carries
local gitignored run dirs.

## 7.10 Release state — 0.2.0 (RELEASED 2026-08-28)

**The confidence bar for "a cut that actually works" is now a rehearsal, not the
test suite.** Method (repeat it for every release; ~15 min, $0 except one
optional `--validate`): `uv build` → `uv venv` + install the WHEEL with `[mcp]`
(no `-e`, no dev extras) → copy `tests/fixtures/seedrepo` to a directory OUTSIDE
the checkout (the venv resolves `security_council` from the cwd otherwise) and
`git init` it → run as a user: `doctor`, `setup --yes`, `scan .` (default arms,
docker), `runs`, `report` in all 12 formats + `--bundle all`, `serve` (curl
index / `/runs/latest` / run page / zip / traversal / bad Host / POST), the MCP
stdio handshake (`initialize`, `tools/list`, `sc_doctor`), `ci.azure_devops
--dry-run`, `ci.gitlab --write-reports --dry-run`, `--sbom`, `decisions
init|trust|verify` + signed `suppress`/`baseline set`/`outcome mark` + rescan,
`--verify-patch` (a real fix → `fixed`, a comment-only patch → `not_fixed`),
`--gate-baseline new` (nothing new → 0; a COPIED vulnerable file → must be 1),
`--validate --validate-max 1` with llm-council on PATH (51 s, TP 0.75, 3/3
citations) AND with it stripped from PATH. Measure exit codes with
`${PIPESTATUS[0]}`, never `$?` after a pipe (bit me three times).

Found by the 2026-08-27 rehearsal, both reproduced live before fixing and
again after: (1) **copy-pasted baselined vuln passed `gate_baseline: new`**
(path-free root-cause fingerprint → same cluster → `unchanged`) — baseline
entries now carry `uris` inside the signed digest, out-of-baseline files ⇒
`new`; 0.1.x baselines ⇒ `baseline_legacy_entries` degradation until re-set;
tamper on `uris` ⇒ `baseline_refused`. (2) **`--validate` with no backend was
silent** (needs_human but "1 cross-examined", no degradation) — now
`validator_unavailable`/`validator_failed` + summary flag + `doctor` row.
Papercuts: cheat sheet's checkout-only paths and hard-coded `@v0.1.0`;
`summary.html` missing from the scan footer. Everything else passed from the
wheel first time. Six regression tests, vacuity-checked. 623 tests.

**R15 council on the two fixes (2026-08-27, quick; claude YES/risk low, codex
timeout, antigravity empty — plan for one usable peer; transcript
`.llm-council/runs/20260827_195752_*`):** control 1 sound (digest catches strip
AND add of `uris`; signature over the recomputed digest), control 2 fail-safe
downstream. Two follow-ups, both reproduced live then closed the same day: a
committed file literally named `app\reports.py` aliased onto `app/reports.py`
(`to_repo_relative` rewrote `\` unconditionally → copy's findings folded into
the original's location, invisible AND `unchanged`) — backslash translation is
now Windows-host/Windows-shaped only (`normalize/paths.normalize_separators`,
shared with `fingerprint._norm_path`); I1 then refuses the uri, so the
findings are DROPPED and counted → `partial_coverage` → exit 3, with the
degradation naming `invalid:I1` (scanner arms now carry the normalizer's skip
breakdown in `coverage.skipped`). I1 was deliberately NOT weakened; and an all-absent panel (llm-council
ran, every peer failed) still counted as cross-examined — `Validation.convened()`
is the single predicate for both the degradation and the summary. Info items
taken: legacy nag only under `gate_baseline: new`; rename-gates-as-new in the
upgrade note.

**R15b (2026-08-28, continuation w/ `independent_review`, FULL QUORUM 2/3: claude NO,
codex NO in 176 s, antigravity empty):** the llm-council session fixed the peer problems
(codex timeouts = inherited `~/.codex` `reasoning_effort=ultra`, 773 s vs 151 s on the
same prompt; stopgap `-c model_reasoning_effort=medium` in `.llm-council.yaml`; upstream
v0.23.0 injects it). Both peers independently found the R15 fixes incomplete one hop out:
codex-security/claude-security adapters still folded `\`→`/` (alias survived those arms);
unmatched absolute/Windows-shaped paths were made relative (`/etc/passwd`→`etc/passwd`,
`C:\src\app.py`→`C:/src/app.py`) — now stay absolute, I1 refuses (+ drive prefix);
HTML "validated" tile counted unconvened panels; `patches._rel` shares the separator
rule; doctor row tested. Lesson: a fix at "the boundary" is only a fix if nothing
upstream pre-normalizes — grep every producer adapter for the same transformation.

**R15c (closure; 3/3 labeled — first full panel ever here — claude YES, antigravity YES,
codex NO):** all R15b items confirmed closed by all three. Codex's two new items, both
fixed + pinned the same hour: claude-security `scan_prefix` strip by bare `startswith`
(`/src` + `/srcfoo/x.py` → `foo/x.py`; now segment-boundary only) and `file:///C:/…` /
UNC file-URIs under a configured root refused instead of matched (false refusal, fail-safe
direction). Council-ready for the tag.

**RELEASED 2026-08-28: `v0.2.0` tagged at `3392c7f`, published at
<https://github.com/Intellimetrics/security-council/releases/tag/v0.2.0> (notes = the
CHANGELOG 0.2.0 section). `live-verify` run 33160501908 on real GitHub runners at that
sha: clean-pass + detects-and-gates both green. At tagging: 629 tests (+1 skip), ruff
clean, wheel rehearsed in a fresh venv (§ method above). Next release is 0.2.1/0.3.0 —
bump pyproject + `__init__` + CHANGELOG first; never move a tag that has a release.

Release steps as run (for next time): `git push`, `git tag
v0.2.0` + push, `gh release create v0.2.0` with the CHANGELOG section, then
`gh workflow run live-verify` (runs against `@main`) and confirm both jobs
green. `git ls-remote --tags origin` first — a stale tag bit 0.1.0.

## 8. Roadmap after 0.3.0 (R19-reviewed 2026-09-01)

**R19 council** (quick; claude tradeoff/risk-low, codex NO/risk-high, antigravity failed
again on its known headless `command` permission; transcript
`.llm-council/runs/20260901_050203_*`). Both peers accepted the four-lane structure;
codex's NO was two draft errors, both VERIFIED in code before revising: the fix-job
mapping was reversed (see §7.7a), and "Phase B = spend $5–15 to live-verify the fix lane"
is impossible as written — `available()` refuses up front (fence cannot run any vendor
CLI). Claude's key reorder: real vendor patch *shape* is an input contract for the
verify-chain work (VP-1 refuses traditional `---/+++` patches; only a live run shows what
vendors emit), so the cheap vendor smoke comes before A2/A3.

**Locked order:** A1(+A4) → B0 design round → B1 claude smoke → A2/A3 → B2 codex leg →
0.4.0 checkpoint → C when provisioned (provisioning requested NOW, runs when ready) →
D behind its own design round (R20). Release checkpoint is **0.4.0**, not 0.3.1 —
A1's default is behavior-changing (both peers agreed).

### 8.1 Phase 1 — A1 baseline max-age + A4 validation preview ($0)

- **A1 — DONE 2026-09-01** (`baseline_age_status` in decisions.py, orchestrator age
  lane after the signature/integrity refusals, `manifest.baseline_ignored`, summary
  provenance lines; 20 tests in `tests/test_baseline_max_age.py`, stale-refusal
  vacuity-checked by neutering — 3 fail; 703 total). Live-smoked through the CLI
  with docker semgrep on a staged seedrepo copy: no-baseline 1 → fresh 0 →
  backdated-400d 1 with `baseline_stale` + NOT-honoured provenance → 350d 0 with
  `baseline_stale_soon` → 400d+`off` 0 with the disabled stamp. Two build notes:
  `0 == False` in Python, so the off-check must use identity or
  `baseline_max_age_days: 0` silently disables the bound (test pins it); and the
  smoke's "exit 1" from system python3 outside the checkout was a
  ModuleNotFoundError, not a gate — use `.venv/bin/python` for staged-copy smokes.
  Spec as built:
  `decisions.baseline_max_age_days`: **default 365**, `ci`/`gov` profiles 180,
  explicit `off` allowed but stamped loudly in manifest + summary. A
  `baseline_stale_soon` informational degradation opens 30 days before expiry (answers
  the pipelines-go-red-overnight objection to default-on). Stale ⇒ `baseline_stale`
  degradation AND the baseline is not honoured (everything gates as new — fail-closed;
  exit flips 0→1 only, NEVER 0→3: pin with a test). Age from the SIGNED event timestamp
  when the signature verifies; unsigned baseline under `warn`/`off` falls back to record
  `set_at` with a visible caveat and the same stale handling. `set_at` materially in the
  future ⇒ `baseline_refused` (today's `max(0, …)` at `orchestrator.py:653` silently
  clamps it to age 0 — codex). Preserve provenance (age, signer, digest) in the manifest
  even when the baseline is ignored. `at` compared as datetimes (R13 lesson). Boundary
  tests: exactly 365d, +1s, future, malformed, each signature status, gate all/new.
  _Divergence recorded: codex preferred profile-only (default off); default-on chosen per
  the R13 precedent — the lenient default is the one attackers get._
- **A4 — DONE 2026-09-01** (`panel.validation_preview` — pure, reads the same
  `select_for_validation` as the loop and the manifest; `run_scan(...,
  on_validation_preview=)` callback fired before any panel convenes, wired by both
  CLI call sites to one stderr line; `manifest.validation.budget_ceiling_usd`;
  ceiling on the summary's coverage line; 8 tests in
  `tests/test_validation_preview.py`, incl. an order test proving preview-before-
  panel against a convening fake runner). The "cost" is the honest one we HAVE:
  `selected × --validate-budget` — the per-finding `--max-cost-usd` fuse ceiling,
  labeled "an upper bound, not a spend prediction" (native CLI peers bill ~$0).
  Live-verified on the staged smoke repo with real llm-council: preview line
  `1 of 2 eligible … ceiling $0.50` on stderr, 1 panel convened, summary line
  carries the ceiling. Build note: same-file same-family fake findings cluster
  into ONE via the CWE-gated overlap tier — fixture findings need distinct
  families or the counts under test collapse.
- **A5 — DONE 2026-09-01** (`council_client.PeerResult.error_kind` parsed from
  `llm-council run --json`; `panel._peer_failure_text` maps
  `error_kind: content_refused` to "declined on content policy — rephrase the
  panel question as verification, not exploitation", used for BOTH the absent
  seat's rationale and the run-level `validator_*` degradation; 4 tests in
  `tests/test_validate.py`, neutering the helper fails 3). A crashed/timed-out
  seat keeps its plain reason — the label is refusal-only. Fail-safe verdict
  unchanged (`needs_human`). 715 tests.

### 8.2 Phase B — fix-lane design round, then the cheapest live smoke

- **B0 — DECIDED 2026-09-01 (council 2/2 YES on option (b); transcript
  `.llm-council/runs/20260901_055957_*`, continuation of R19; antigravity failed
  again on its headless `command` permission).** Live vendor patch generation is
  enabled by RELAXING THE FENCE, not abandoning it: orchestrator-owned bwrap
  keeps kernel write-denial + real-home invisibility; network becomes a declared,
  certified, stamped posture. Binding conditions, all adopted:
  1. **Vendor runtime ro-bound at NEUTRAL paths** (`/opt/security-council/vendor/…`),
     never at real `~/.local/bin`/`~/.nvm` — in-place binding makes the real HOME
     exist in the namespace, which the canary's `HOME_VISIBLE` probe rightly calls
     a breach (my draft (b) was self-contradictory here; caught by claude-peer,
     echoed by codex). Record runtime versions/hashes in the manifest.
  2. **claude loses `--dangerously-skip-permissions`** (its own help scopes it to
     no-internet sandboxes — exactly what (b) removes). v1 policy is codex-peer's
     stricter shape: EDIT-ONLY allowlist (Read/Glob/Grep/Edit/Write), no Bash, no
     WebFetch/WebSearch, no MCP/subagents/hooks; tests come later from the
     deterministic verify lane. If claude cannot produce a patch under that
     policy, park CLAUDE specifically, don't weaken the lane. (Divergence noted:
     claude-peer would allow Bash minus fetch tools; the stricter roster won.)
  3. **codex keeps `--sandbox workspace-write` INSIDE the fence** (defense in
     depth) and is the preferred first live leg — after verifying Landlock nests
     inside bwrap here and project commands stay net-denied while model
     transport works.
  4. **Auth: dedicated spend-capped API key via the env allowlist, preferred;**
     else copy ONLY the exact credential file into the ephemeral vendor HOME
     (`CLAUDE_CONFIG_DIR`/`CODEX_HOME` — MV4-11 finally wired). NEVER ro-bind the
     real auth dirs (HOME-visibility conflict; `~/.claude` carries other
     projects' history + hooks the CLI executes). Never copy: OAuth refresh
     tokens, hooks/plugins/MCP config, history/memories/caches, any non-vendor
     credential. Host note for B1: the claude job invokes the claude-security
     PLUGIN command, and plugins are on the never-copy roster — so the claude
     fix job likely reframes onto a HOUSE fix prompt (M-V3 precedent).
  5. **Consent is double opt-in and repo-unforgeable:** `--fix` alone no longer
     suffices — an explicit CLI acknowledgement flag is required (repo config can
     NEVER supply it; R17 parameter-over-config lesson), refusal names what's
     missing. `gov` refuses the lane unconditionally, as policy like Red.
  6. **Posture stamping is structured, never boolean** — `cov["fenced"] = True`
     is R12's boolean-coverage failure recurring. Stamp execution_boundary /
     network_access / egress_destination_control / operator_acknowledged /
     real_home_visible / vendor_home / code_disclosed_to / vendor_sandbox /
     project_command_network / cert hash + runtime hashes. Do NOT overload
     `safeguard_posture` (model tiers, not host isolation). The canary records
     the NET probe as `waived_by_posture` — today it's silently uncounted, which
     reads as "passed". Summary carries one plain-language residual sentence
     (open egress = scratch copy + delivered credential could leave).
  7. **The first control to ADD is destination-constrained egress** (host-side
     proxy allowlisting the vendor's API endpoints; blocks loopback/RFC1918/
     metadata; DNS-rebinding-resistant) — both peers named it independently. Too
     heavy for the first probe, so it is the GRADUATION CRITERION named in the
     manifest before the lane runs on private code. Interim release conditions:
     spend-capped API keys only (no refresh tokens), first live runs on
     public/synthetic repos only. Residual even WITH the allowlist: exfil via
     attacker-supplied key to the same vendor endpoint (Files-API class).
  8. `tests_ran` is set only by orchestrator-observed execution, never vendor prose.
  $0 checks before any spend (from both peers): in-place bind ⇒ expect
  HOME_VISIBLE breach; relocated runtime launches both CLIs; codex Landlock
  nesting inside bwrap; claude honors `CLAUDE_CONFIG_DIR` with minimal
  credential (or `ANTHROPIC_API_KEY` alone); auth refresh writes only ephemeral
  files; real vendor dirs byte-identical before/after (snapshot assert); hostile
  hooks/MCP/nested-agent fixture cannot execute; vendor ToS permit lane-scoped
  key use (operator to confirm).
- **B1 — DONE + LIVE-VERIFIED 2026-09-01 (commits 6b177cd fence, 2e024c8 arm,
  c86cdae consent, f50997b live-leg fixes). The codex leg ran end to end.**
  735 tests. NOTE: spend is NOT a gate for this project — it runs on internal
  enterprise CLIs with their own sign-in, not metered APIs (memory
  `security-council-deployment-context`); auth = the credential-file copy
  (`oauth-file-copy`), not a metered key. Pieces:
  - **B1a fence** (`fence.py`): `runtime_binds` (ro, neutral vendor runtime) +
    `writable_binds` (rw, ephemeral vendor home) threaded through
    bwrap_argv/certify/verify/config_hash; both part of the hashed shape (host
    paths ephemeral, sandbox paths certified). `resolve_runtime` maps a command
    to its plan — self-contained ELF (claude) binds one file; node script
    (codex) binds the whole node root. Canary records open network as
    `network: open:waived_by_posture`.
  - **B1b arm** (`arms/fix.py`): `FixArm(allow_network, egress_acknowledged)`.
    Relaxed lane resolves the runtime to a neutral bind, opens network, delivers
    auth as an API key via the env allowlist OR a COPY of the single credential
    file into a writable ephemeral vendor HOME at neutral `CODEX_HOME`/
    `CLAUDE_CONFIG_DIR` (never the real dir). codex keeps `--sandbox
    workspace-write`; claude drops `--dangerously-skip-permissions` for an
    edit-only roster. `cov["fenced"]=True` replaced by the structured `posture`
    stamp (also on the patch artifact). Strict lane unchanged.
  - **B1c consent** (`config.py`/`cli.py`/`orchestrator.py`): double opt-in —
    `fix.allow_network` (config) AND `--allow-unrestricted-fix-egress` (CLI);
    repo-sourced `allow_network` refused; `gov` refuses (exit 4). MCP does not
    expose the lane (CLI-only consent, per council).
  - **$0 checks passed:** in-place bind ⇒ HOME_VISIBLE breach, neutral ⇒ absent
    (pinned by live test); both real runtimes launch relocated; relaxed codex
    fence certifies with the writable vendor home (credential readable, home
    absent, write lands in the copy not `~/.codex`); claude honors a neutral
    `CLAUDE_CONFIG_DIR`; cert-hash bug found+fixed (certify must strip the
    writable host path like config_hash_for).
  - **LIVE LEG RESULT (2026-09-01, seedrepo copy, one SQLi finding):** codex ran
    end to end inside the relaxed fence and produced a CORRECT minimal fix
    (f-string SQL → parameterized query) as a `.patch` never applied; the
    deterministic `--verify-patch` lane then confirmed it `fixed` (absent from a
    verified re-scan). Confirmed live: codex's Landlock `workspace-write` NESTS
    inside bwrap; the credential copy authenticates; codex writes all its state
    (memories/history/logs/goals sqlite) into the EPHEMERAL vendor home — real
    `~/.codex` untouched (no leak-back). The run surfaced FOUR contract defects,
    all fixed in f50997b: (1) DNS dead — `/etc/resolv.conf` symlinks into `/run`
    which the fence didn't bind → agent hung reconnecting; relaxed fence now
    binds the dereferenced resolver + a `DNS_OK` canary control; (2) `codex exec`
    blocks reading stdin even with a prompt arg → `proc.run_command(stdin=)`,
    fenced run passes DEVNULL; (3) the vendor skill trigger isn't reachable in
    exec mode (R10 again) → plain instruction naming file + CWE; (4) codex under
    workspace-write left `__pycache__/*.pyc` → binary hunk refused; extract_patch
    now shares the workspace junk-excludes. To re-run:
    `printf 'fix:\n  allow_network: true\n' > op.yaml` then
    `scan <synthetic repo> --arms semgrep --fix <id> --fix-job fix-finding
    --allow-unrestricted-fix-egress --config op.yaml` (each fix ~4 min on this
    host's default reasoning; runs on synthetic repos only — open egress).
  - **Residuals for later:** a SIGKILL (timeout/interrupt) bypasses the arm's
    `finally: rmtree`, leaving a scratch dir with the credential COPY in /tmp
    (0600) — add signal-cleanup. Auth-refresh-writes-only-ephemeral and the
    hostile-hooks/nested-agent-fixture inertness were not exercised (the fix
    completed before a refresh; no hostile fixture staged) — cover in B2/a
    hardening pass. The destination-egress proxy (graduation criterion) is still
    unbuilt — required before private-code runs.
  - **B1-residual DONE (B2 lane, commit 9c3ad9d + R20 6d25eba):** SIGTERM/SIGINT
    + atexit scratch cleanup (handler-chained, main-thread-guarded, non-blocking
    lock after R20-SIGNAL-01), credential scrubbed the instant the vendor returns
    AND the copy is inside the try/finally (R20b nit). SIGKILL stays uncatchable
    (documented). Still open: auth-refresh ephemerality + hostile-hooks fixture
    not exercised; destination-egress proxy (graduation criterion) unbuilt.
- **B2 — DONE + LIVE-VERIFIED 2026-09-01 (commit 9c3ad9d).** The claude fix job
  (`suggest-patches`) is reframed off the `/claude-security suggest-patches`
  plugin onto `prompts/house-fix.md`, shared by both legs (M-V3 precedent);
  `FIX_JOBS` maps job→(family, prompt file), `available()` fails closed on a
  missing prompt. Live: claude produced a correct minimal SQLi fix (verify-fix
  `fixed`); codex re-verified on the same shared prompt (`fixed`). The claude
  leg runs edit-only (no `--dangerously-skip-permissions`). Was a subagent lane
  (Lane 2 of the R19 release fan-out).

### 8.3 Phase 1b — A2 `--verify-patch --against RUN_DIR` + A3 MCP exposure ($0, after B1)

**A2/A3 — DONE 2026-09-01 (commits 00f0b57 A2, b2ba8a7 A3; subagent Lane 1 of
the R19 fan-out).** `--verify-patch --against RUN_DIR` judges a patch against an
old run via a control (unpatched) + patched re-scan at the CURRENT scanner
version; `fixed` needs the old run's verified coverage + control reproduction +
verified patched absence; every precondition fails closed to graded
`unproven (<reason>)`; evidence binds against-run id/commit/manifest sha256 +
both sides' scanner versions/coverage; `fixed` is evidence-only. MCP
`sc_verify_patch` (against-mode only, absolute+in-root path). Design decisions
council-blessed (R20 Q1–Q3): the moved-sink baseline is the CONTROL population
(same scanner version), the old run supplies selection/coverage/identity;
MCP is against-only; store evidence recorded only on a real verification. The
`--against`-mode dirty predicate reuses `workspace.git_info` (the consolidate
path). Original spec preserved below for reference.

- **A2** preconditions, all fail-closed: run base commit == HEAD (sha equality; shallow
  clones are a non-issue, rebases invalidate — the principled LATER relaxation is
  `HEAD^{tree}` equality); clean target tree (reuse the R18-hardened dirty predicate with
  the state-dir exemption); `scan_scope` full; vouching arms' coverage `verified`; refuse
  run dirs containing git-tracked files (the committable-run-dir class, checked on the
  symlink-RESOLVED path). Precondition failures are graded `unproven (base_mismatch/…)`
  verdicts, never usage errors. **Control run (codex, load-bearing):** re-run each
  vouching scanner on the UNPATCHED current tree too; if the original finding does not
  reproduce in the control ⇒ `unproven (control_not_reproduced)` — otherwise
  scanner/ruleset drift masquerades as `fixed`. Evidence binds: against-run id + commit +
  `manifest.json` sha256 (run dirs are unsigned — this is the same trust class as the
  pre-R9 store; full run-signing stays out of scope), patch digest, scanner
  versions/rulesets both sides, both coverage verdicts. Refuse internally inconsistent
  manifests. `fixed` stays evidence-only — never disposition, never gate.
- **A3** MCP `sc_verify_patch`: patch path absolute + in-root (sc_consolidate's import
  rule); keep the rehearsal's validator-refuses-store-touching-patch test on the MCP path.

### 8.4 Phase C — real-infrastructure verification (blocks on operator; request now)

- **C1 GitLab** (free-tier project + PROJECT access token — `CI_JOB_TOKEN` can't post
  notes): shipped template verbatim; verify `artifacts:reports` accepted, MR Code-Quality
  widget (Free-tier — 2-min doc check first), MR note, gate re-raise. SAST dashboard
  needs Ultimate ⇒ residual, not defect.
- ~~**C2 Azure DevOps Services** as a PROXY for D4's first-class ADO Server target~~ —
  **SUPERSEDED / DONE better: live-verified on a real ADO Server 2022, 2026-09-02.**
  A Server instance materialised (real US-Gov, disconnected, RHEL 9 agents), so the
  first-class D4 target itself is closed — the Services proxy is moot. 5/5 claims PASS
  (logissue escaping, uploadsummary, CodeAnalysisLogs, PR-thread REST api-version=6.0,
  gate re-raise 0/1/3). Found+fixed a real URL-encoding defect (project-name spaces) and
  documented the Server deltas in the template header. Only residual: SARIF-tab render on
  a disconnected Server (third-party extension). See §7 item 6.
- **C3 CKLB** into a real STIG Viewer 3 (DISA public download, $0).
- Hygiene for all: disposable projects, least-privilege tokens, synthetic code only,
  revoke credentials after.

### 8.5 Phase D — calibration corpora (design round R20 first; charter pinned NOW)

R20 must resolve, not re-discover: Juliet-Java does NOT satisfy §7.4's non-Java gap
(the C/C++ suite would, but then arm/ruleset coverage for C is a question); Juliet is
MORE templated than BenchmarkJava (near-twin train/test leakage gets worse) and its
prevalence is equally unrealistic; the negative corpus attacks the prevalence caveat;
panel-term fitting needs an outcome-dataset sampling/export story (privacy-reviewed,
avoiding one repository's heavily-selected disputed cases) BEFORE the fit. Default
stays `prior`; "calibrated" stays banned.

### 8.6 Release checkpoint — 0.4.0

After Phases 1 + B0/B1 (and A2/A3 if landed): bump pyproject + `__init__` + CHANGELOG,
wheel rehearsal per §7.10 method, `git ls-remote --tags origin` first.

### 8.7 Parked — BY NAME (silent parking is how items get lost)

§7.1 SCA/dep-reachability validator (oldest honest-list item, R2) · §7.2 redacted-secret
validation bluntness · entitlement deep-rung live verification (needs real entitled
creds; declare permanently residual if never intended) · decisions export/import bundle
(`--accept-foreign`) · serve TLS/token rotation · Red tier (D5) · vendor verify-fix arm
(superseded by the deterministic lane).

### 8.8 Completed pre-0.3.0 roadmap (historical)

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
     analysis arms kept out of coverage/gate (failure = informational degradation). ~~Runner drives
     the verified `$skill` Codex trigger~~ — R10 proved those skills unreachable; **reframed
     2026-08-26 onto house prompts** (see §7.9), same trust-boundary design.
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
     (degrades to no_patch/unproven). **Superseded 2026-08-26:** R11 Q4 replaced the vendor
     verifier with the deterministic lane (`verify_patch.py`, §7.9); the vendor arm is unwired.
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
