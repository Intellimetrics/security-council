# Changelog

## Unreleased

### Added — signed decisions (R9 signing lane)

- Suppressions, accepted-risk decisions, outcome marks and baselines can be
  signed with the operator's SSH key (`ssh-keygen -Y`, OpenSSH ≥ 8.2; no new
  dependency) and are verified on every scan against a committed
  `allowed_signers` roster. `security-council decisions init|trust|verify`;
  `--signing-key` (or `$SECURITY_COUNCIL_SIGNING_KEY` / `decisions.signing_key`)
  on `suppress`, `outcome mark`, `baseline set`; MCP `signing_key` argument and
  `sc_decisions_verify` tool. `doctor` reports the verifier.
- `decisions.require_signatures: auto|enforce|warn|off`. Under `enforce` an
  unsigned, tampered, untrusted, foreign (copied from another repo) or
  unverifiable decision is **not applied** — the finding reappears and gates;
  when a signature verifies, the signed expiry/lifecycle/context hash are what
  get applied. **Default `enforce`** (R13: `auto`'s "pre-existing store" is
  a fact about attacker-writable files, so it is an opt-in adoption mode:
  enforce for new or initialised stores, warn — loudly — for a store with
  unsigned decisions and no `store.json`, until 2027-01-01).
- Manifest `signature_policy` (configured, effective, reason, verifier, store
  id, trusted principals), a `signature` on every `prior_decisions` row and on
  `baseline_delta`, `history_audit`; the summary shows the level that ran, a
  Signature column on reapplied suppressions, and a "refused" table.
- New page `docs/signing.md`; updates to triage, safety-model, FAQ, concepts,
  CI guides, MCP and config reference.
- `scan --require-signatures off|warn|enforce|auto` (MCP `require_signatures`);
  the GitHub Action (`require-signatures` input), GitLab
  (`SECURITY_COUNCIL_REQUIRE_SIGNATURES`) and Azure DevOps (`requireSignatures`)
  templates pass `enforce` — `--ignore-repo-config` alone resolves to `auto`,
  which is `warn` for a committed pre-existing store.
- A signed event is bound to its record: a real signed event pasted into
  another root cause's record is `invalid`, and the LATEST human event is
  the one verified (not whichever the mutable block points at).
- `require_signatures: off` written bare in YAML (which YAML reads as `False`)
  is accepted as `off`.
- One signed outcome mark pasted N times counts once (dedupe on signature
  bytes); `trust` refuses pattern principals (`*`, `?`, `!`, `,`) and
  a roster containing a pattern principal or `cert-authority` line
  refuses every verification until it is removed (`decisions verify` names
  the line; a missing `namespaces=` only warns); a run that replays unsigned machine
  suppressions under `enforce` reports `machine_decisions_replayed`; the
  baseline's age is printed with its provenance.
- History-term hardening (R13 round 2): a forged clone carrying a real mark's
  signature can no longer shadow the real mark (dedupe happens after
  verification, on signature + signed payload); a record file not named by
  its root cause is ignored (a rogue file could override a root cause's
  history); the governing decision is the verifying event with the latest
  *signed* timestamp, not the last one in the array; `decisions verify`
  applies the same checks as the scan; refused marks and a poisoned roster
  are scan degradations.
- Round 3: outcome-mark dedupe keys on the signed payload, not the armored
  signature text (ssh-keygen accepts whitespace variants of one armor, so a
  real mark stored twice with/without its trailing newline counted twice);
  a record with any human decision event takes the human (verified) path
  even if its block's `decided_by.kind` was edited to `auto`; signed times
  compared as datetimes with a shorter-expiry tiebreak; `cert-authority` is
  matched as a roster option, not a substring of the comment.
- Round 4: the roster option field is parsed the way OpenSSH parses it —
  quote-aware (`namespaces="a,b c"`) and case-insensitive — so a
  `CERT-AUTHORITY` or a CA option hidden behind a quoted space is refused.
- Round 5: the roster is read as OpenSSH reads it — records split on `\n`
  only (`\r` is in-line whitespace) and `\"` honoured inside quoted values —
  so a CA option cannot hide behind either.
- Round 6 (council YES): only `\"` is treated as an escape inside a quoted
  roster value, exactly as OpenSSH does.

### Added — one-page HTML report on every scan

- `summary.html` is written next to `summary.md` on every scan: gate banner,
  what-to-do-next, tiles (severity, gating, corroboration, arms, degradations,
  decision signatures), a red degradations box, a "Where to look" block
  linking every file the run produced (SARIF, findings, raw per-arm bundles,
  analysis documents, patch verification), a section nav, then the full
  report. The body is rendered FROM `summary.md` by a strict renderer for our
  own dialect (`export/mdrender.py`), so the page cannot lag the markdown;
  the hardening is unchanged (one escaping boundary, zero script, zero
  external assets, print = PDF). Light and dark.
- `security-council runs` lists a target's runs newest-first; `report` with
  no run directory means the latest; `report --open` and `scan --open` render
  and open the page; `runs/latest` symlink points at the newest run. MCP
  `sc_report` accepts `format: html`.

### Added — deterministic verify-fix

- `scan <path> --verify-patch FILE [--for IDS]` verifies a patch the way the
  R11 council settled on: the orchestrator applies it to a scratch copy
  (never your tree), re-runs the deterministic scanners that reported each
  finding (semgrep / gitleaks / osv-scanner), and requires the finding to
  disappear — matched by the same fingerprint tiers as the baseline delta.
  `fixed` only when every vouching scanner completed a *verified* scan of the
  patched copy and no longer reports it; `not_fixed` when one still does or
  the same rule fires at a new place in the same file (a moved sink is not a
  fix); `unproven` when nothing can vouch (agent-only finding, scanner
  unavailable or failed, coverage `partial`/`none`, patch refused or not
  applied). No model, no network, no cost. Without `--for`, every open
  finding in the files the patch touches is checked.
- `--fix … --verify-fix` takes the same deterministic path; the vendor
  verify arm is no longer on any path (kept only as a possible future
  explainer). `--help` says what is functional.
- Results are machine evidence, never a decision: a `verify_fix` block and
  one `verify-fix` artifact per finding in the manifest (`method:
  deterministic`, `decided_by: machine`, `non_closing: true`, bound to
  patch sha256 + base commit), a *Patch verification* section in
  `summary.md` that renders provenance and says "requires human review",
  the verdicts in `scan --json` and the terminal summary, the scanners' raw
  output from the patched copy under `<run>/verify-patch/raw/`, and a
  `deterministic_verify_fix` event in the decision store that the score
  history term ignores and that never counts as a decision for
  `require_signatures: auto`.
- Fixed on the way (reproduced first): the fix lane's `.patch` artifact
  carried the absolute scratch paths of the `git diff --no-index` snapshot,
  so neither `git apply` nor `patch -p1` could apply it. `extract_patch` now
  emits an ordinary `-p1` patch, and `patches.apply_patch` is the one shared,
  atomic, config-neutralised applier.
- New page `docs/verify-fix.md`; pointers from the README, triage, FAQ, arms
  and data-boundaries pages.

### Changed

- Machine (auto) suppressions in the store replay only while the current
  config still arms auto-suppression (a forged `kind: auto` record no longer
  applies in a repo that never enabled it).
- The default policy is `enforce`: an unsigned `suppress`/`outcome mark`/
  `baseline set` is refused up front with the setup steps, and decisions
  recorded before signing come back as "refused" (the findings gate) until
  they are re-made signed; set `decisions.require_signatures: warn` to keep
  applying unsigned decisions meanwhile.

### Changed — analysis lane reframed onto house prompts (M-V3; threat-model live-verified via claude)

- `scan --analyze threat-model,attack-path,hardening,policy,writeup` works
  again. 0.1.0 refused it honestly because the vendors' analysis skills are
  internal to their own scan and not a public surface (R10). The lane now
  runs security-council's **own** prompts (`prompts/house-analysis-*.md`)
  through the same read-only CLI contract the house scan arms already ran
  live on claude, codex and agy; pick the CLI with `--analyze-with` (default
  claude) or `arms.options."analysis:<job>".cli`. The producer is recorded
  as `house:<cli>` — never a vendor skill name.
- Each document is a validated envelope (`sc-analysis-doc/1`: title, kind,
  scope, files read, completion, notes + Markdown body) and carries
  provenance: served model (attested where the CLI reports it; codex never
  does), entitlement tier and safeguard posture, prompt hash, cost (claude
  reports it; codex/agy do not). claude runs under a `--max-budget-usd` fuse
  (`max_cost_usd`, default 5); a budget stop, a declined or invalid
  document, a timeout or a substituted model is a failed analysis — an
  informational note in the report, never a build failure.
- Unchanged trust boundary, now tested end to end: artifacts never enter
  `findings.json`, coverage or the gate; `attack-path` and `writeup` remain
  dual-use — `raw/`-only and export-excluded.
- Blue scope: the prompts refuse exploit steps, and a best-effort post-check
  redacts shell blocks (dual-use jobs) and known payload signatures (all
  jobs) from the returned document, marking each redaction in place. It is
  a filter for obvious runbooks, not a certification.
- The findings-scoped jobs (`writeup`, `attack-path`) receive a digest of
  what the scan arms found in the same run (ids, titles, locations, sources;
  no snippets, no dispositions) as context.


## 0.1.0 — 2026-08-25

First release. A multi-arm security scanner: deterministic scanners (semgrep,
gitleaks, osv-scanner — local or via docker) and optional agentic LLM reviewers
(claude, codex, agy CLIs), merged by root cause, scored, guardrailed, and gated
for CI. The design rule throughout is **auto-demote, never auto-close**.

### What is in the box

- `security-council scan` with profiles `quick` (default, $0), `ci`, `gov`,
  `deep` (adds the three house AI reviewers + the cross-vendor validation panel;
  real vendor spend on your CLI subscriptions).
- Exports: SARIF 2.1.0, eMASS, OpenVEX, OSCAL AR/POA&M, GitLab SAST/CodeQuality,
  CKLB (STIG Viewer 3), CycloneDX 1.6 (VDR, or merged into a syft SBOM), CSV,
  HTML. `report --bundle triage|gov|all`.
- A GitHub Action (live-verified on real runners), GitLab and Azure DevOps
  templates (local halves verified; not yet run on real infrastructure).
- A decision store: baseline, suppress, outcome-mark — attributed, expiring,
  drift-aware, tamper-EVIDENT (content digest) but not tamper-proof.
- An opt-in fitted calibration record (OWASP Benchmark, Java, semgrep only).
- `security-council setup` — a guided first run.

### What is NOT functional in this release

`--fix`, `--verify-fix` and `--analyze` are present and **refuse honestly**
before running anything. The fix lane's no-network fence cannot reach a vendor
CLI (by design — see `docs/reviews/R11-fix-lane-and-fence.md`), and the
vendor analysis skills are internal to the vendor's own scan, not a public
surface (`docs/reviews/R10-live-vendor-runs.md`). `codex-security` as a
dedicated arm needs its own `codex-security login`.

### The ship review

Sixteen council rounds (`docs/reviews/R12-ship-readiness.md`) on one question:
*is there any path to a silently wrong "clean" or a CI gate that passes when
it should not?* Every round found something real. The root cause of nearly all
of it was one design flaw — coverage was a per-arm boolean — replaced by a
coverage model (`none | partial | verified`) that the gate, the corroboration
context and the SARIF `executionSuccessful` all read. Also added: G10 (a
degraded run cannot auto-suppress or consume a shadow run), G11 (a crypto or
critical finding needs a real panel to leave the gate), I7b, I13, and a
widened I6. The simplest exploit — `printf '*' > .semgrepignore` producing a
clean exit-0 scan in the default profile — was found at round sixteen and is
closed: repository ignore-files now make coverage `partial`.

Rounds seventeen to nineteen, on the released code, found and closed three
more — all in the default configuration, all reproduced before fixing:

- A `security_council/` directory in the *scanned* repository replaced the
  scanner in every CI template (`python -m` puts the caller's checkout first on
  `sys.path`; a stub gave exit 0 with no output). Templates run `python -P -m`.
- `osv-scanner` honoured the repository's `.gitignore` by default, so naming
  `requirements.txt` there yielded a verified-clean exit 0. It runs
  `--no-ignore`; semgrep is pinned `--no-git-ignore`. The scanned repository
  never decides what gets scanned.
- A decision record with an unreadable `expires_at` crashed the scan instead
  of degrading.
- gitleaks auto-loaded the repository's `.gitleaks.toml` (an allowlist of
  every path produced a verified-clean exit 0), and osv-scanner read the
  repository's `osv-scanner.toml`. Both now use a config this package ships,
  passed explicitly; the repository's files are never consulted.

- The scanned repository's own `.security-council.yaml` chose the arms and
  the gate, so a branch could configure its own scan. Not a bug locally, but
  wrong for CI: every run now records and reports `config_source`, the CI
  templates pass `--ignore-repo-config`, and `--config PATH` names an
  operator-controlled file instead.

- The CI templates picked "the latest run" by globbing the scanned repo's
  `runs/` directory, so a committed `runs/99999999_999999/` would have been
  uploaded and annotated in place of the real run. They now read the run
  directory from `scan --json`'s own record. (A round-21 edit had also left a
  doubled line continuation in all three templates — every CI scan failed
  with a usage error until round 22 caught it; the templates are now
  shell-parsed in a test and were re-run on real GitHub runners.)

The principle behind the last six of these: **the scanned repository never
decides what gets scanned.** Ignore-files the tools still honour
(`.semgrepignore`, `.gitleaksignore`) make coverage `partial` and are named in
the report; scanner configs are pinned; `.gitignore` handling is disabled for
the tools that read it.

The word "calibrated" is not used anywhere unless a fitted record is in force.
