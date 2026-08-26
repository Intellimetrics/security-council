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

### Changed

- Machine (auto) suppressions in the store replay only while the current
  config still arms auto-suppression (a forged `kind: auto` record no longer
  applies in a repo that never enabled it).
- The default policy is `enforce`: an unsigned `suppress`/`outcome mark`/
  `baseline set` is refused up front with the setup steps, and decisions
  recorded before signing come back as "refused" (the findings gate) until
  they are re-made signed; set `decisions.require_signatures: warn` to keep
  applying unsigned decisions meanwhile.


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
