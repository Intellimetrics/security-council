# Changelog

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

The principle behind the last four of these: **the scanned repository never
decides what gets scanned.** Ignore-files the tools still honour
(`.semgrepignore`, `.gitleaksignore`) make coverage `partial` and are named in
the report; scanner configs are pinned; `.gitignore` handling is disabled for
the tools that read it.

The word "calibrated" is not used anywhere unless a fitted record is in force.
