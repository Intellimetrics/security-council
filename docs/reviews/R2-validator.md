# Validator panel — status & findings (2026-08-20)

The cross-vendor validator panel (validate/*) is built, unit-tested (7 tests via an
injected fake council runner), and integrated into `security-council scan --validate`.
It shells out to `llm-council run --mode consensus --json` (design decision D2),
parses per-peer verdicts, verifies citations, applies the panel guardrails, and sets
each finding's `validation` + `disposition.state`. Lifecycle stays `open` — v1
auto-demotes (refuted -> SARIF suppression `underReview`) but never auto-suppresses.

Proven live end-to-end: a scan of the fixture ran the 3-peer panel
(prosecutor/defender/adjudicator across claude/codex/antigravity), verified 4/4
citations against the real code, and produced verdicts + dispositions.

## Two real issues the live runs surfaced

1. **SAST-shaped prompt does not fit SCA/dependency findings.** Asking
   "is the code defective / reachable?" of a `urllib3@1.24.1 -> CVE-x` finding makes
   peers hedge to uncertain. FIXED for v1 by skipping `supply_chain` (deterministic
   from osv) via `SKIP_VALIDATION_FAMILIES`. A dedicated dep-reachability validator
   (is the vulnerable symbol imported/used? VEX justification) is a future lane.

2. **The validator writes llm-council transcripts into `<target>/.llm-council/runs/`,
   which the NEXT scan then scans** — inflating counts and re-ingesting finding
   snippets/secrets. Partial fix: semgrep now excludes `.llm-council`/`.security-council`.
   PROPER fix (deferred): scan a scratch `git worktree` copy that excludes runtime
   dirs (the plan's workspace.py isolation), and/or point the validator council's
   transcripts_dir outside the target. gitleaks/osv still lack a CLI path-exclude,
   so scratch-worktree isolation is the real answer.

## Also improved
- Verdict extraction now parses an explicit `VERDICT: true_positive|false_positive|
  uncertain` line from the council transcript (S2's proven pattern), falling back to
  the coarse RECOMMENDATION label — the label alone under-committed clear findings.

## Deferred (validator)
- Per-finding budget/caching, batching by file, the calibrated confidence function
  and full disposition state machine (score.py/policy.py), shadow mode, the decision
  store. v1 sets state but never suppresses, so these are safe to defer.
