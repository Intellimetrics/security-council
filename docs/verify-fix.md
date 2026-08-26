# Verifying a patch: did the fix actually make the finding go away?

**Who this is for:** anyone who has a scan report in one hand and a patch in
the other and wants to know, before opening the pull request, whether the
patch removes the finding — without paying for an AI opinion and without
trusting one.

**What it does, in one sentence:** it applies your patch to a throwaway copy
of your repository, runs the same scanners that found the problem on that
copy, and tells you whether they still find it.

**What it does not do:** it never edits your files, never closes or hides a
finding, and never decides anything for you. It produces *evidence* that a
human reads — the report says "requires human review" on purpose.

## Quick start

```bash
# 1. scan, and note the id of the finding you fixed (printed in the summary)
security-council scan . --arms semgrep,gitleaks,osv-scanner

# 2. write your fix on a branch, and save it as a patch
git diff > fix.patch

# 3. verify the patch against the finding
security-council scan . --arms semgrep,gitleaks,osv-scanner \
    --verify-patch fix.patch --for 14a881449f73c63d
```

Real output from the practice repository in this project
(`tests/fixtures/seedrepo`, a semgrep-only scan, a hand-written patch that
parameterises the SQL query at `app/reports.py:9`):

```text
security-council scan 20260826_121253  (target .../seedrepo)
  semgrep       ok                       raw=3 normalized=3 2.45s
findings: 2 clusters  severity={'high': 2}
patch verification fix.patch: 1 fixed, 0 not fixed, 0 unproven — machine evidence, requires human review (never closes a finding)
  14a881449f73c63d  fixed      app/reports.py  semgrep: absent from a verified scan of the patched copy
reports: .../run2  (summary.md, merged.sarif, findings.json, manifest.json)
exit 1
```

And the same command with a patch that only edits a comment in that file:

```text
patch verification noop.patch: 0 fixed, 1 not fixed, 0 unproven — machine evidence, requires human review (never closes a finding)
  14a881449f73c63d  not_fixed  app/reports.py  semgrep: still reports it (matched by root_cause)
```

Two things to notice. The exit code is still `1`: the scan itself ran on your
*unpatched* tree, where the finding is still present, so the gate still
fails. That is correct — the verdict is about the patch, not about the tree
you scanned. And the verdict is *evidence*, not a state change: nothing in
the finding's disposition moved.

## Reading the verdicts

| Verdict | Meaning | What to do |
|---|---|---|
| **fixed** | Every scanner that had reported the finding completed a *verified* scan of the patched copy and no longer reports it. | Review the patch as you normally would; the scanners agree the specific pattern is gone. |
| **not fixed** | At least one of those scanners still reports it — or the same rule fired at a *new* place in the same file that was not in the run (the sink moved rather than went away). | The patch does not remove what was flagged. Look at the `Why` column. |
| **unproven** | Nothing could vouch either way: the finding had no deterministic scanner behind it (an AI-reviewer-only finding), a scanner was unavailable or failed on the copy, its coverage of the copy was `partial`, or the patch did not apply. | A human has to look. The reason is spelled out; `unproven` is never silently upgraded to `fixed`. |

`fixed` is deliberately the hardest verdict to earn. An absence is only
evidence when the scan that reports it examined the whole copy, so an arm
whose coverage verdict is `partial` or `none` ([safety-model.md](safety-model.md),
the R12 coverage model) cannot produce `fixed`, however clean its output.

## Which findings get checked

- With `--for id[,id...]`: those findings. Ids come from the summary or
  `findings.json` of the run; a unique prefix of six or more characters is
  accepted. A refuted or suppressed finding is not checked (it is not open).
- Without `--for`: every open finding whose primary location is in a file
  the patch touches. If the patch touches no file with an open finding, the
  run reports `verify_patch_nothing_to_verify` and checks nothing.

Ids are stable across runs of the same commit (they are derived from the
finding's fingerprints, never from line numbers), so the id printed by
yesterday's scan is the id you pass today — as long as the code has not
changed in between. The verification always runs against the *current*
scan's findings, which is the pre-patch picture at the same commit; that is
what lets it tell "the finding moved" from "the finding was already there".

## What it writes

- **`summary.md`** — a *Patch verification* section: the patch's sha256 and
  the base commit it was checked against, the files it touches, which
  scanner (and version) checked it with what coverage, and one row per
  finding with the verdict and the reason.
- **`manifest.json`** — a `verify_fix` block with the same data in machine
  form, plus one `verify-fix` artifact per finding (`method:
  deterministic`, `decided_by: machine`, `non_closing: true`). `scan --json`
  includes the block.
- **`<run>/verify-patch/raw/<scanner>/`** — the scanners' raw output from
  the patched copy, so the verdict can be re-derived.
- **The decision store** (`.security-council/decisions/`) — a
  `deterministic_verify_fix` event on the finding's root-cause record, bound
  to the patch sha256 and the base commit. It is machine evidence: it is not
  signed, it is not a decision, and the scoring history term ignores it
  ([signing.md](signing.md), [safety-model.md](safety-model.md) L1).

## Requirements and limits

- `git` (the patch is applied with `git apply`, config neutralised, atomic:
  a patch that does not apply cleanly touches nothing and comes back
  `unproven` with git's message). Make the patch with `git diff` or
  `git format-patch`; both produce the `a/…` `b/…` form it expects, with
  context lines. A zero-context hunk in the middle of a file is rejected by
  git and reported as not applied.
- The scanners used for the verdict are exactly the ones that reported the
  finding in this run, so run the same `--arms` you scanned with. Nothing is
  sent anywhere the scan itself did not already send it; no AI vendor is
  involved. `--inplace` is refused (the patch is applied to a copy only).
- Patches that touch `.git/`, `.github/`, agent configuration files
  (`.claude/`, `CLAUDE.md`, `AGENTS.md`, …), symlinks or binaries are
  refused before anything is applied, the same validator the fix lane uses.
  Patches that touch tests, CI files or lockfiles are applied but flagged
  in the report.
- It answers one narrow question — "do the scanners still see this
  pattern?" — and nothing else. A patch can silence a scanner without fixing
  the bug (a suppression comment, a rewrite the rule does not match). The
  *moved-sink* check catches the obvious form of that within the same file;
  it cannot catch a fix that is wrong in a way no scanner detects. That is
  why every verdict says "requires human review".
- AI-reviewer-only findings (the cross-file authorization bug this tool
  exists to catch) come back `unproven`: no deterministic scanner ever saw
  them, so none can vouch that they are gone.

## `--fix … --verify-fix`

The same verification runs on every patch the fix lane produces when
`--verify-fix` is passed. The fix lane itself is not functional in 0.1.0
(the no-network sandbox cannot reach a vendor CLI, see
[reviews/R11-fix-lane-and-fence.md](reviews/R11-fix-lane-and-fence.md)), so
today `--verify-patch` with your own patch is the way to use this.

## Why deterministic

The earlier design had a vendor model assess its own vendor's patch. The R11
council review found that verdict worth little and settled on this one: the
scanners that raised the finding are the cheapest, most reproducible judge of
whether the pattern they matched is still there; they need no credentials,
no network and no sandbox exemption; and a model can *explain* a result
afterwards without ever deciding it. The vendor verify arm still exists in
the code as a possible future explainer; it is not on any path.
