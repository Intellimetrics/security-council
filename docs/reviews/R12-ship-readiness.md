# R12 — Ship-readiness review for 0.1.0

- **Date:** 2026-08-25 · **Mode:** quick · **Quorum:** NOT met (1/3)
- antigravity **no** (182s, risk critical) · claude **timeout 480s** ·
  codex **timeout 600s**
- Brief: `.llm-council/inputs/r12-ship-readiness/brief.md` · transcript
  `.llm-council/runs/20260825_120417_*`

Council's verdict was **no-ship**, on one label. Everything below was
re-verified here before acting; a degraded round is a lead, not a finding.

## The one that mattered: a scanner that scanned nothing looked clean

semgrep, gitleaks and osv-scanner all treat **exit 1 as success** ("findings
found"). `ScannerArm.run` set `findings = []` whenever the SARIF file was
absent and otherwise passed `r.ok` straight through — so a run that exited
inside `success_exit_codes` but wrote no report returned `ok=True,
findings=[]`, **with no error**. A scanner that examined nothing reported a
clean repo, and the CI gate passed.

This is the exact failure this project exists to prevent, and it is the class
I told council to hunt for. Now: no report + success exit ⇒ loud failure,
`coverage_unverified`, `"nothing was scanned (coverage unverified, NOT clean)"`.

### The opposite mistake, which only running it revealed

osv-scanner writes no SARIF and exits non-zero on a repo with **no dependency
manifests** — so the fix above would have turned every dependency-free repo
into a failed scan. That case is *not-applicable*, not a failure. A
`not_applicable_markers` spec field separates them.

Verified live in both directions: a clean dependency-free repo went from
**exit 3 → exit 0**, and semgrep/gitleaks were confirmed to write an *empty*
SARIF when they find nothing — which is what makes the loud-failure rule safe.
There is a test pinning that, because if it ever stopped being true the new
rule would fail every clean scan.

## Found by running the tool while writing the brief

- **`available()` was never consulted on the scan path** — only by `doctor`,
  the MCP doctor and the setup wizard. So the "honest refusals" added in R11
  refused nothing: `--analyze threat-model` ran for 131s, reported `ok`, and
  wrote a `THREAT_MODEL.md` stamped with vendor-skill provenance R10 had
  established we cannot support. (The model answered from its own knowledge;
  the skill never ran.) An unavailable arm is now a failed arm.
- **A relative `--out` broke every docker-based scanner.** The path reaches
  `docker -v` unresolved and is read as a volume *name*. `--out ./x` made
  semgrep, gitleaks and osv fail together, which tripped `insufficient_arms`
  and exited 3. Now resolved at the CLI.

## Ship-quality changes

- **`deep` no longer ships arms that cannot run.** It enabled the two
  dedicated vendor plugins — one of which needs its own login — while the three
  house arms, live-verified on all three CLIs this session and one per vendor
  family, were in no profile at all. Swapped; the dedicated arms stay reachable
  via `--arms`.
- **The README no longer oversells the default.** It led with an "AI
  cross-examination panel" while the default runs three deterministic scanners
  and no panel. A table now states plainly what is $0 and what costs vendor
  spend, and says the opt-in half is the half the design is about.

## Recorded, deliberately not changed

`_exit_code` returns 3 whenever any arm failed, even when
`len(ok) >= min_arms_ok`, so `min_arms_ok` does not tolerate failures the way
its name implies. It errs **safe** — a partial failure never reports clean — so
this is a contract/naming inconsistency to document, not something to patch
against a ship deadline.

## Council health

claude and codex have now timed out in three of four rounds, at 240s, 480s and
600s, on prompts as small as 2.5 KB. Raising the timeouts did not help. Plan
for antigravity-only or 2/3 rounds in this environment, and never read a
timeout as agreement — R12's single label still carried the most important
finding of the review.


## Round 2 — full 3/3 quorum, unanimous NO-SHIP

`.llm-council/runs/20260825_121958_*` — claude **no** (117s), antigravity
**no** (119s), codex **no** (512s, its first completion in four rounds). All
three confirmed the round-1 fixes landed, and all three found further
silent-clean paths. They were right to say no.

Every one below was verified here, then fixed:

1. **An unreadable report was a clean scan.** The SARIF parse `except` set an
   error string but left `r.ok` **True**, so a corrupt report produced
   `ok=True, findings=[]` — the same silent clean result as a missing report,
   one branch over from the fix I had just made.
2. **`min_arms_ok: 0` with nothing succeeding returned 0.** `len(ok) < 0` is
   false, no findings gated, no arm was "failed" by the later branch — so a
   scan where NOTHING ran reported the repo clean. There is now a structural
   floor: no successful arm ⇒ exit 3, whatever `min_arms_ok` says.
3. **An arm that declined every category counted as a success.**
   `llm_cli` returned `ok=True` even while setting `coverage_unverified`. With
   only such arms enabled, the run had a "successful" arm, no findings, and
   exited 0. Observed for real earlier in the day: codex and agy both declined
   everything and printed `ok`.
4. **The GitLab template's gate could pass with findings present.**
   `SCAN_EXIT=$?` sat in its own `script:` entry; GitLab Runner runs each entry
   separately with its own output machinery, so `$?` need not be the scan's
   status. Capture now happens inside one entry and the code is persisted to a
   file that the final `exit` reads.
5. **`--working-tree` silently became a committed-changes scan.**
   `DiffSpec`'s docstring already said claude-security "is skipped in this
   mode" — nothing skipped it. Uncommitted vulnerable code went unexamined
   while the arm reported success. It now refuses.
6. **The `not_applicable` marker could excuse a genuine failure** — it forced
   `ok=True` on any exit code, including a timeout that merely printed the
   marker. Now bounded to a run that finished.
7. **`--deep` had become a no-op for the `deep` profile**, since it only ever
   set options on the two dedicated plugin arms. It now applies to whichever
   arms are actually enabled.

Codex additionally noted the dead lanes remain visible in `--help`; that is a
deliberate 0.1.0 decision, recorded in the release notes rather than hidden.

## Verified after the round-2 fixes

428 tests, ruff clean, eval gate green (`true_positive_suppression_rate` 0.0,
`crypto_suppression_rate` 0.0, no violations). Live: a clean dependency-free
repo exits 0; the vulnerable fixture still finds 17 clusters and exits 1.

**Ship position:** the silent-clean class that made this a no-ship is closed,
and each instance has a regression. A third round would be worth running
before tagging, since rounds 1 and 2 each found real defects in the previous
round's fix.
