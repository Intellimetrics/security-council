# R10 — First live vendor-spend runs: what only real invocation could find

- **Date:** 2026-08-25 · CLIs: `claude` 2.1.245, `codex` 0.149.0, `agy` 1.1.19
- **Authorised by the user** ("I don't care about money spend here… we should
  use codex, agy, claude"), CLI subscriptions, no API keys.
- Council: `.llm-council/runs/20260825_063841_*` (quick, **degraded 1/3** —
  claude and codex both timed out at 264s on a 9,087-char prompt).

## Why this review exists

Five lanes were built offline against fake-proc doubles and had never been
invoked for real: the codex/agy house arms, the analysis-artifact lane (M-V3),
the fix + verify-fix lane (M-V4), and the vendor voters (M-V5). Every defect
below was invisible to the offline tests, because the double answered where
the real CLI refuses.

## 1. The house prompt spoke only Claude Code's dialect  → FIXED

`prompts/house-sast.md` said *"Do not run shell commands. Use your
Read/Grep/Glob tools."* Codex and Antigravity have no such tools — their file
access **is** the shell. Both arms therefore declined every category:

- codex: *"the available toolset exposes no non-shell Read, Grep, or Glob
  capability, while the user explicitly prohibited shell commands"*
- agy: *"I cannot fulfill requests to perform vulnerability scanning"*

The agy line reads as a model-policy refusal. It was not. It was our prompt.

Read-only is enforced at the **flag** layer — `claude --tools Read,Grep,Glob,LS`
(no Bash granted at all), `codex -s read-only`, `agy --sandbox --mode plan` —
so the prose ban bought nothing on Claude and was fatal everywhere else.

| | codex | agy |
|---|---|---|
| before | 0 findings, `completion=declined` | 0 findings, `completion=declined` |
| after | 7 findings, `completion=complete` | 7 findings, `completion=complete` |

After the fix, 8 clusters (4 critical / 4 high), 3 of them corroborated
**2 src / 2 vendor**, including the labelled prompt-injection canary in
`README.md`. **The guardrails held throughout the broken period**: zero
findings without a `complete` self-report was recorded as
`coverage_unverified`, never as "clean", and the summary printed
"⚠ coverage unverified · completion declined" rather than a clean bill.

## 2. The vendor voter was a silent no-op  → FIXED

`validate/panel.py::make_vendor_runner` called
`codex-security validate <title> --format json`. The real CLI rejects it:

> `codex-security: validate does not support noninteractive JSON output; run
> it without --json, --format json, or --format jsonl.`

Every live call failed, `r.ok` was False, and the runner returned `[]` — the
voter contributed nothing while appearing to work. Now: correct command, and
a voter that cannot run is recorded as an `absent` panel opinion (kept in the
panel so the run shows the opinion was sought and never arrived; filtered from
`ok` so it stays weight-0 and cannot move a verdict). `--effort` is pinned —
upstream defaults to `xhigh`, billed per finding.

The test covering this asserted the silent-drop behaviour, so it encoded the
defect. It now pins the corrected command and guards against reintroducing
`--format json`.

## 3. CRITICAL — "verified" citations prove existence, not relevance

Found by council (antigravity, in the degraded run), reproduced here.

`llm-council`'s `verify_ref` sets `verified=True` when the path resolves inside
cwd and `start_line <= file_line_count`. **Nothing else.** security-council
consumes that flag verbatim, and `score._fully_verified_defender` asks only for
`status ok`, `>=1 citation`, `citation_pass_rate == 1.0`.

So a defender that votes false_positive citing **`README.md:1-1`** is a "fully
verified defender". Reproduced end to end: a **semgrep-corroborated** SQL
injection reached state `refuted`, **G2 did not fire**, and
`orchestrator._exit_code` drops `refuted` from the CI gate.

This defeats the *stronger* guardrail on the *highest-confidence* finding
class. The safety model presents citation verification as the core
anti-wrongful-suppression control; it is satisfiable by any real line number.

### 3b. Citing nothing is treated better than citing badly

`synthesize_validation` decides by **counting** opinions — it never reads
`op.weight` (dead in the decision path) and drops only `absent`. So an
`unevidenced` opinion (zero citations) is a full vote, and two of them reach
`false_positive`. Meanwhile `score.py` clamps on `unreliable` (citations
present, <67% verified) but has **no `unevidenced` branch**.

Reproduced: an LLM-only finding corroborated by two independent vendor
families, refuted by two opinions citing nothing at all; policy did not rescue
it (G2 covers only findings with a deterministic source).

**Mitigations that DO hold:** demote-never-close — lifecycle stays `open`,
renders as SARIF `suppressions[underReview]`, and appears in the summary
appendix. Nothing is hidden. But it stops failing CI, which is the
operational protection.

Fix is under council review (`fix-brief.md`); the open objection is Q2 — a
defender refuting a *wholly fabricated* finding legitimately has nothing to
cite, so "no citations cannot refute" would pin hallucinated findings open
forever.

## 4. M-V3 (analysis artifacts) — the invocation contract is wrong

`arms/artifact_runner.py::_cmd` builds
`[codex, -p, <prompt>, --output-format json, --dangerously-skip-permissions,
--no-session-persistence, --strict-mcp-config]`. Those are **Claude Code**
flags. On codex, `-p` is `--profile`. The lane could never have run.

Worse, the premise is wrong. `artifacts.py` claims the analysis skills are
"triggered as `$threat-model` inside a codex session". They are not
independently reachable:

- `codex plugin list` → only gmail/github; `codex plugin add` installs from a
  marketplace snapshot only, so the bundled plugin cannot be registered.
- The real producer runs `codex exec --ignore-user-config **--disable
  plugins** --ephemeral --color never --json --config model=… --sandbox
  workspace-write --skip-git-repo-check --cd <dir> <prompt>` — it **inlines**
  the skill instructions rather than triggering `$skill`.
- `codex-security skills list` exposes only wrappers for its own subcommands;
  there is no threat-model/attack-path/hardening subcommand.
- `skills/threat-model/SKILL.md` is not self-contained (it references
  `../../references/*.md`) and states that standard scans "build their threat
  models within their ordinary workflow; neither invokes this separate phase
  skill."

**Conclusion:** the analysis skills are internal phases of `codex-security
scan`, not a public API. Driving them ourselves would mean copying vendor skill
text into prompts and depending on internal reference paths. The supported
alternatives are (a) reframe M-V3 onto our own house prompt so it works across
all three CLIs, or (b) drop the lane. Decision pending.

## 5. M-V4 (fix / verify-fix) — three compounding blockers, and the wrong shape

`arms/fix.py` runs the vendor CLI inside `fence.bwrap_argv(..., allow_network=False)`:

1. **The binary is not visible.** The fence binds only `/usr /bin /sbin /lib
   /lib64 /etc`; `codex` lives in `~/.nvm/versions/node/v22.22.0/bin`, `claude`
   and `agy` in `~/.local/bin`. Verified live: `bwrap: execvp codex: No such
   file or directory`.
2. **`--unshare-net`** blocks the model API the patch generation depends on.
3. **tmpfs `HOME`** drops `~/.codex/auth.json`, so even reachable+networked it
   would be unauthenticated.

Beyond the flags, the shape is wrong: `codex-security` has first-class
`patch` and `verify-fix` subcommands, and `scan --patch --patch-severity`
("Patch and verify confirmed findings after the scan"). Driving raw `codex
exec` inside a fence was never the vendor's supported route.

This is a genuine security tradeoff — patch generation needs egress, and the
fence exists to deny both writes and exfiltration — so it needs a design
decision, not a flag tweak.

## 6. Not our bug: codex-security credentials are stale

`validate`, `patch`, and `scan` all fail fast (~3s, exit 1, `ok: true / data:
null`). Root cause, from `scan --verbose`:

> Your access token could not be refreshed because your refresh token was
> already used. Please log out and sign in again.

`info` works (local metadata only). Plain `codex exec` is unaffected —
`~/.codex/auth.json` is valid and I confirmed it still authenticates.
codex-security maintains its own credential refresh path and that token is
stale. **Requires an interactive `codex-security login` by the operator**;
until then the dedicated codex arm, the vendor voter, and `scan --patch` are
all blocked for reasons unrelated to this codebase.

Note this does **not** explain defect 2 — the `--format json` rejection is an
argument-validation error emitted before any API call, with a different
message.

## Status after this review

| Lane | Before | After |
|---|---|---|
| house arms claude/codex/agy | claude only | **all three live-verified**, cross-vendor corroboration real |
| validator panel (`--validate`) | unproven | **live-verified** — 3 seats, 3 vendors, citations verified |
| vendor voters (M-V5) | unproven | command fixed; blocked on vendor login |
| analysis artifacts (M-V3) | "built offline" | **contract wrong**; lane needs a design decision |
| fix / verify-fix (M-V4) | "built offline" | **cannot run as built**; needs a design decision |

## Council round 2 — quorum met, and it moved the design

`.llm-council/runs/20260825_064655_*` — claude **tradeoff** (229.7s),
antigravity **yes** (127.5s), codex **timeout** (again; the reliable
failure in this environment). Every claim below was re-verified here against
the real files.

### It refuted my own objection (Q2)

I argued that "no citations cannot refute" would pin *fabricated* findings
open forever, because a defender refuting invented code legitimately has
nothing to cite. **That premise is wrong.** `normalize/snippets.py::capture`
returns `None` for a missing file, a traversal escape, or `start > len(lines)`,
and `normalize/base.py::build_finding` drops the finding
(`ctx.skip("unresolvable_location")`) when it does. **A wholly-fabricated
location never reaches the panel.** A finding that *does* reach the defender
has a location that resolves — so an anchored citation is always available to
a defender who actually looked. Rule (2) is therefore viable, and Q1's anchor
set can be `locations ∪ data_flow[].location` (`model.py:159-163`), which is
free and deterministic.

### Four more defects in the same surface, all verified

1. **`no_cross_file_navigation` is a dead flag.** Defined
   (`model.py:289`), read (`score.py:157`), and **never assigned anywhere in
   the package**. The clamp that `score.py`'s own docstring and
   `docs/safety-model.md` both advertise — "missing cross-file navigation
   flags human review" — has never once fired. Either wire it or delete it and
   the claim; a documented control that cannot trigger is worse than no claim.

2. **`defender_hallucinated` only watches the defender**
   (`panel.py:70-72`). A *prosecutor* or *adjudicator* voting
   `false_positive` on a fabricated citation is not trapped, even though the
   verdict it feeds is the wrongful-suppression direction.

3. **Malformed citations improve your score.** `_citations`
   (`panel.py:25-36`) silently `continue`s past entries with a bad path or bad
   line numbers, so they never enter `cites` — and `citation_pass_rate =
   verified / len(cites)` is computed over the survivors. Dropping junk
   *raises* the rate. Related: `pass_rate >= 0.67` keeps status `ok`, so
   2-verified-of-3 with one fabricated citation escapes the `unreliable`
   clamp entirely.

4. **The FP quorum is not deduped by vendor family.** `fps = [... verdict ==
   "false_positive"]` with `len(fps) >= 2` (`panel.py:66-80`) counts
   *opinions*, not families, while `FAMILY_BY_PEER` maps both `antigravity`
   and `gemini` to `"google"`. The documented property — "three seats on
   distinct vendor families so one vendor's blind spot can't both produce and
   confirm a verdict" — is enforced by config discipline, not by code. Not
   reachable with today's three-seat config; unguarded if a fourth peer is
   ever added.

5. **`_fully_verified_defender` never checks the defender's own verdict**
   (`score.py:70-73`). A defender voting *true_positive* with one good
   citation satisfies G2 — which then clears the way for other peers to carry
   the `false_positive` quorum. The function that gates refutation does not
   require the defender to be refuting.

### What the gate actually still catches

`disputed`, `likely`, and `needs_human` all still fail the build
(`orchestrator.py:69-73`); `refuted` is the only panel-derived escape. That
narrowness is why the impact is bounded, and why the fix should concentrate on
the `refuted` transition rather than on scoring.

## Decisions taken

Fixed and committed this session: the house prompt (defect 1), the vendor
runner (defect 2), and — in `0a5abfe` — **every defect in §3 and in this
section**.

The evidence rules now gate refuting harder than confirming, on purpose,
because refuting is the wrongful-suppression direction: a refutation must be
**anchored** to the finding's own code (`locations` ∪ `data_flow`, ±25 lines,
≤80-line span — the span cap exists because `verify_ref` bounds `start_line`
but not `end_line`, so a 1..5000 citation would otherwise intersect anything),
must come from a defender who actually voted `false_positive`, must be fully
**evidenced** (`unevidenced`/`unreliable` opinions still count toward
`true_positive`, the fail-safe direction, but never toward `false_positive`),
and must span **≥2 distinct vendor families**. Any peer refuting off a
fabricated citation forces `needs_human`. Malformed citations lower the pass
rate instead of raising it. A blocked refutation is named in the report
(`refutation_blocked`) rather than vanishing. `no_cross_file_navigation` is
wired to a real signal.

**Guarded against over-correction**, which was the live risk in tightening
this: a legitimate anchored refutation still reaches `refuted` (unit test and
live run), and the eval gate still demotes the `FP-MD5-CACHE` decoy —
`validated_precision` 0.9524, `true_positive_suppression_rate` 0.0,
`crypto_suppression_rate` 0.0, no violations. 11 of the 12 new tests in
`tests/test_panel_evidence.py` fail without the change; the twelfth is the
control asserting that a zero-citation opinion may still *confirm*.

Codex timed out in both council rounds, so the third opinion on these rules is
still outstanding — worth a re-run when the codex timeout is raised.
