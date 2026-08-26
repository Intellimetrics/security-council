# The safety model

This page is for auditors and skeptics. Every claim carries a code pointer;
none of it is aspirational prose — the properties are enforced by structural
invariants and a CI eval gate, not by convention.

## The risk this design answers

Agentic LLM triage demonstrably works — published research on agentic
false-positive filtering reports enormous precision gains. The same
literature reports the failure mode: the best-performing configuration
**wrongly suppressed 22% of true vulnerabilities, and over 50% for
crypto-related CWEs**, and removing cross-file navigation dropped triage
accuracy from 96% to 44% ("Sifting the Noise", arXiv 2601.22952; cited in
`security_council/policy.py` and `score.py`). security-council's position:
take the precision, and make the suppression failure mode *structurally*
hard.

## Invariants I1–I12 (`model.py`, `assert_invariants`)

Checked at every producer/exporter boundary, fail-closed. The load-bearing
ones:

| | Property |
|---|---|
| I1–I3 | Every location resolves and is hashed; fingerprints are line-number-free by construction (line drift can't resurrect or duplicate findings) |
| I4 | Crypto is *sticky*: any crypto CWE anywhere in the taxonomy forces the crypto family — a crypto finding can't be re-filed under "injection" to dodge crypto rules |
| **I6** | A suppressed/accepted-risk finding **must** carry full attribution — auto: model id + prompt hash + panel hash; human: operator — plus decision ref and expiry. An unattributed hidden finding *cannot be constructed* |
| **I7** | A crypto finding with `kind != human` on a hidden lifecycle is invalid — crypto is never machine-hidden, period |
| I7b | The same for a **critical** finding. G7 forbade auto-suppressing critical in the policy layer, but only crypto had the structural twin — a hidden critical finding could be *constructed* where a hidden crypto one could not |
| I9 | Finding ids are derived from fingerprints and verifiable — an id can't be forged to collide a decision onto a different finding |
| I13 | The lifecycle must be one the model knows. Every hiding invariant and the CI gate key on set membership, so an *invented* value (`wontfix`) was in no set: no invariant fired and the gate dropped the finding. Reproduced on a critical finding — exit 0, no complaint |
| I6 (widened) | `fixed` requires baseline evidence the finding is **gone — from anyone**. It exempted `kind: human`, and a stored record simply claims its own kind, so a record asserting human + `fixed` closed a live critical finding. "Fixed" is a claim about the code, not an opinion; the scanner just found it |
| I11 | SARIF suppressions / VEX `not_affected` may only appear on closed lifecycles — no export can *show* suppressed what the model holds open |

## Guardrails G1–G8 (`policy.py`)

| | Rule |
|---|---|
| G1 | Crypto never auto-suppressed (backed by a scoring floor: crypto p ≥ 0.50) |
| G2 | An LLM panel alone cannot refute a deterministic-scanner finding — without a defender who actually refuted, whose *every* citation verified, and at least one of whose citations is **anchored to the finding's own code**, it escalates to `needs_human` (which still fails the gate) |
| G3 | Every suppression fully attributed (see I6) |
| G4 | First 5 armed runs are shadow mode; the counter counts only armed runs and resets on suppression-config change |
| G5 | Decisions scope to one root-cause fingerprint — never a rule, CWE, or glob |
| G6 | Suppressions expire (90 days) → the finding reopens |
| G7 | Critical severity never auto-suppressed |
| G8 | Context drift (the code around the finding changed) → the decision deactivates permanently and the finding reopens for re-validation |
| G9 | Crypto and critical findings can never be taken out of the gate by **unsigned operator state**: a baseline never excuses them, and a stored suppression of one is re-affirmed every 30 days instead of 90 |
| G11 | A crypto or critical finding may leave the gate only on a refutation an **actual panel** produced (≥2 independent, evidenced, distinct-family refuters). Demotion removes a finding from the build just as suppression does, and nothing else checked that a high-assurance `refuted` state had evidence behind it |
| G10 | A run that did not verify its full coverage **cannot auto-suppress**. A partial run has fewer eligible corroborators, so p is lower and suppression is *more* likely — exactly when it is least justified — and the stored record would outlive the run that could not justify it. Reported as `auto_suppress_withheld`; human decisions are unaffected |

### Coverage is a verdict, not a boolean

`normalize/coverage.coverage_verdict()` answers one question for every arm:
**what can this arm vouch for having examined?**

| | |
|---|---|
| `none` | It failed, wrote no report, wrote an unreadable one, or declined everything. It does not count as coverage and gets no vote |
| `partial` | It ran over less than its scope — a timeout, a cost stop, an incomplete vendor bundle, declined categories. The run is degraded; it is credited for what it *did* report but its **silence proves nothing** (`may_decline=False`), and it is scoped out of families it declined |
| `verified` | It completed over the scope it was given. `not_applicable` lands here on purpose: nothing in scope (osv on a repo with no dependency manifests) is an honest clean for that arm's categories |

Three consumers read that one function — the CI gate, the corroboration
context, and the SARIF `invocations[].executionSuccessful` — so they cannot
drift apart. Drift between exactly those three is what the 0.1.0 ship review
kept finding: coverage used to be a per-arm boolean, and **six review rounds
each turned up a fresh way for a scan that examined less than it claimed to
report clean** (a missing report, an unreadable one, zero arms under
`min_arms_ok: 0`, an arm that declined every category, a timed-out scanner
resurrected by partial findings, a CI template capturing the wrong `$?`).
Patching each instance produced the next one; the model is what stopped it.

The simplest exploit of the whole review was found at round sixteen, in the
default configuration: `printf '*' > .semgrepignore` turned the vulnerable
fixture into a clean, `verified`, exit-0 scan. A repository's own scanner
ignore-files (`.semgrepignore`, `.gitleaksignore`, `osv-scanner.toml`) are
still honoured — ignoring vendored code is legitimate — but they now make
coverage `partial`, and the degradation names them. Likewise `osv-scanner`
runs with `--recursive`: without it, manifests below the top level were never
read and the "no package sources" case read as a verified clean.

The rule that emerged, after four instances (`.semgrepignore`, `.gitignore`,
`.gitleaks.toml`, `osv-scanner.toml`): **the scanned repository never decides
what gets scanned.** gitleaks and osv-scanner run with a config this package
ships, passed explicitly, so a repository's own config is never auto-loaded;
`.gitignore` is disabled for both tools that read it (`--no-ignore`,
`--no-git-ignore`); and the ignore-files the tools still honour make coverage
`partial` and are named in the degradation. In every case the fix was verified
by reproducing the clean-exit-0 first and re-running after.

The same principle has one more instance that is a **trust decision rather
than a bug**: `.security-council.yaml` is normally the scanned repository's
own file, and it chooses the arms, the gate severity, the baseline mode and
the suppression policy. That is the right local workflow and the wrong CI
one — a branch under test must not configure its own gate. So every run
records `config_source` in the manifest and the summary (with a warning when
it came from the repository), the shipped CI templates pass
`--ignore-repo-config`, and operators who want a file use `--config <path>`
to name one the branch cannot edit.

Plus the meta-rule: **demote, never auto-close.** A refuted finding leaves
the CI gate but stays open, renders as SARIF `suppressions[underReview]`, and
appears in the summary's appendix.

### The decision store: signed events, verified on every scan

`.security-council/decisions/` and `baseline/latest.json` are plain local
files that decide what does *not* gate. R9 found (and this project reproduced
live) that a hand-written baseline could switch the CI gate off entirely — the
fingerprints it needed are published in every SARIF report. That is closed
in two layers:

1. **Tripwire.** The baseline carries a content digest; a baseline whose
   entries don't match it — **or that has no digest at all** — is refused,
   which means no baseline, which means everything gates. Someone who can
   write the file can recompute the digest, so this only catches careless
   edits.
2. **Signatures** (`signing.py`, [signing.md](signing.md)). Every human
   write — suppression, outcome mark, baseline — is an event signed with the
   operator's SSH key (`ssh-keygen -Y`, no new dependency) over a fixed field
   list bound to this store's id, and verified on every scan against the
   committed `allowed_signers` roster with the principal = the claimed
   operator. Under `require_signatures: enforce` (the default; the CI
   templates pass it explicitly) a decision that is unsigned, edited after
   signing, signed by an untrusted key, or copied from another repository is
   **not applied** — the finding reappears and gates. When a signature
   verifies, the scan applies the **signed** expiry, lifecycle and context
   hash, not the record's editable copy. Machine writes are never signed (a
   signing key must not exist on CI runners), so an automatic suppression
   replays only while the operator config still arms auto-suppression.

Be clear about what this buys. A signature is **provenance, never
assurance**: it attests who decided and that nothing changed since, not that
the decision was right, and it cannot stop an insider who can write both the
store and the roster. What makes it load-bearing is putting `decisions/`,
`baseline/`, `store.json` and `allowed_signers` behind CODEOWNERS and
required review, so every change to what gets hidden — and every new
signer — is a reviewed diff. Every reapplied suppression is also listed
individually in the report — who, signature status, when, expiry, and how
many times it has been silently reapplied — because an aggregate count is
the thing nobody re-reads. Residuals (replay of an unexpired signed record
from git history; the `auto` level's warn period for pre-existing stores)
are stated in [signing.md](signing.md).

## Scoring (`score.py`) — transparent, and honest about calibration

p(true positive) is an additive log-odds model: prior −1.2 plus seven named
terms (vendor-family corroboration, deterministic corroboration, adjudicator
verdict, reachability, verified citations for/against, eligible-but-silent
coverage decline, human-outcome history). Every term and clamp is recorded in
`policy.json` — a suppression is always auditable back to its arithmetic.

Clamps are fail-safe in one direction only (they can raise p or force human
review, never lower p): crypto floor 0.50; deterministic floor 0.60 unless a
fully-verified defender showed the mitigating code; an unreliable panel
opinion caps p at 0.50 *and* flags human review; an attempted refutation that cited
nothing flags human review; missing cross-file navigation (the finding spans
several files but no panel opinion cited more than one — the published
96% → 44% failure mode) or an uncovered category flags human review.

**The word "calibrated" is banned** in code, docs, and reports. The default
weights are hand-set (`calibration: "prior"`), and the docs say so.

Since R7 an **opt-in fitted record** exists (`score.calibration: off | auto |
<path>`; default `off`): per-family `P(TP | semgrep detection)` measured on the
OWASP Benchmark corpus (`security-council calibrate`, see the packaged
`data/calibration-owasp-benchmark-java-1.2.json`). Its honesty rules are
structural: the record is a **trust boundary** (schema/scope validated, logits
clamped to ±2.5, low-n families dropped, any failure → prior with a manifest
note); it applies only to deterministic singletons inside the record's fitted
arm/language/family scope, replacing only the base — every clamp and guardrail
is untouched, and floors still censor low fitted values (rendered as
"measured X; deployed value raised by …"). A finding is labeled `fitted` only
when nothing but the fitted base contributed; a composed score stays `prior`
even though its base was measured. `auto` refuses the record when the run's
scanner version/ruleset don't match the record's pins. The record itself
carries its caveats (prevalence-conditional, templated-corpus split leakage,
case-level labeling) — read them before trusting the numbers cross-repo.

## The validator panel

Three seats on distinct vendor families — prosecutor, defender, adjudicator —
so one vendor's blind spot can't both produce and confirm a verdict.

**Be precise about what a "verified" citation proves.** Verification resolves
the *reference*: the path exists under the repo root and the line numbers fall
inside the file. It says nothing about whether the cited lines support the
claim. R10 found the consequence live — a defender citing `README.md:1-1` was
counted as a "fully verified defender", which cleared G2 and let a
semgrep-corroborated finding be refuted out of the CI gate.

So refuting is now gated harder than confirming, deliberately, because
refuting is the wrongful-suppression direction:

| Rule | Effect |
|---|---|
| **Anchored** | A defender's refutation counts only when a verified citation lands on the finding's own code — its `locations` ∪ `data_flow` steps, within ±25 lines, spanning ≤80 lines so a whole-file citation can't trivially intersect |
| **Refuting** | The defender must actually have voted `false_positive` — the function gating refutation previously didn't require the defender to be refuting |
| **Evidenced** | Only a fully-evidenced (`ok`) opinion may refute. `unevidenced` (cited nothing) and `unreliable` (cited badly) still count toward `true_positive`, the fail-safe direction, but never toward `false_positive` |
| **Independent** | Refuters must span ≥2 *distinct vendor families*, counted by family and not by seat |
| **Honest** | Any peer arguing `false_positive` off a fabricated citation forces `needs_human` — not just the seat holding the defender role |
| **Costly** | Malformed citations count against the pass rate instead of being dropped, which used to *raise* it by shrinking the denominator |

A blocked refutation is named in the report (`refutation_blocked`), so "two
peers voted to drop this and were not counted" is visible rather than silent.

This can't be solved by reference-checking alone — only claim-checking would
settle relevance — so the anchor is a narrowing, not a proof. What it removes
is the ability to refute anything while pointing anywhere.

## The eval gate (`security_council/eval/`, runs inside pytest)

A replay-based gate over a labeled ground-truth corpus: recorded raw output
from every arm family is replayed through the *real* normalize → cluster →
score → policy pipeline and matched against `EXPECTED.yaml`. The gate is
**zero-tolerance**: any ground-truth true positive ending demoted or hidden
fails CI — including under a fully-armed auto-suppression config with
adversarial hostile history injected. A deliberately wrong panel verdict is a
red test (the gate catches the published 22% failure mode by construction).

Honesty about scale: the corpus is currently 7 true positives + decoys. At
n=7 a "≤5% suppression rate" is meaningless (one wrongful suppression is
already 14%), which is exactly why the gate is zero-tolerance. Fitting uses a
separate, larger corpus (the OWASP Benchmark importer, R7) — and the gate is
additionally proven to hold under an adversarial minimum-logit record.

## What is *not* claimed

- No numeric false-positive-reduction rate — the corpus is too small to
  quote one honestly.
- The demo IDOR catch happened on this repo's own 12-file fixture, not a
  customer codebase.
- Prompt-injection resistance is a tested regression (the fixture carries a
  labeled canary), not a guarantee.
- Decision signatures attest authorship and integrity, not correctness, and
  only protect a store whose paths are behind required review; an insider
  who can edit `allowed_signers` unreviewed can sign anything.
