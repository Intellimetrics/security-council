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
| I9 | Finding ids are derived from fingerprints and verifiable — an id can't be forged to collide a decision onto a different finding |
| I11 | SARIF suppressions / VEX `not_affected` may only appear on closed lifecycles — no export can *show* suppressed what the model holds open |

## Guardrails G1–G8 (`policy.py`)

| | Rule |
|---|---|
| G1 | Crypto never auto-suppressed (backed by a scoring floor: crypto p ≥ 0.50) |
| G2 | An LLM panel alone cannot refute a deterministic-scanner finding — without a defender whose *every* citation verified against the repo, the finding escalates to `needs_human` (which still fails the gate) |
| G3 | Every suppression fully attributed (see I6) |
| G4 | First 5 armed runs are shadow mode; the counter counts only armed runs and resets on suppression-config change |
| G5 | Decisions scope to one root-cause fingerprint — never a rule, CWE, or glob |
| G6 | Suppressions expire (90 days) → the finding reopens |
| G7 | Critical severity never auto-suppressed |
| G8 | Context drift (the code around the finding changed) → the decision deactivates permanently and the finding reopens for re-validation |

Plus the meta-rule: **demote, never auto-close.** A refuted finding leaves
the CI gate but stays open, renders as SARIF `suppressions[underReview]`, and
appears in the summary's appendix.

## Scoring (`score.py`) — transparent, and honest about calibration

p(true positive) is an additive log-odds model: prior −1.2 plus seven named
terms (vendor-family corroboration, deterministic corroboration, adjudicator
verdict, reachability, verified citations for/against, eligible-but-silent
coverage decline, human-outcome history). Every term and clamp is recorded in
`policy.json` — a suppression is always auditable back to its arithmetic.

Clamps are fail-safe in one direction only (they can raise p or force human
review, never lower p): crypto floor 0.50; deterministic floor 0.60 unless a
fully-verified defender showed the mitigating code; an unreliable panel
opinion caps p at 0.50 *and* flags human review; missing cross-file
navigation or an uncovered category flags human review.

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
so one vendor's blind spot can't both produce and confirm a verdict. Evidence
rules: citations are re-verified against the repository; an opinion with no
verified citations carries no weight; **a defender that fabricates a citation
is the classic wrongful-suppression vector, and it forces `needs_human`**
rather than a refutation.

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
- The decision store is target-local and unsigned; git review is the audit
  trail.
