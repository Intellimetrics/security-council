# R9 — Decision-store trust: signing, sync, and a live gate bypass

- **Date:** 2026-08-24 · **Mode:** quick (llm-council MCP) · **Quorum:** met (2/3)
- **Peers:** claude **tradeoff** (280s) · antigravity **tradeoff** (127s) ·
  codex **timeout** (the reliable-in-this-env failure)
- **Transcript:** `.llm-council/runs/20260824_101021_*` · brief:
  `.llm-council/inputs/r9-decision-store-trust/design-brief.md`

## What was asked

How to sign and share the decision store (suppressions, human outcome marks,
shadow counter, baseline) given the stdlib-only runtime — options A HMAC,
B `ssh-keygen -Y`, C optional `cryptography`, D git-native signed commits —
plus enforcement default, rollback protection, cross-repo binding, and what
must never be importable.

## The headline: council found a live, exploitable bypass

Not a design gap — a working exploit in shipped code. Under
`gate_baseline: "new"` (exactly what the `ci` and `gov` profiles set), a
hand-written `baseline/latest.json` naming the current findings marks them
`unchanged`, and `_exit_code` excludes those from the gate. The root-cause
fingerprints it needs are **published in every SARIF report**, so the attacker
needs no inside knowledge. **Reproduced live** against the real CLI before
fixing: exit 1 → exit 0, one file, no crypto, whole gate off.

Council's ranking was blunt and correct: *five zero-crypto fixes beat the
entire signing lane on ROI, and the signing lane should land behind them.*

Two more verified holes in the same area:

- **G1/G7 bypass on the replay path.** `apply_policy` short-circuits on
  `CLOSED_LIFECYCLES` before `_suppression_guardrails`, and I7 forbids crypto
  hiding only when `decided_by.kind != "human"`. So a hand-written record
  claiming `kind: "human"` passes `assert_invariants` and permanently hides a
  crypto or critical finding — something auto-suppression is *structurally
  forbidden* from doing.
- **`DecidedBy(**sup["decided_by"])` raises an uncaught `TypeError`** on any
  unexpected key: a malformed store crashed the whole scan instead of degrading.

Council also corrected an error in our own brief: the score history term is
`(confirmed_tp − confirmed_fp)`, so *importing* false-positive marks and
*deleting* true-positive marks are the dangerous directions — the brief had
deletion backwards.

## Decisions

| Q | Decision |
|---|---|
| Q1 signing | **B (`ssh-keygen -Y`)** when the lane lands: asymmetric, no new Python dep (consistent with D2 "shell out, don't import"), reuses SSH keys the forge already knows, and works for local-only stores. Reject **A** (HMAC: to verify in CI you must give CI a forging key — it fails against the CI-laundering threat on its own terms), reject **C** (`cryptography` extra costs the stdlib-only value and invents key management). **D** (git-native `verify-commit`) optional later; it dies on dirty trees, shallow checkouts, and squash-merges. Two hard requirements: bind the signing principal to `decided_by.operator`, and fail closed when the verifier is missing. |
| Q2 enforcement | Per-store, not global: new stores start `enforce`, pre-existing get `warn` + sunset; `ci`/`gov` profiles `enforce`. `warn` must be loud (manifest + report), or it is functionally `off`. |
| Q3 rollback | **Drop** the signed `index.json` + `seq` — a hot file every write touches, merge-conflicts constantly, and is itself rollback-able. The signed absolute `expires_at` is the replay bound; `prior_decisions` in each run manifest already gives a local anchor. Residual: replay inside the unexpired window. |
| Q4 cross-repo | Bind suppressions to a store id. A code-location suppression's justification is intrinsically about *this* codebase. The legitimate org-wide case ("CVE-X not-affected for this dependency") is a **different object** — a purl+CVE VEX statement, not a root-cause suppression; don't overload one record across two trust semantics. `--accept-foreign` requires local re-signature, expiry clamped to ≤30d, origin recorded, crypto/critical never accepted, and a double-gate flag. |
| Q5 never importable | Confirmed: `outcome_mark` history (feeds the score prior) and `policy_state.json`. Enforce as an **allowlist** of importable event kinds, not a denylist. |
| Q6 structure | Sign **events, not records** — a record mixes human and machine writes, so whole-record signing would force a signing key onto CI runners (the exact credential the threat model excludes). Also: signing creates false confidence unless the report renders **provenance, never assurance**. |

**The framing correction worth keeping:** no mechanism A–D stops an insider
with repo write access, because all four anchor trust in a file that insider
can also write. Signing is only load-bearing when `allowed_signers` and the
store paths are covered by CODEOWNERS + required review. Absent that, the lane
is theater — what it genuinely buys is a reviewable chokepoint, detection of
tampering *outside* a reviewed commit, and per-person attribution.

## What landed now (commit `aa4296d`)

All five zero-crypto fixes, ranked by council's safety-per-complexity:

1. **G9 `high_assurance()`** — crypto and critical generalized from the
   auto-suppression path to every gate-removal path. A baseline can never
   excuse them; stored suppressions of them run on a **30-day** leash (not 90).
2. **Baseline integrity digest** — `baseline set` pins a content hash over the
   identity fields; a mismatched *or missing* digest means the baseline is
   refused entirely, and no baseline means everything gates. Explicitly a
   tripwire, not a signature.
3. **Shadow counter** = `min(stored, real sibling run dirs)`.
4. **Malformed records degrade**, never crash; unusable decisions aren't applied.
5. **Per-suppression provenance in the report** — who, when, expires, times
   reapplied (≥5 flagged stale) — replacing the aggregate count.

15 regressions in `tests/test_store_hardening.py`, including an end-to-end
reproduction of the original bypass.

## Still open (the signing lane proper)

Design is settled by this review; implementation is the next milestone.
Until it lands, the honest statement is: **the store is tamper-evident, not
tamper-proof.** An attacker with write access can still recompute the digest
and forge an ordinary (non-crypto, non-critical) suppression or baseline entry.
Teams that need more should commit the store and require review on those paths.
