# R11 — The fix lane, the fence, and two gaps in the R10 fix

- **Date:** 2026-08-25 · **Mode:** quick · **Quorum:** met (2/3)
- claude **tradeoff** (341.8s, risk high) · antigravity **tradeoff** (98.8s,
  risk critical) · codex **timeout at 600s**
- Brief: `.llm-council/inputs/r11-fix-lane/brief.md` · transcript
  `.llm-council/runs/20260825_104500_*`

Codex has now timed out in three consecutive rounds — at 240s twice and at
600s here, on a 2.7 KB prompt. Treat codex as unavailable for council in this
environment rather than as a peer that merely needs more time.

## It found two gaps in the R10 fix shipped hours earlier

**1. The anchor rule never ran in the panel.** R10 enforced anchoring only
through `_fully_verified_defender` → G2, and G2 applies only when
`corroboration.deterministic_sources` is non-empty. The panel's own refuter
gate asked for `status == "ok"` and nothing else. So an **agent-only** finding
— the cross-file IDOR shape this project exists to catch, and the one class
G2 cannot help — was still refutable by peers citing `README.md:1-1`.
Reproduced, then closed: `_refutation_block_reason` now gates every
refutation at the panel, and a blocked one is reported as `unanchored`.

**2. Unmapped peers passed as distinct vendor families.** `FAMILY_BY_PEER`
fell back to the *participant name*, so two peers absent from the map counted
as two independent families and could carry the refutation quorum. Unmapped
peers are now bucketed as `"unknown"`; `participant` still names them.

Both now have regressions that fail without the fix.

## Fix-lane defects found and fixed

- **A hedged verdict counted as a fix.** `_parse_verdict` substring-matched, so
  *"could not determine whether this is fixed"* returned `fixed`, as did
  *"unable to confirm it is remediated"*. Hedges now return `unproven`.
- **`independent` was hardcoded `True`** in the verify evidence, directly under
  a comment saying it must be false when the verifier shares the fixer's vendor
  family — while the orchestrator passes `family=arm.family`, i.e. *always* the
  same family. Now computed from a new `fix_family`; unknown ⇒ not independent.
- **The env deny list could not remove anything.** `_ENV_DENY_SUBSTR` is
  labelled "never pass these, even if a broad rule would", but the allowlist
  exempted every key matching a vendor prefix, and all three `_VENDOR_ENV_KEYS`
  match one. `CODEX_GITHUB_TOKEN` and `ANTHROPIC_AWS_SECRET` rode in on their
  prefix. Deny now wins; only the enumerated vendor keys and caller `extra_keys`
  are exempt (none contain a denied substring).

## Q1 — my framing was challenged, and I did not change the fence

I proposed redefining the fence as "filesystem containment, not exfiltration
control" for a lane whose purpose is egress. Council's answer, with receipts:
`docs/arms.md:129-134` tells users the fix lane runs with **no network** and
that a canary proves it, and `docs/data-boundaries.md:11-21`'s "what leaves
your machine" table has **no row for the fix lane at all** — despite `fix.py`
sending the scanned tree to a vendor CLI. Relaxing the fence while those
statements stand would remove a promised property and deepen an existing
omission.

So the fence is unchanged. Instead the lanes now **refuse honestly up front**:
`fence.reachable_in_fence()` resolves the CLI through its symlinks and checks
it against the bind set, and `FixArm.available()` / `VerifyFixArm.available()`
return a precise reason rather than burning minutes and vendor spend to end in
a vague `no_patch`. Same for the M-V3 analysis lane, which now states that its
skills are internal phases of `codex-security scan` rather than emitting an
artifact stamped with provenance we cannot support.

Council also noted that node-installed `codex` is a shim needing the node root
and `lib/node_modules`, so binding `~/.nvm/.../bin` alone would not have fixed
blocker #1 anyway.

## Q4 — the recommended direction for verification

Both peers converged on this and it is the most useful outcome of the review:
asking a model whether its own vendor's patch worked is worth little. The
verification that costs nothing and proves something is **deterministic**:
re-run the scanners against the patched tree and require the finding to
disappear, with the model only *explaining* the result. That needs no
credentials, no network, and no fence exemption — which dissolves most of Q1.

Not implemented; it is the design this lane should be rebuilt on.

## Fence defects recorded, NOT fixed

The lane is disabled by `available()`, so these are latent, not live. All were
verified in code:

- `certify()` builds its canary argv with the default `allow_network=False`
  and a *different* `home` than the run uses, so the canary never tests the
  posture the run will use.
- `fix.py` checks only `cert is None` — `cert.live()` and `cert.config_hash`
  are never used, contradicting the guarantee stated at `fence.py:68-70`.
- `_config_hash` strips path arguments but keeps flags, so different bind
  scopes hash identically; its `/tmp/` filter is `TMPDIR`-dependent.
- The canary probes `~/.ssh/id_rsa` and `getent hosts`, both of which fail
  benignly on a host lacking either — no positive control, so the canary can
  "pass" without proving anything.

## Still open, and they are the user's calls

- **Q3** — whether to abandon our harness for `codex-security patch` /
  `scan --patch` (vendor sandbox, lose the pristine-vs-work diff) or keep
  driving the CLI ourselves. Unverifiable here regardless: `codex-security`'s
  stored credentials are stale and need an interactive login.
- **M-V3** — reframe the analysis lane onto our own house prompt (works across
  all three CLIs, honest provenance) or drop it.
