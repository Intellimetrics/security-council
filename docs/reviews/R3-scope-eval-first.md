# R3 — Scope review: eval gate before the decision store (2026-08-22)

Council run on the post-`score.py`/`policy.py` roadmap (HANDOFF §8, then ordered:
decision store → gov exporters → MCP/CI → eval harness). Mode `quick`, participants
claude + antigravity (codex timed out at 406s; quorum 2/2 labeled, not degraded, $0).
Transcript: `.llm-council/runs/20260822_072853_032493_49f6408d218d440ba89c2a10e9d6139b.md`.

## Verdict (both peers converged, label `tradeoff`)

The four items are the right scope, but the ordering was half wrong: **the eval
gate must come before `decisions.py`**. The decision store feeds the `history`
score term → raises p → grounds suppressions → writes outcomes back into the
store: a self-reinforcing feedback loop on seven hand-set weights never checked
against ground truth. The published failure mode this project cites (22% wrongful
TP suppression, >50% crypto) is exactly what the gate measures — and it costs ~$0
here because `tests/fixtures/raw/` (recorded output for every arm family) and
`tests/fixtures/EXPECTED.yaml` (`kind`, `must_not_demote`, decoy `must_end_as`)
already exist.

Nuance adopted from the claude peer over antigravity: **split the eval item** —
build the replay-based *gating* half now, defer *calibration fitting* (fitting 7+
weights on a 7-TP corpus overfits meaninglessly), and gate on **zero** violations
rather than ≤5% (not statistically resolvable at n=7; one wrongful suppression is
already 14%).

## Adopted ordering

1. Minimal replay-based eval gate (zero TP demotion/suppression, crypto 0%).
2. `decisions.py` + `outcome mark` **+ baseline/delta** (missing from the roadmap
   entirely — §7.8 lists it, §8 never scheduled it; it is the CI-template adoption
   blocker on brownfield repos: first scan of any real repo fails the gate forever
   without it).
3. eMASS static-code-scans exporter (pure render per D7, zero policy risk, the
   strongest DoD demo artifact) — ahead of MCP/CI.
4. `mcp_server.py` + Azure DevOps template — last unless a pilot is scheduled.
5. Calibration fitting — deferred until a larger corpus; `calibration: "prior"`
   stays honestly labeled.

## Risks to carry into implementation

- The eval replay must include a **validated-run input** (panel-verdict fixture),
  otherwise only the no-op branch of `apply_policy` is exercised.
- When `decisions.py` lands, re-run the gate with **adversarial history counts** —
  `W_HISTORY` must not push a borderline decoy past `suppress_below`.
- Moving shadow counting from directory census to a stored counter **flips its
  fail-safe direction** (census can only under-count = safe); the counter should
  reset on policy-config change (arguably a G8 drift event). Don't burn the 5
  shadow runs on uncalibrated scores (antigravity).
- SCA validator gap (HANDOFF §7.1) will skew eval metrics if a future corpus is
  dependency-heavy; fine for the current SAST-shaped seed corpus.
- eMASS: verify field names against a real import template/spec sample before
  building — eMASS import formats are notoriously picky.
