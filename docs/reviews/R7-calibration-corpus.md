# R7 — Calibration corpus lane (OWASP Benchmark importer + first fitted record)

- **Date:** 2026-08-24 · **Mode:** quick (llm-council MCP) · **Quorum:** met (2/3)
- **Peers:** claude **yes** (216s) · antigravity **tradeoff** (77s) · codex **timeout**
  (the reliable-in-this-env failure; quorum reached without it, run NOT degraded)
- **Recommendation:** leaning-yes → built with the reconciled conditions below.
- **Transcript:** `.llm-council/runs/20260824_053608_*` · brief:
  `.llm-council/inputs/r7-calibration-lane/design-brief.md`

## What was reviewed

The last §8 roadmap item: convert OWASP BenchmarkJava (2,740 labeled Java cases)
into ground truth, run the real pipeline over it, fit per-family
`P(TP | semgrep detection, family)`, and integrate a fitted record into
`score.py` without weakening any guardrail or overstating calibration honesty.
Recon facts fed to council: GPL-2.0 license (→ converter-only, never vendored);
only semgrep is Java-capable among our deterministic arms (→ only the
deterministic-singleton base is fittable, NOT the seven-term model); measured
scorecard precision — crypto 1.000 (437 det.), xss 0.65, injection 0.56,
path_traversal 0.53; 41% of in-corpus clusters span true AND false test files
(generated near-twin code → case-level labeling, Benchmark's own convention).

## Decisions (both peers converged)

| Q | Decision |
|---|---|
| Q1 scope + labeling | Option **(b) + (d)-lite**: fitted base may sit under prior-weighted panel terms, but the per-finding `calibration` label is `"fitted"` ONLY when no other term contributes; composed scores stay `"prior"` with the record id kept in the score breakdown. The (d)-lite render (new surface: unvalidated in-scope singletons) shows the **post-clamp** p with the clamp named. |
| Q2 shipped default | **Opt-in** (`score.calibration: off` default). `auto` applies the packaged record only when the run's semgrep **version + ruleset match the record's pins**, else prior + manifest note. Scope is **language-gated** (Java) so Benchmark numbers never touch non-Java findings. |
| Q3 guardrails | Confirmed p-independent: demotion (panel-triggered), exit gate (severity/state), crypto guardrails. **One real corner found:** post-refutation suppression checks `p <= suppress_below`, and the deterministic floor is waived exactly when a fully-verified defender exists — a low fitted base can convert demote → suppress there. Bounded by: loader logit clamp (±2.5), adversarial-record eval-gate test, action-delta assertion (both landed). Empirically moot for this record: all four fitted logits ≥ the prior base, so it only raises p. |
| Q4 family table | `CWE-643 → injection` as its **own trust-surface commit** (I4 interaction — confirmed live: the pre-mapping corpus run failed I4 on re-ingest and had to be re-scanned). 501/614 stay unmapped; enlarging a reviewed trust surface to grow a corpus's coverage is the wrong causality. |
| Q5 floors over fit | Floors stay (action-gates, not probability estimates). The 0.60 deterministic floor **censors the whole (d)-lite population** below it — record carries per-family `floor_binding`, rendering says "measured X; deployed value raised by …", ECE reported pre- AND post-clamp. |
| Q6 structure | Sound; presentation fixes: per-category counts inside each family entry (sqli/cmdi skew visible), prevalence-conditional caveat (~50% real by construction), split-leakage caveat (templated near-twins → effective n < nominal, CIs/ECE flatter), exclusion audit (noise, unmapped categories). Laplace+Wilson kept (stdlib; Jeffreys noted as the cleaner construction). |

**New trust boundary (claude peer, severity high):** the record is data that
injects logits into the scorer. Loader validates schema+scope, clamps logits to
±2.5, drops families under min-n, and fails closed to the prior with reasons in
the manifest. The word "calibrated" stays banned everywhere; rendered-output
tests enforce it.

## What landed (commits R7 1–4)

1. `CWE-643 → injection` (`model.py`) + pin test.
2. `eval/import_owasp.py` converter (GPL-safe, strict integrity) + self-authored
   format-only fixtures; one matcher shared with the eval gate.
3. `eval/calibrate.py` (case-level labels, per-family fit, Wilson, dual ECE,
   caveats in-record) · `calibration.py` runtime (loader/resolve/base_for/
   fitted_scores) · `score.py` fitted_base + strict-label rule · manifest/
   summary surfaces · adversarial + inert eval-gate tests.
4. `security-council calibrate` CLI · packaged record
   `data/calibration-owasp-benchmark-java-1.2.json` (semgrep 1.173.0, p/default,
   corpus sha `0db793a`) · docs.

**Fitted record (held-out):** crypto p=0.995 (n=216, deploy-clamped to 0.924) ·
xss 0.654 · injection 0.549 (floored 0.60) · path_traversal 0.500 (floored
0.60) · ECE 0.022 pre-clamp / 0.018 post-clamp · Brier 0.179. Live `auto` run
on the corpus: 284 findings fitted, clamp warning rendered, exit gate unchanged.
