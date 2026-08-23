# Contributing

security-council is source-available under a proprietary license (see
[LICENSE.md](LICENSE.md)); issues and security reports are welcome, code
contributions are accepted at the maintainer's discretion. If you plan a
change, open an issue first.

## Working conventions (enforced by review)

- **Runtime is stdlib + pyyaml only.** No new runtime dependencies without a
  design discussion; `mcp` stays an optional extra, `jsonschema` stays
  test-only.
- **The finding model is the trust surface.** Every producer/exporter
  boundary calls `assert_invariants` (I1–I12, `model.py`) — fail closed. Do
  not weaken an invariant without reading `docs/reviews/R1-*.md` first.
- **Verify external contracts before coding against them** (the R3 rule).
  eMASS, GitLab, and SARIF exports each carry a vendored schema under
  `tests/fixtures/schemas/` with provenance; new export targets must do the
  same.
- **Never write the word "calibrated"** in code, docs, or reports unless
  `calibration == "fitted"` (`score.py` explains why).
- Tests + `ruff check security_council/ tests/` must be green:
  `python3 -m pytest tests/ -q`. The eval gate
  (`tests/test_eval_gate.py`) is part of the suite — a change that wrongly
  suppresses a ground-truth true positive fails CI by design.

## Adding a scanner/LLM arm

1. Implement the arm in `security_council/arms/` and register it in
   `arms/registry.py`.
2. Add a normalization adapter under `normalize/sources/` returning findings
   that pass `assert_invariants`.
3. **Add a `coverage.CATEGORY_POLICY` row (or `POLICY_ALIASES` entry)** — an
   arm without one is `unknown` for every category and its findings mislabel
   as singleton/uncovered.
4. Add real-shaped fixtures under `tests/fixtures/raw/` and wire them into
   the eval runner (`security_council/eval/runner.py`) so the gate covers the
   arm.
5. Document cost, prerequisites, and data-boundary behavior in
   `docs/arms.md` and `docs/data-boundaries.md`.

## Repo hygiene

- Run outputs (`**/.security-council/`), scratch (`.spikes/`), and the
  project venv (`.venv/`) are gitignored — never force-add them.
- The fixtures are intentionally vulnerable (see [SECURITY.md](SECURITY.md));
  changes to `tests/fixtures/seedrepo/` must keep `EXPECTED.yaml` truthful,
  since it is the eval gate's ground truth.
