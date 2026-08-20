# Council review R1 — finding model + agent envelope (2026-08-20)

Mode: consensus (claude/codex/antigravity, ~11min). All three independently
converged on the SAME defect set (labels yes/no/tradeoff were assigned stances,
not real disagreement). Transcript gitignored under `.llm-council/runs/`.

## Fixed in model.py (guardrail-evasion — all confirmed, several reproduced)
- **Crypto sticky (I4/I7):** family/guard no longer key on `cwe[0]` alone.
  `is_crypto_finding()` fires if ANY cwe is in `CRYPTO_CWES`; I4 rejects a crypto
  CWE mislabeled to a non-crypto family. Closes `cwe=["CWE-79","CWE-327"]` bypass.
- **Fail-closed decision kind (I6/I7):** `decided_by.kind` validated ∈ {auto,human};
  anything not an explicit `human` decision is treated as auto for attribution and
  the crypto guard. Closes `kind="system"` bypass (codex reproduced `== []`).
- **I7 covers accepted_risk**, not just suppressed; auto `fixed` requires
  `baseline_state == "absent"` (never auto-close).
- **Strong attribution (I6):** `prompt_sha256`/`panel_sha256` must be sha256-shaped;
  `expires_at` must parse as RFC3339 (rejects "never").
- **I11 (new):** `sarif_suppression`/`vex_status in {not_affected,fixed}` require a
  closed lifecycle; `not_affected` requires an OpenVEX justification; affected/
  under_investigation require an open lifecycle. Closes "export as suppressed while
  lifecycle=open with zero attribution".
- **I12 (new):** panel evidence citations validated (repo-relative POSIX, in-bounds).
- **I1 extended** to `data_flow[*].location`; **I5** rejects unknown labels;
  **I2** requires `prompt_sha256` only for agent_cli (sha-shaped), not scanners.
- Removed dead `CWE-732-config` key (canonicalization made it unreachable).
- 10 regression tests added (28 total green).

## Fixed in schemas/agent_finding_envelope.v1.json
- Stripped `$schema` + strict-mode-incompatible keywords (minItems/maxItems/
  maxLength/minimum/maximum/pattern) — codex `--output-schema` and Claude strict
  mode reject them; bounds enforced by the normalizer + invariants instead.
- Added `scan.completion` (complete|partial|declined) so the empty-findings
  coverage guard is structural. Added `data_flow.end_line`+`role` so envelope
  data-flow maps cleanly to `CodeLocation`.

## Deferred to exporters/normalizer (tracked, not model.py)
- OpenVEX: SAST findings need a synthetic `vulnerability.name` (e.g. `CWE-89@<rootcause>`)
  + product purl -> `export/vex.py`.
- OSCAL: derive UUIDv5 from `finding_id`; map `operator` -> party-uuid -> `export/oscal.py`.
- SARIF `fixes` need diff geometry (deletedRegion/insertedContent) — add to
  `Remediation` when the remediation lane lands (M3).
- Normalizer must map envelope `confidence` -> scoring input, `entry_point` ->
  `reachability.entrypoints`, `exploit_precondition` -> description/validation;
  don't drop them into `raw_ref`.
- **assert_invariants must be called at every jsonio/export/decision-store boundary**
  — invariants are a function, not `__post_init__`; that call is what makes them
  structural. Enforce in those modules + a test.
- Claude `--json-schema` with this exact envelope not yet spiked (only codex/agy).
