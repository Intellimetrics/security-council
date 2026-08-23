# R5 — Complete vendor-workflow scope (2026-08-23)

Consensus-mode council on exposing the FULL vendor built-in security-workflow
surface (the maintainer's stated "main point"), completeness prioritized over
speed. claude ("yes"/for) and antigravity ("tradeoff"/neutral) **converged**;
codex timed out at 792s (quorum 2/2, not degraded, $0). Transcript:
`.llm-council/runs/20260823_064028_612187_ff80361c054843ea8b01978f39506221.md`.
Contracts below re-verified against the installed packages after the run.

## Consensus (both peers)

**Integration shape — NOT a generic passthrough, NOT MCP-mount-as-primary.**
Both peers independently rejected the "run any of them via passthrough" shape:
it bypasses normalize → cluster → disposition and the I1–I12 invariants,
creating a split-brain where the vendor CLI's own state disagrees with our
system of record. Shape = **per-vendor job-parameterized dedicated arms
(scan-shaped jobs) + one artifact runner per vendor (analysis/fix jobs)**;
the vendors' bundled MCP servers are a documented per-workflow *fallback*
transport only, never the primary path.

**Three lanes by workflow shape:**
- SCAN-type → flows through the finding model (I1–I12).
- ANALYSIS-type → attaches as a manifest-indexed artifact; never touches
  `findings.json`.
- FIX-type → `.patch` artifacts on the scratch copy; **never applied** to the
  user tree.

**Skip the state-management overlaps** (documented as deliberate decisions, not
gaps): vendor `triage`/`validation`, `scans`/`track-findings`, `findings` (FP
marking), `export` — each forks our validator panel / baseline / I6-attributed
decision store / D7-withholding exporters. (claude peer: `validate`/`triage`
*may* be admitted later only as non-independent extra panel voters.)

**Model tier = one orthogonal layer**, not per-workflow: populate the existing
`ProvenanceEntry.entitlement`/`safeguard_posture`, declare (CLI, tier, model)
in config, inject `--model` into any arm. GA default (codex `gpt-5.6-sol`,
claude Fable); Mythos/Daybreak stamp `safeguard_posture: relaxed`; Red
(`gpt-5.6-cyber`) refused for ALL workflows until the D5 authorization block
exists. codex never attests its served model → a requested gated tier there
always renders "unattested".

**Must NOT build / must gate:** no fix application to user code (no `--apply`);
no PoC generation/execution (Red deferred, D5); no vendor decision/tracking
state or vendor export egress; `vulnerability-writeup` + `attack-path-analysis`
are dual-use → gated + `raw/`-resident + export-excluded by default; verify-fix
is human-mark evidence only, never auto-close.

## Verified invocation contracts (post-run)

- `codex-security scan --diff <base> --head <ref>` and `--working-tree` EXIST →
  **security-diff-scan = the existing arm + params** (not a new class).
- `--mode deep` (deep-security-scan) and `--model`/`--effort` (tier knob) are
  existing `scan` params.
- claude-security `scan-changes` job = the same scan workflow over a diff/commit
  (gate-collapse prompt, needs a live spike — recipe may not transfer verbatim).
- `threat-model`/`attack-path-analysis`/`vulnerability-writeup` are separate
  phase-skills with NO CLI subcommand → session/plugin/MCP invocation, artifact
  lane. (threat-model's own SKILL.md: standard/deep scans build their threat
  model internally and do not invoke the standalone skill.)

## Adopted scope table

| Vendor workflow | Lane | Note |
|---|---|---|
| codex security-scan / claude scan-codebase | finding-model | wired |
| codex deep-security-scan | finding-model | `--mode deep` (already a param) |
| codex security-diff-scan / claude scan-changes | finding-model | diff lane — `--diff`/`--working-tree`; pairs with `gate_baseline: new` |
| codex threat-model | artifact | repo context doc |
| codex attack-path-analysis | artifact, gated | dual-use; export-excluded |
| codex propose-security-hardening | artifact | recommendations |
| codex define-security-policy | artifact | policy proposal (≠ our policy.py) |
| codex vulnerability-writeup | artifact, gated | dual-use; `raw/` only, export-excluded |
| codex fix-finding / claude suggest-patches | artifact, gated | `.patch` on scratch copy, never applied |
| codex verify-fix | decision-evidence, gated | human-mark evidence only; never auto-close |
| codex finding-discovery | skip | internal scan step |
| codex triage-finding / validation | skip (opt. panel voter) | overlaps validator panel |
| codex track-findings / `scans` | skip | overlaps baseline/delta + decision store |
| codex `findings` (FP mark) | skip | bypasses I6 decision store |
| codex `export` | skip | bypasses D7 withholding |
| bundled MCP servers | fallback only | per-workflow transport for no-CLI skills; never default-mounted |

## Milestone ordering (adopted — claude peer's, entitlements early)

The one disagreement was where entitlements go (claude: 2nd so later lanes
inherit it; antigravity: last). Adopted **claude's** because the maintainer
named gated-tier access as a core goal — doing it early means every later
workflow inherits the tier knob for free.

1. **M-V1 Diff lane** — codex `--diff`/`--working-tree` + `--mode deep`
   first-class; claude `scan-changes`; job-aware `CATEGORY_POLICY` (a diff not
   reporting a category = absence-of-scope, not "suppresses"); scan-scope in
   the manifest so baseline/delta handles partial scans; per-job cost fuses,
   default-off.
2. **M-V2 `entitlements.py` + tier knob** — 4-rung probe ladder (never reads
   keys), config declaration, populate provenance, Red refusal until D5.
3. **M-V3 Artifact lane** — manifest artifact index (none exists today),
   summary appendix links, per-artifact provenance; threat-model,
   attack-path-analysis, propose-security-hardening, define-security-policy,
   vulnerability-writeup (export-excluded).
4. **M-V4 Fix lane (gated, council-reviewed before landing)** — suggest-patches
   + fix-finding as `.patch` artifacts; verify-fix as decision evidence.
5. **M-V5 (optional)** — vendor validate/triage as non-independent panel voters.
6. **Documented skips** — recorded as a locked decision.

## Prerequisites flagged (carry into M-V1)

- `CATEGORY_POLICY` is keyed by arm name → diff jobs need per-job rows or diff
  findings mislabel as singleton/uncovered.
- No artifact index in `manifest.py` → M-V3 must add one.
- Diff-scan × baseline/delta × G6/G8 reopen across partial scopes is the
  subtlest correctness surface — test it hard in M-V1.
- Each job needs its own budget fuse and must default off.
