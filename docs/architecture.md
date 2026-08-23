# Architecture

## Pipeline

```
isolate (scratch copy) → parallel arms → normalize → cluster (root cause)
  → category-aware coverage → decision-store replay (reapply/expire/drift)
  → [optional] cross-vendor validation → score (log-odds p_true)
  → disposition policy (G1–G8) → baseline delta
  → exports: SARIF (merged+raw) · summary.md · policy.json · manifest.json
  → exit code
```

Everything after the arm fan-out is pure and replayable from a run's raw
outputs — the eval gate exploits exactly this.

## The finding model is the trust surface

`model.py` defines one canonical `Finding` (taxonomy, severity, locations,
data flow, fingerprints, provenance, corroboration, validation, disposition,
remediation, compliance). Every producer adapter and every exporter passes
through `assert_invariants` (I1–I12) — the safety guarantees live in the
*data model*, not in the goodwill of callers. `findings.json` is the system
of record; SARIF, eMASS, and GitLab reports are projections of it through one
disposition-rendering rule (`export/__init__.py:open_unresolved`) — decision
D7: change a disposition and every export changes consistently.

## Fingerprints and clustering

Three content-derived fingerprints per finding, none containing raw line
numbers (line drift must not change identity):

- `pathCweSink/v1` — path + canonical CWE + enclosing symbol/normalized sink
- `contextHash/v1` — ±3 lines, whitespace-collapsed, comments dropped,
  literals masked
- `rootCause/v1` — family + source symbol + sink expression (or package +
  advisory for SCA)

Clustering is union-find over tiered joins (shared root cause → CWE-gated
line overlap → context hash → package), so five arms reporting the same flaw
five ways become **one** finding with five provenance entries. Single-source
clusters are kept — corroboration is a score input, not an admission gate.

## Normalization

Per-producer adapters (`normalize/sources/`) with an explicit registry:
generic SARIF (semgrep/gitleaks/osv), our strict agent envelope
(house-prompt arms), the claude-security report, the codex-security sealed
bundle. Shared passes: 5-layer CWE normalization with crypto-stickiness,
severity derivation (CVSS wins; SARIF level always derived), repo-relative
path hardening, and snippet capture that **drops findings whose claimed
location doesn't resolve** (hallucinated locations die at the boundary,
counted). Secret-bearing snippets are redacted at ingestion — hash kept,
text never stored.

## Validator transport

The panel shells out to `llm-council run --json` as a subprocess (decision
D2) — never `import llm_council` — so the validator backend can evolve
independently. Verdicts come from explicit `VERDICT:` lines; citations are
re-verified against the tree before they count.

## Decision store & baseline

`<target>/.security-council/decisions/by-root-cause/<fp>.json` — append-only
history per root cause, atomic writes. On every scan, stored suppressions are
reapplied *before* validation (no validator budget on suppressed findings),
with expiry and context-drift reopening (G6/G8). The baseline is a separate
operator-set snapshot used to stamp SARIF `baselineState` and drive
`gate_baseline: new`. See [triage.md](triage.md).

## MCP server

`security-council-mcp` exposes the surface as `sc_*` tools ([mcp.md](mcp.md)).
Two hard guards: paths must resolve inside `SECURITY_COUNCIL_MCP_ROOT`
(absolute-only), and the presence of `SECURITY_COUNCIL_NESTED` (set for every
arm subprocess) makes `sc_scan` refuse — an agentic arm that discovers the
server cannot recursively scan.

## Relationship to llm-council

security-council is derived from — and depends on, but does not fork —
[llm-council](https://github.com/Intellimetrics/llm-council). The validator
panel is a specialization of llm-council's `consensus` mode; the MCP server
follows its `_serve` pattern.

## Repository map

```
security_council/
  model.py jsonio.py          # canonical model + invariants; (de)serialization
  fingerprint.py cluster.py   # identity + root-cause clustering
  normalize/                  # adapters, CWE/severity/paths/snippets, coverage
  arms/                       # scanner, house-prompt, dedicated agentic arms
  validate/                   # panel via llm-council subprocess
  score.py policy.py          # log-odds confidence + guardrails G1-G8
  decisions.py                # decision store, baseline, shadow counter
  eval/                       # replay eval gate (metrics + runner)
  export/                     # sarif, markdown, emass, gitlab
  ci/                         # azure_devops, gitlab glue
  orchestrator.py cli.py mcp_server.py workspace.py manifest.py config.py
templates/                    # ADO + GitLab CI templates; action.yml at root
tests/fixtures/               # seedrepo (intentionally vulnerable), recorded
                              # arm outputs, vendored official schemas
```
