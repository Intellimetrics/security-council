# Data boundaries

**Who this is for:** anyone with code that mustn't leak — and required reading for government/regulated environments before enabling any AI arm.

**Read this page before scanning anything sensitive.** security-council's
arms differ radically in what they send off your machine, and the difference
is the whole point of the deterministic-by-default design.

## What leaves the machine, per arm

| Arm | Kind | What leaves your machine |
|---|---|---|
| `semgrep` | scanner (docker/local) | Nothing from your code. Fetches rules over the network at scan time. |
| `gitleaks` | scanner (docker/local) | Nothing — the container runs with `--network=none`. |
| `osv-scanner` | scanner (docker/local) | Dependency coordinates are matched against the OSV database (network); source code is not uploaded. |
| `claude`, `codex`, `agy` (house-prompt) | agent CLI | **Source code from the scanned tree** is read by the vendor CLI and sent to its hosted model API (Anthropic / OpenAI / Google, per your CLI login). |
| `claude-security` | dedicated agentic | **Source code** → Anthropic-hosted models, driven by the claude-security plugin. |
| `codex-security` | dedicated agentic | **Source code** → OpenAI-hosted models (or the provider your `~/.codex` config selects). |
| `--validate` panel | validator | **Finding details + cited code snippets + repository context** → the three vendor CLIs llm-council routes to (cross-vendor by design). |
| `--fix` | fix lane | **Not functional in 0.1.0 — refuses before running anything.** *When* it runs, by design it sends **the scanned tree** to a vendor CLI to generate a patch; that egress is the feature, and this table omitted it (R11). The patch is never applied to your code. |
| `serve` | report viewer | **Nothing leaves the machine unless you bind a non-loopback address.** Then every run's files are readable by anyone holding the token, over plain HTTP on your network — treat the link as you would the reports. Dual-use artifacts withheld unless `--include-dual-use`; refused under `DEPLOY_MODE=secret` ([serve.md](serve.md)). |
| `--verify-fix` / `--verify-patch` | deterministic verify lane | Nothing beyond what the selected scanner arms already send (rows above). No vendor CLI, no model: the patch is applied to a scratch copy and the scanners are re-run there. Your tree is never modified ([verify-fix.md](verify-fix.md)). |
| `--analyze` | analysis lane | **Source code from the scanned tree** is read by the house CLI you pick (`--analyze-with claude\|codex\|agy`, default claude) and sent to that vendor's hosted model API, exactly as the house-prompt scan arms do. The prompt is ours (`prompts/house-analysis-*.md`); the document comes back as a run artifact under `raw/`, never as a finding. `attack-path` and `writeup` are dual-use and stay `raw/`-only. |


The default profile (`semgrep,gitleaks,osv-scanner`) keeps all source local.

## What this is *not*

- **Vendor origin ≠ authorization.** "US-origin model vendor" is not GovCloud,
  not FedRAMP, not an IL, and not an enterprise data-handling approval.
  Whether a hosted arm is acceptable for your data classification is your
  organization's determination, not this tool's.
- **Do not scan CUI, classified, ITAR/export-controlled, regulated, or
  customer-confidential code with hosted arms** unless your own approvals
  cover those exact vendor services. The tool will not stop you; this page is
  the warning.

## Isolation model (what the arms can even see)

- Arms run against a **scratch copy** of the target (`workspace.py`), which
  excludes VCS internals and runtime directories (including prior
  `.security-council/` run outputs, so an LLM arm never reads earlier reports
  as "context"). The copy is discarded after the run.
- Arm subprocesses get `SECURITY_COUNCIL_NESTED=1`; the MCP server refuses
  `sc_scan` when it's set, so an agentic arm cannot recursively launch scans.
- Prompt-injection resistance is a **tested regression**, not a hope: the
  fixture embeds a labeled injection canary and the eval suite asserts arms
  don't obey it. That is a test, not a guarantee — treat scanned code as
  hostile input to the LLM arms, because it is.

## What persists on disk, where

| Artifact | Location | Contains |
|---|---|---|
| Run outputs | `<target>/.security-council/runs/<id>/` | Findings incl. **code snippets** (secret-bearing snippets are redacted at normalization — hash kept, text dropped), model/cost attestation |
| Decision store | `<target>/.security-council/decisions/` | Suppression/outcome records per root cause: operator names, justifications, timestamps |
| Baseline | `<target>/.security-council/baseline/latest.json` | Finding ids/titles/fingerprints from the baselined run |
| Validator transcripts | `.llm-council/runs/` | Full panel debate text, incl. cited code |

All of these are plain files under the scanned repo — govern them like any
other build artifact containing findings about your code. This project's own
`.gitignore` excludes `**/.security-council/`; teams that *want* shared
decisions commit `decisions/` + `baseline/` deliberately (see
[triage.md](triage.md)).

## Model attestation (knowing *which* model saw your code)

Every finding carries provenance: source arm, model id, prompt hash. The
summary's "Method & attestation" table shows the served model per arm, and a
pinned model that gets substituted by a vendor **fails the arm loudly** rather
than misattributing output (decision D8). Honest limitation: the
codex-security CLI does not report its served model anywhere; such findings
are marked `model_unattested` rather than guessed.
