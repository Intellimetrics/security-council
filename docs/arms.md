# Arms

**Who this is for:** you're choosing which scanners/AI reviewers to enable, or setting one up. New to the terminology? [concepts.md](concepts.md) first. If you're considering the AI arms, read [data-boundaries.md](data-boundaries.md) before enabling them.

An **arm** is one independent producer of findings. Arms run in parallel
against the isolated workspace; their output is normalized into one finding
model, clustered by root cause, and corroborated across vendor families.
Costs below are from live runs on this repo's 12-file fixture — treat them as
floors, not estimates, for real repos.

## Catalog

| Arm | Kind | Vendor family | Cost / speed (fixture-scale) | Prerequisites |
|---|---|---|---|---|
| `semgrep` | scanner | semgrep | free, seconds | docker or local binary; network for rules |
| `gitleaks` | scanner | gitleaks | free, seconds | docker or local binary; runs offline |
| `osv-scanner` | scanner | osv | free, seconds | docker or local binary; network for OSV DB |
| `claude` | house-prompt agent | claude | ~$0.5–3, ~2–3 min | `claude` CLI logged in |
| `codex` | house-prompt agent | codex | ~$0.5–3 | `codex` CLI; the arm passes `--ignore-user-config` (without it codex hangs applying user memories) |
| `agy` | house-prompt agent | google | ~$0 (CLI-plan dependent) | `agy` CLI; note `exit 0` does not imply success — status is parsed |
| `claude-security` | dedicated agentic | claude | ~$7 at `effort: low`, ~7 min | `claude` CLI + `claude plugin install claude-security@claude-plugins-official` |
| `codex-security` | dedicated agentic | codex | ~$5–8, ~18 min | `@openai/codex-security` (PATH, or npx cache — never auto-installed); `~/.codex` must be mode 700 |

`security-council doctor` shows exactly which arms are ready and why not.

## House-prompt vs dedicated agentic arms

The **house-prompt arms** (`claude`/`codex`/`agy`) run our SAST prompt with a
strict JSON output schema — a floor of agentic coverage on any capable CLI.
The **dedicated arms** wrap the vendors' own purpose-built scanners and
ingest their richest native output rather than a lossy projection:

- **`claude-security`** runs the plugin's scan headlessly (its interactive
  cost gates collapse via the documented acknowledgement phrase), fused by
  `--max-budget-usd` (default 10). We ingest its SARIF including the
  plugin's own 3-voter verification panel and verification stamp — a report
  that isn't `verified` is reported as partial, never as a clean scan.
- **`codex-security`** scans into a private (0700) temp dir and seals a
  canonical bundle (`scan-manifest.json` + `findings.json` + `coverage.json`);
  success is decided by the sealed manifest, not the exit code. Cost is
  parsed from its stderr progress stream (the CLI writes nothing to stdout)
  and a `--max-cost` stop is surfaced as `cost_stopped` in the manifest.
  The default $5 fuse can cut its final "attack paths" phase — give it
  `max_cost_usd: 8` if you want that phase.

Per-arm options go in `.security-council.yaml` under `arms.options.<name>`
(they are constructor kwargs — see each arm's module docstring).

## Model attestation (D8)

Agent findings carry the **served** model id, read from the CLI's own usage
accounting, not the requested one. If you pin a model
(`arms.options.claude-security.model`) and the vendor serves a different one,
the arm **fails loudly** with `model_substituted` rather than attributing
findings to the wrong model, and the summary shows a MODEL SUBSTITUTION
banner. Known gap: the codex-security CLI reports its served model nowhere,
so its findings are honestly marked `model_unattested`.

## Gated model tiers (Mythos / Daybreak)

The vendor workflows run on whatever model the CLI has — GA by default (codex
`gpt-5.6-sol`, claude Fable). If your account holds a gated tier, route the
same workflows to it:

```yaml
# .security-council.yaml — declare what you hold (nothing routes to an unclaimed tier)
entitlements:
  - tier: mythos          # Anthropic, claude-mythos-5 (relaxed safeguards)
  - tier: daybreak-blue   # OpenAI, daybreak-blue-latest
```

```bash
security-council entitlements                        # what you've declared + availability
security-council scan . --arms claude-security --tier mythos
```

Rules the tool enforces before any scan runs (no cost is incurred on refusal):

- **A gated tier must be declared** in `entitlements:`, or the scan is refused
  (exit 4) — it will never silently route to a tier you didn't claim.
- **Daybreak Red (`gpt-5.6-cyber`) is refused for every workflow** (exit 5)
  until the authorization block + sandbox exist — offensive/PoC use is out of
  scope here by design.
- A relaxed-safeguard tier stamps `safeguard_posture: relaxed` on its findings
  and is flagged in the report; the served model is attested per finding (codex
  can't report its served model, so gated codex tiers render "unattested").

Availability probing never reads your API keys: it checks local model catalogs
(zero network) and, where a deeper probe is wired, uses the CLI's own
credentials — it never copies them.

## Category-aware corroboration

Not every arm is *eligible* to report every category (Claude's tooling
excludes dependency CVEs by policy; gitleaks only does secrets). Coverage
policy (`normalize/coverage.py:CATEGORY_POLICY`) tracks who could have
reported what, so:

- a finding two eligible arms agree on is **corroborated** (weighted by
  vendor family independence — two same-family arms count barely more than
  one);
- a finding only one arm *could* have reported is **singleton-by-policy**,
  not "uncorroborated";
- a category no ran arm covers is reported as an explicit **coverage gap**,
  never silently.

If you add an arm, you must add its policy row — see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## The validator panel (`--validate`)

Cross-examines each finding with three seats on **distinct vendor families**
— prosecutor, defender, adjudicator — via `llm-council run --json`. Citations
are re-verified against the repository; a defender that fabricates a citation
can never ground a suppression (the finding escalates to human review
instead). Supply-chain findings skip the panel (the SAST-shaped prompt
doesn't fit dependency CVEs; osv is authoritative). Budget-capped per finding
(`--validate-budget`, default $0.50).
