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
  `max_cost_usd: 8` if you want that phase. **What the dollars mean depends on
  how you signed in.** With an API key (`OPENAI_API_KEY`, or `login
  --with-api-key`) the estimate tracks real API billing. With a **ChatGPT
  sign-in** (`npx @openai/codex-security login`, the local default — `login
  status` says "Logged in using ChatGPT") nothing is billed per token: the
  CLI still reports an *estimated* cost at standard API prices, and the run
  draws on your ChatGPT plan's Codex usage limits instead. The fuse is then a
  cap on token volume, not on money — a standard scan of the 9-file fixture
  needs ≥ $8 of "estimated" cost (~2.2M input tokens, mostly cached) to reach
  its findings, and a $4 fuse stops it in the validation phase with nothing
  emitted (reported honestly as `cost_stopped`, coverage `none`, exit 3).

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

## Analysis jobs (documents, not findings)

Besides findings, security-council can write you a *document* about the
repository — a threat model, an attack-path analysis, hardening proposals, a
draft security policy, or defender-facing write-ups of the run's findings:

```bash
security-council scan . --analyze threat-model,hardening
security-council scan . --arms semgrep --analyze writeup --analyze-with codex
```

**Who writes it.** These are security-council's **own prompts**
(`prompts/house-analysis-<job>.md`, plus a shared preamble), run through one
of the three house CLIs — `claude` (default), `codex`, or `agy` — with
exactly the read-only contract the house scan arms use (`--permission-mode
plan --tools Read,Grep,Glob,LS` / `-s read-only` / `--mode plan --sandbox`).
The vendors' own "analysis skills" are *not* used: they are internal phases
of the vendor's scan, not a public surface
(`docs/reviews/R10-live-vendor-runs.md` §4). The report therefore names the
producer `house:<cli>`, never a vendor skill.

**What each job produces** (all Markdown, under `raw/<cli>-analysis_<job>/`):

| Job | Document | Dual-use? | Gets the run's findings as context? |
|---|---|---|---|
| `threat-model` | System overview, assets, actors, STRIDE-style threat table with code citations, existing controls, gaps | no | no |
| `attack-path` | The three-to-six most significant chains of weaknesses, each with entry point, preconditions, impact, the cheapest defensive change, and detection | **yes** | yes |
| `hardening` | Prioritized hardening changes (P1–P3) with the defensive code/config to apply | no | no |
| `policy` | A draft security policy for the team, grounded in the code, with "(gap)" marks where the code does not meet it | no | no |
| `writeup` | One defender-facing write-up per finding: affected code, root cause, impact, remediation, how to verify the fix | **yes** | yes |

**What it costs.** Each job is one model call over your tree — the same order
of cost as one house scan arm. claude runs under a hard fuse
(`--max-budget-usd`, default $5; set `arms.options."analysis:<job>":
{max_cost_usd: 2}`), and reports the spend in the manifest. codex and agy
have no budget flag and report no cost, so those columns read "—". If the
fuse trips, the job fails (see below); you never get a half-document
presented as whole.

**Provenance on every document.** The manifest's `artifacts` index and the
document's own header carry: producer (`house:<cli>`), the served model
(attested from the CLI's output on claude/agy; codex never reports it, so it
is marked *not attested*), entitlement tier and safeguard posture (a document
written on a relaxed-safeguard tier says so), a hash of the exact prompt, the
files the model says it read, completion (`complete` / `partial`), and how
many redactions were applied.

**Never a finding, never the gate.** Documents attach to the run as
**artifacts** (manifest `artifacts` + the summary's "Analysis artifacts"
appendix). They never enter `findings.json`, coverage, or the exit code. A job
that fails — CLI error, timeout, budget stop, a substituted model, a document
that does not validate, or a model that declines — is recorded as an
`analysis_failed` note in the report and changes nothing else.

**Dual-use handling.** `attack-path` and `writeup` describe how the code is
attacked. They are marked **export-excluded** and kept `raw/`-only — no
report bundle inlines them. The prompts forbid exploit code, payloads and
attack one-liners (Blue scope; this tool never generates proofs of concept),
and a **post-check** redacts, in place and visibly, any shell-tagged code
block in a dual-use document and any known payload signature (reverse
shells, exploit tooling names, canonical injection strings) in *every*
document. That check is deliberately simple and **best-effort**: a prose
description of an attack, an untagged code block, or a payload the list does
not know will pass through. Treat the raw directory of a dual-use job as
sensitive.

**Data boundary.** This lane sends your source to the chosen vendor — see
[data-boundaries.md](data-boundaries.md).

*Status: built and tested offline (fake CLIs) on all three CLIs against the
same flag contract the house scan arms have already run live. A real
`--analyze` run has not yet completed here, so expect the first live run to
tell you something the fakes could not — most likely about the document the
model returns, not about the invocation.*

## Fix workflows (reviewed patches, never applied)

The vendor fix workflows turn a finding into a **reviewed `.patch` file you
apply yourself** — security-council never writes to your tree:

```bash
security-council scan . --fix <finding-id>[,<id>...] --fix-job suggest-patches
security-council scan . --fix gating          # all open gating findings
```

Because a fix workflow *edits files and runs your test suite* (untrusted code
execution), it runs under a hard sandbox and fails closed if that sandbox can't
be proven:

- **Requires bubblewrap (`bwrap`).** Each fix job runs inside an
  orchestrator-owned kernel sandbox: read-only system, writable **only** a
  throwaway copy of your repo, a tmpfs HOME (your `~/.ssh`, `~/.aws`,
  `~/.claude`, `~/.codex` are unreachable), and no network. Before the job runs,
  a canary proves the sandbox blocks writing outside the copy, reading your
  home, and network — **no proof, no run.**
- **The patch is never applied.** There is no `--apply`; the tool emits a
  `.patch` artifact under `raw/` with its base commit and sha, and prints how to
  apply it manually. Commit/push/PR-open are never available.
- **Patches are validated and redacted.** Anything touching agent/CI/VCS-meta
  files (`.claude/`, `.github/`, `.gitmodules`, …) or containing symlink/binary
  entries is refused; secret material is redacted from both sides; a
  secrets-family patch is export-excluded (`raw/`-only).
- CI/cloud tokens in your environment are stripped from the fenced process.

*Status: the fence, canary, and patch validator are live-verified; the vendor
patch-generation step is built and tested offline and needs real vendor spend to
exercise end to end (it degrades safely to "no patch" if the skill produces
nothing).*

### Verifying a patch (deterministic, $0, no vendor)

Whether the patch came from the fix lane (`--verify-fix`) or from you
(`--verify-patch fix.patch --for <finding-id>`), verification is the same and
involves no model: the patch is applied to a scratch copy, the deterministic
scanners that reported the finding are re-run on that copy, and the finding
must disappear under verified coverage — `fixed`, `not_fixed` or `unproven`,
recorded as machine evidence that never closes anything. See
[verify-fix.md](verify-fix.md).

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
