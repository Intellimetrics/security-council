# M0 spike results

Fixture: `tests/fixtures/seedrepo` (own git repo, `main`). Ground truth: `tests/fixtures/EXPECTED.yaml`.

## S2 — llm-council `consensus` as the validator panel — **PASS** (2026-08-20)

Ran `council_run` mode=consensus over 3 candidate findings, `working_directory` = the fixture,
peers instructed to Read/verify before voting and answer buggy?/reachable?/impact? separately.

Peers: claude (for/prosecutor), codex (against/defender), antigravity (neutral/adjudicator).
Wall 67s, aggregate 148s, $0 (native CLI peers). 3/3 succeeded.

Per-finding verdicts (unanimous, all correct):
- F1 MD5 password hash (CWE-916, crypto, must_not_demote) -> true_positive x3. Reachability
  traced to POST /api/register. **Crypto TP survived.**
- F2 md5 cache key, usedforsecurity=False (FP bait) -> false_positive x3. The against-stance
  defender still rejected it -> ethical-override clause works. **FP demoted.**
- F3 IDOR (CWE-639, authz, cross_file) -> true_positive x3. Reachability traced
  app/routes.py:/api/orders/<id> -> app/order_repo.py:get_order. **Cross-file navigation happened**
  (peers grepped for callers, cited both files).

Evidence: all [VERIFIED:path:lines] resolved, zero evidence_verification_failures.
Isolation: all three detected the README prompt-injection payload and refused it (reasoning-level).

Design confirmations:
- Parse the per-finding VERDICT/FINDINGS block, NOT llm-council's coarse yes/no/tradeoff
  recommendation (antigravity returned council-level "tradeoff" while its per-finding verdicts
  were correct and unanimous).
- `execute_council`/consensus mode + stance overrides is a viable validator with zero upstream
  llm-council changes (D2/D3 hold).
- Cross-file navigation and evidence verification both work through the CLI arms as-is.

Transcript: `tests/fixtures/seedrepo/.llm-council/runs/20260820_100035_*.{md,json,html}` (gitignored).

## Pending
- S1 classifier refusal (Fable vs Opus, +/- SAFE_CONTEXT_DIRECTIVE) — read-only, token cost.
- S3 codex-security, S4 claude-security, S6 docker scanners, S9 agy plugins — need install consent.

## Full M0 scorecard (2026-08-20)

| Spike | Result | Key finding |
|---|---|---|
| S2 llm-council consensus validator | **PASS** | Unanimous correct verdicts: crypto+IDOR TP survive, md5-cache FP demoted; cross-file nav + evidence verification worked; prompt-injection refused. Thesis holds, zero upstream changes. |
| S3 @openai/codex-security | **PASS (entitled)** | Runs on this account, no Trusted-Access wall. Heavyweight: ~$4.2 and >7.5min on a 12-file repo in `standard` mode, killed by timeout before SARIF finalization. Needs `--max-cost` + long timeout. Hardening: output dir 700, parent not group/world-writable, `~/.codex` not group-writable (I set it 700; revert `chmod 775 ~/.codex`). |
| S4 claude-security plugin | **PASS** | Installed v0.10.1 (user scope, marketplace `anthropics/claude-plugins-official`). Headless gate COLLAPSES with job+scope+effort+cost in the prompt (0 blocking AskUserQuestion). `Workflow` tool present. Ran on pinned `claude-fable-5` — no silent Opus downgrade. Writes `CLAUDE-SECURITY-<ts>/` into the scanned repo -> confirms scratch-worktree need. Needs >$3 budget to finish. |
| S5 agy --json-schema | **PASS (mech.)** | `status: SUCCESS`, valid `sc-agent-finding/1` structured_output. BUT 0 findings on the vulnerable repo in `--mode plan` -> coverage-unverified case. **Soft-deny/exit-0 trap CONFIRMED**: shell-command probe returned exit 0 + `status: CANCELED` -> `exit==0` is not success. |
| S6 docker scanners | **PASS** | semgrep->SARIF (found SQLi; `p/default` missed crypto/cmdi -> need richer ruleset), gitleaks->SARIF (found AWS token + generic key, exit 1), osv->SARIF (34 CVEs, exit 1). **Non-zero-exit-on-findings confirmed -> `success_exit_codes` is a hard requirement.** Fixture secret had to be non-example (gitleaks allowlists AKIA...EXAMPLE). |
| S7 codex --output-schema | **PASS (mech.)** | Requires **`--ignore-user-config`** (without it, gpt-5.6-sol dragged in this machine's memories/skills/plugins, tried to apply_patch ~/.codex/memories, and hung to timeout). With it: exit 0, valid envelope. 0 findings (same coverage caveat as agy). |
| S9 SecureCoder agy plugin | **PASS** | `agy plugin validate` -> ok, 8 skills. Installable. (Scanner skills need the IDE sidecar per R2; prompt-only skills usable. Not globally installed.) |
| S1 classifier refusal | **partial** | Not run as the full 2x2, but S4 observed a real security scan running on `claude-fable-5` with no refusal/downgrade. Guard still built (D8). |
| S8 MCP mount of codex-security | not run | Deferred, non-blocking (v1.1 capability). |

### Design refinements the spikes forced
1. **codex arm MUST pass `--ignore-user-config`** (+ explicit `-m`) or it inherits the operator's memories/features/plugins and hangs. Add to `arms/llm_cli.py` codex flag builder.
2. **Generic `--json-schema`/`--output-schema` arms produce well-formed but EMPTY findings without tool-use driving.** The recon pre-pass + REVIEW_WITH_TOOLS/CROSS_FILE_NAVIGATION directives are load-bearing, not optional; the dedicated scanners (codex-security, claude-security) are the real finding producers, the house-prompt arm is a floor. The coverage guard (zero findings + peers-found-bugs -> inconclusive) is validated twice.
3. **`success_exit_codes` confirmed necessary** (gitleaks/osv exit 1 on findings).
4. **agy soft-deny returns exit 0 + status!=SUCCESS** — `arms/base.py` must assert on status, not exit code.
5. **codex-security is expensive/slow** — orchestrator needs generous per-arm timeout + `--max-cost`; not suitable for tight CI without scoping.
6. **claude-security & codex-security both write into the scanned repo** — scratch `git worktree` per arm is mandatory.
7. Fixture: seed a non-example secret; `p/default` semgrep ruleset is too thin — use `p/owasp-top-ten`/`--config auto` (needs network) or a bundled pack.
