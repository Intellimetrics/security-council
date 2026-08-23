# R6 — M-V4 fix-lane safety review (2026-08-23)

Pre-landing safety review of the fix/remediation lane (R5 required it). Consensus
mode, but **degraded: only the claude peer responded** (codex timed out at 576s;
antigravity returned empty). So this is a single thorough, code-grounded opinion,
not a quorum — treated as go-with-conditions with all conditions mandatory, and a
second opinion is worth getting before the live arm is certified. Transcript:
`.llm-council/runs/20260823_100146_780541_1d2f231172e249bb803fb4185c2b7117.md`.

## Verdict: GO-WITH-CONDITIONS

The lane's shape (scratch-copy → `.patch` artifact, no apply path, verify-fix as
non-closing evidence) is right and reuses boundaries that already hold. But the
scratch copy today is a **pollution fence, not a security boundary**, and the fix
lane is the first workflow that executes untrusted code *by design* (it runs the
project's test suite). Six landing gates are mandatory.

## Landing gates (MUST-HAVE before the live fix arm runs)

- **M1 — kernel sandbox + proven canary.** Fix jobs run only under the vendor
  CLI's native sandbox (codex `--sandbox workspace-write`, network off; Claude
  Code bubblewrap + domain allowlist to the vendor API only). `--dangerously-
  skip-permissions` alone is NOT acceptable for this lane. Before each fix job a
  canary in the same sandbox must FAIL to: write `<original>/.sc-canary`, read
  `~/.ssh`/`~/.gitconfig`, `curl` the network. Any success → refuse the job
  (`fence_unverified`). **Needs vendor-sandbox config verified against current
  docs + a live canary run — requires vendor access, not certifiable on the dev
  machine.**
- **M2 — hard-refuse `inplace` for fix jobs in `run_scan`** (not just the CLI;
  MCP passes `inplace` straight through). A fix arm in-place edits the real tree.
- **M3 — allowlisted env**, not `dict(os.environ)`: pass only PATH/HOME/LANG/
  TERM/TMPDIR + the vendor's own auth vars + NESTED markers. Drop `AWS_*`,
  `GITHUB_TOKEN`/`GH_TOKEN`, `GITLAB_TOKEN`, `SECURITY_COUNCIL_GITLAB_TOKEN`,
  `SYSTEM_ACCESSTOKEN`, `CI_JOB_TOKEN`, `NPM_TOKEN`, `KUBECONFIG`, `DOCKER_*`,
  `SSH_AUTH_SOCK`, any non-vendor `*_API_KEY`/`*_TOKEN`. (Closes the "we never
  built PR-open, but the agent inherited a token that can" laundering path.)
- **M4 — git-neutered copy.** `git init` + one baseline commit, **no remotes**,
  credential helpers disabled (`GIT_CONFIG_GLOBAL=/dev/null`,
  `GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=/bin/false`,
  `GIT_SSH_COMMAND=/bin/false`, empty `credential.helper`). Also functionally
  required: `.git` is excluded from the copy, so a "scratch checkout" and
  `git diff` extraction need a repo. The orchestrator extracts the patch itself
  with `git diff <baseline>` — never trusts the vendor's named output.
- **M5 — fresh serial workspace per fix job, after the scan phase** (today scan
  + analysis arms share one `ws.root` in a thread pool; a file-modifying arm
  there races the scanners).
- **M6 — test execution as untrusted code:** inside M1's sandbox, network-denied,
  existing `timeout` + RLIMIT/cgroup mem+CPU cap, `TMPDIR` inside the sandbox.

Also: `copytree(symlinks=False)` dereferences symlinks — a repo symlink to
`~/.aws/credentials` lands in the copy; use `symlinks=True` for the fix lane.

## Patch handling
- Exportable by default (a patch a reviewer can't see is useless), EXCEPT:
  **secrets-family findings** (`SECRET_CWES`) → `export_excluded=True` and `-`
  hunks replaced by `-<redacted sha256:…>`; **gitleaks post-filter over every
  produced patch** (context lines can leak an adjacent key) → any hit →
  export-excluded + redacted + `secret_in_patch`. Inherit the related finding's
  export treatment + dual-use/posture labels. Seal patch provenance (sha256,
  base commit/dirty, producer, model, posture).
- Reject patches touching `../`, absolute, `.git/`, `.security-council/` paths or
  binary hunks. Flag `review_required` for patches touching CI/workflow/build
  files, lockfiles, or deleting/modifying tests (a "fix" that deletes the failing
  test is the classic launder). Crypto patches → `review_required: crypto`;
  their verify-fix evidence renders "requires human cryptographic review", never
  a green check.

## verify-fix as evidence — right boundary, three laundering paths to fence
- **L1** evidence under a separate `evidence[]` key `kind: vendor_verify_fix`,
  `decided_by.kind: machine`; `history_counts()` must ignore it even with an
  `operator`; `mark_outcome` stays the only writer of `outcome_mark`.
- **L2 (a REAL current hole, not just M-V4):** the CLI `outcome mark`/`baseline`/
  `suppress` have NO nesting guard and `outcome mark` defaults operator to the
  login user — a nested agent could forge a human mark. Refuse decision-store
  writes when `SECURITY_COUNCIL_NESTED` is set. **Fixed 2026-08-23 ahead of the
  rest of M-V4.**
- **L3** verify-fix evidence is never converted to a panel vote / defender claim
  / `score_finding` input (would satisfy G2's defender exception). Scope
  verify-fix to a patch artifact; never feeds baseline `absent`; no
  `outcome mark --from-evidence`.

## Refuse outright
`--apply`/`git apply` automation, commit, push, PR/MR open (M3 + M4 kill the
side channels); fix jobs `inplace` or when the canary fails; Red tier (already);
unscoped "fix everything" (take explicit finding ids); out-of-repo/binary
patches. Do NOT refuse crypto or Blue-tier fixes — label them `review_required`.

## Safer shape / sequencing
- **Two halves:** M-V4a = patch generation + fence canary + patch validator +
  secrets filter, live-verified before M-V4b = verify-fix evidence.
- codex family needs its own `_cmd` with `--sandbox` (the M-V3 artifact runner
  currently sends claude flags for codex — latent bug; for fixes the flag choice
  *is* the safety knob).
- Verify `codex-security patch` honours the codex sandbox (vs spawning its own
  `codex exec`); whether suggest-patches' verifier needs network (if so degrade
  to `tests_ran: false`, never open egress).

## Verified sandbox facts (ctx7 /openai/codex, 2026-08-23 — no vendor spend)
- `codex exec --sandbox workspace-write`: writes confined to the workspace;
  **network is OFF by default** (`SandboxWorkspaceWrite.network_access` defaults
  false — must be explicitly set true to enable). Headless `codex exec` defaults
  `approval_policy = Never`. So the fix-lane codex invocation = `--sandbox
  workspace-write` (default no-network), `--add-dir` NEVER pointing at the
  original repo, and NEVER `--dangerously-bypass-approvals-and-sandbox`/`--yolo`.
  This satisfies M1/M6 for the codex family at the flag level; the canary run
  still needs live vendor access to prove. (Claude Code bubblewrap sandbox
  config to be verified the same way before the claude-family fix path.)

## Second independent review (2026-08-23, also degraded — 1 peer)

The maintainer asked for a clean quorum. It is **not attainable in this
environment**: on the re-run, antigravity again returned empty and codex again
timed out (both fail reliably). What came back was a second, fresh, full-effort
claude pass — independent of the first — which **confirmed go-with-conditions**,
corrected one gate's ownership, and found escape paths the first missed. Two
independent passes now converge on go-with-conditions. Reconciled changes:

- **M1 re-owned: orchestrator-applied kernel fence, vendor sandbox as
  defense-in-depth.** Wrap the whole vendor process in a bwrap sandbox
  (ro-bind system dirs, rw-bind ONLY the scratch copy, tmpfs HOME,
  `--die-with-parent`, `--new-session`) — or `@anthropic-ai/sandbox-runtime`.
  **This makes the canary deterministic, $0, and certifiable on the dev machine
  now** (no model cooperation, no vendor spend) — it dissolves the earlier
  "fence needs vendor access" blocker. Vendor `--sandbox` flags still passed as
  a second layer. Egress is a *functional* knob (tests may `pip install`), not
  the primary control once HOME is tmpfs and the original tree is unbound — do
  not block landing on a perfect egress filter.
- **M4 corrected (MV4-10, high): never run `git diff` inside the agent's tree
  outside the fence.** The agent owns `.git/config` and can set
  `core.fsmonitor=<cmd>` / `diff.*.textconv=<cmd>`, which git executes as the
  orchestrator user. Extract the patch with `git diff --no-index` between a
  pristine copy and the work copy, from a non-repo cwd, with
  `GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CEILING_DIRECTORIES=…`
  (or pure-Python difflib).
- **MV4-11 (high): vendor-config persistence.** A prompt-injected agent plants a
  hook in `~/.claude/settings.json` / `~/.codex/` (or `CLAUDE.md`/`AGENTS.md`)
  that fires in the operator's NEXT interactive session, outside every sandbox.
  Per-job **ephemeral `CLAUDE_CONFIG_DIR` / `CODEX_HOME`** seeded with auth +
  plugin cache only, discarded after. Also shields against operator config that
  says `sandbox_mode = danger-full-access`.
- **MV4-12 (medium): L2 guard is cooperative** (`env -u SECURITY_COUNCIL_NESTED`
  bypasses it) and the **MCP `sc_baseline`/`sc_suppress`/`sc_outcome_mark`
  handlers have NO nesting guard**. Relabel MV4-4 "cooperative guard, closed by
  M1's write-denial on `<original>/.security-council/`"; add the guard to the MCP
  handlers for symmetry (belt-and-braces, not the boundary).
- **MV4-13 (medium): `proc.run_command` orphans grandchildren** on timeout (no
  process group). Need `start_new_session=True` + `os.killpg` (or bwrap
  `--die-with-parent`); RLIMITs via `preexec_fn`/`prlimit`.
- **MV4-14 (medium): patch validator additions.** REFUSE (not just flag) patches
  touching agent/VCS-meta config: `.claude/`, `CLAUDE.md`, `AGENTS.md`,
  `.mcp.json`, `.codex/`, `.cursor/`, `.vscode/`, `.envrc`,
  `.pre-commit-config.yaml`, `conftest.py`, `.gitmodules`, `.gitattributes`.
  Reject symlink (`120000`) entries, mode changes, rename/copy headers unless
  both paths pass; cap bytes/files; flag out-of-target-file hunks
  `review_required: out_of_scope`. Redact secrets on BOTH `+`/`-` sides and
  classify by path heuristic (`.env*`, `*.pem/.key/.p12/.jks`, `*secret*`,
  `*credential*`).
- **MV4-15 (low): verify-fix runs tests** → same fence + fresh copy, the
  ORCHESTRATOR applies the patch (never the agent); bind evidence to
  `patch_sha256 + base_commit`; label `producer == verifier` (not independent).
- **Fail-closed made structural:** the fix arm's `run()` requires a
  `FenceCertificate` only `fence.certify()` can mint in-process (binds sandbox
  binary+version, vendor CLI version, flag hash, host, ≤1h TTL); no config key
  can set it; CLI/MCP cannot reach the live arm without it.

Net: M-V4a (orchestrator fence + canary + env allowlist + git-neuter +
per-job workspace + patch validator + secrets/gitleaks redaction + ephemeral
vendor HOME + killpg) is **buildable and certifiable here**; only the
*functional* "does the vendor skill produce a good patch under the fence"
needs vendor spend and degrades safely to `no_patch`/`tests_ran: false`.

## Findings (peer, severity-ranked)
MV4-1 crit: scratch copy is cwd-only; agent+tests have full HOME/env/original reach.
MV4-2 crit: `inplace` (CLI or MCP) would let a fix arm edit the real tree.
MV4-3 high: inherited CI tokens enable PR/MR-open by side channel.
MV4-4 high: nested agent can forge a human outcome mark (no CLI nesting guard). **[fixed]**
MV4-5 high: secrets-family patches embed the secret; `runs/` is CI-published.
MV4-6 med: shared `ws.root` thread pool races a file-modifying arm.
MV4-7 med: `copytree(symlinks=False)` pulls out-of-tree symlink targets in.
MV4-8 med: verify-fix verdict could satisfy G2's defender exception if fed to the panel.
MV4-9 low: artifact runner uses claude flags for codex family.
