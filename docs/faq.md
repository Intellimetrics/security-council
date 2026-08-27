# FAQ

**Does it send my code anywhere?**
With the default arms (semgrep, gitleaks, osv-scanner): no — scanning is
local; the scanners fetch their rule/vulnerability databases over the
network, but your source is not uploaded. The **optional AI arms and the
validator panel do send source code to AI vendors' servers** (Anthropic,
OpenAI, Google). Full per-arm table: [data-boundaries.md](data-boundaries.md).

**How much does it cost?**
The default profile: $0. The AI arms cost real money per scan — on a small
repo roughly $5–8 per dedicated AI arm, with hard budget caps built in
(`max_budget_usd` / `max_cost_usd`). Treat published figures as small-repo
floors. [arms.md](arms.md).

**Why did my build fail?**
The scan exits `1` when a finding at/above `policy.fail_on_severity`
(default `high`) is open. Open the run's `summary.md` — the **Gate** line
and the findings register say exactly which findings gate. Fix them,
suppress them with a justification, or baseline the backlog
([triage.md](triage.md)). Exit `3` means a scanner itself failed — see the
"Degraded run" box in the summary.

**How do I ignore a false positive?**
`security-council suppress <finding-id> --operator you --justification "..."`.
It's scoped to that one root cause, expires in 90 days, self-cancels if the
code changes, and is recorded with your name. There is deliberately no
"disable this rule everywhere" button. [triage.md](triage.md).

**I adopted this on an old codebase and CI is permanently red.**
`security-council baseline set`, then scan with `--gate-baseline new`. The
backlog stays visible in reports but only *new* findings fail builds.

**It says my suppression "must be signed here". What?**
Decisions are signed with your SSH key by default so a scan can verify *who*
made them. Run the two commands the message prints
(`decisions trust` with your `.pub`, then re-run with `--signing-key`), or
put `decisions: {require_signatures: warn}` in `.security-council.yaml` to
record unsigned decisions for now. Three-minute setup: [signing.md](signing.md).

**I wrote a fix. Can it tell me whether the fix worked?**
Yes, for findings a scanner reported: `security-council scan . --verify-patch
fix.patch --for <finding_id>` applies your patch to a throwaway copy, re-runs
that scanner on the copy, and reports **fixed**, **not fixed** or
**unproven** with the reason. No AI, no cost, your files untouched. It is
evidence for your reviewer, not a decision — the finding closes only when a
scan of the merged code no longer sees it ([verify-fix.md](verify-fix.md)).

**A finding I suppressed came back. Why?**
Suppressions expire after 90 days, and they self-cancel when the code around
the finding changes (the old justification may no longer hold). The report
marks these `reopened` with the reason. Re-suppress if it's still justified.
A third reason, under `require_signatures: enforce`: the decision's
signature no longer verifies (edited after signing, signer removed from
`allowed_signers`, or copied from another repo) — the summary lists it under
"Stored decisions refused", and `security-council decisions verify` says why.

**Do I need the AI arms at all?**
No — the deterministic profile is useful on its own. The AI arms add the
things patterns can't catch (cross-file logic flaws like IDOR/broken access
control). Many teams run free arms on every PR and AI arms nightly.

**Do I need API keys?**
Not for the default arms. The AI arms use vendor **CLIs** you install and
log into (`claude`, `codex`, `agy`) — security-council drives those; it
never handles your API keys itself.

**What's a SARIF / why do I care?**
The standard results format that GitHub, Azure DevOps, and others render
natively — it's how findings become PR annotations. Every run produces one.
[concepts.md](concepts.md).

**Can the AI wrongly dismiss a real vulnerability?**
That's the failure mode this design centers on (research measured naive AI
triage wrongly dismissing 22% of true bugs, >50% for crypto). Mitigations
are structural: nothing is auto-deleted, auto-suppression is off by default
and dry-runs first, crypto/critical can never be auto-suppressed, and a
CI-enforced eval gate replays labeled ground truth and fails if any true
positive gets buried. [safety-model.md](safety-model.md).

**Where did the report go?**
`security-council runs` lists every run with its exit code and counts;
`security-council report --open` opens the newest run's `summary.html`
(`scan . --open` does it straight after a scan). Runs live under
`<your-repo>/.security-council/runs/<timestamp>/`, and `runs/latest` always
points at the newest. `summary.html` has a "Where to look" block linking the
SARIF, `findings.json`, each scanner's raw bundle and any analysis documents.

**Is my repo's scan data stored anywhere?**
Only on your machine: run outputs and decisions live under
`<your-repo>/.security-council/` (gitignored by default). If you use the
validator panel, its transcripts land in `.llm-council/runs/`.
[data-boundaries.md](data-boundaries.md) lists everything that persists.

**Why does the fixture in this repo contain AWS keys?!**
They're fake, on purpose — `tests/fixtures/seedrepo/` is the intentionally
vulnerable practice/eval target. Never deploy it; allowlist it in your
secret scanner. [SECURITY.md](../SECURITY.md).

**Windows?**
Untested. Linux and macOS with Python 3.11+ are the developed-on platforms;
docker-based arms need a working docker.

**Is this open source?**
Source-available: you can read, evaluate, and test it freely, and copy the
CI templates for use with it; production use needs a license.
[LICENSE.md](../LICENSE.md).

**Can an AI assistant run this for me?**
Yes — an MCP server exposes scan/report/triage as tools with guardrails
(root-scoped paths, no recursive scans, human attribution required on
suppressions). [mcp.md](mcp.md).
