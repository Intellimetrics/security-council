# Operator guide: triage, baselines, suppressions

**Who this is for:** the person who owns the findings day to day — reviewing reports, deciding what's real, and keeping CI green honestly. Assumes you've run a scan ([tutorial.md](tutorial.md)).

The operator loop is designed around one principle: **decisions are scoped,
attributed, expiring, and auditable** — never a rule-wide mute button.

## Brownfield adoption in two commands

A first scan of any real repo fails the gate on the existing backlog. Accept
the backlog explicitly, then gate only what's *new*:

```bash
security-council scan .                      # the first, failing scan
security-council baseline set --operator you # snapshot it as the baseline
# in .security-council.yaml:  policy: {gate_baseline: "new"}
security-council scan . --gate-baseline new  # exit 0 unless NEW findings appear
```

Baselined findings still appear in every report (stamped
`baselineState: unchanged/updated` in SARIF); they just stop failing the
build. Findings that disappear are reported `absent` in the delta. Matching
is by root-cause fingerprint, then context hash, then path+CWE+sink — stable
across line drift. The baseline is an operator-set pointer; scans never move
it themselves.

## Suppressing a false positive (human path)

```bash
security-council suppress <finding_id> \
  --operator you --justification "md5 here is a non-security cache key" \
  [--accept-risk] [--expires-days 90] \
  [--vex-justification inline_mitigations_already_exist]
```

What you get, structurally:

- the decision is **scoped to one root cause** (G5) — it will never mute a
  rule, a CWE, or a path glob;
- it **expires** (default 90 days, G6) — on the first scan after expiry the
  finding comes back as `reopened: suppression_expired`;
- it **deactivates on code drift** (G8) — if the code around the finding
  changes (context hash mismatch), the finding reopens for re-validation and
  the old decision never silently reactivates;
- it is **fully attributed** (operator, timestamp, justification, decision
  ref) — invariant I6 makes an unattributed suppression unrepresentable;
- suppressed findings are withheld from operator-facing exports (eMASS,
  GitLab) but remain in `summary.md`'s appendix — demoted, not hidden.

Future scans reapply it automatically (`prior_decisions` in the manifest,
"Decision store" line in the summary).

## Recording ground truth (`outcome mark`)

```bash
security-council outcome mark <finding_id> --verdict fp --operator you --note "..."
```

Outcome marks are the **only** input to the scoring model's history term —
an anti-poisoning rule: machine decisions (auto-suppressions, shadow
decisions) are recorded for audit but never feed the prior that grounds
future machine decisions. Mark generously; it is how the system learns your
codebase's truth.

## Auto-suppression and shadow mode (off by default — read first)

Automatic suppression exists but requires **both**
`policy.auto_suppress: true` and `policy.accept_suppression_risk: true` —
the second flag is your explicit acknowledgement of the wrongful-suppression
risk documented in [safety-model.md](safety-model.md). Even then:

- the first `shadow_runs` (5) armed runs are **shadow mode**: would-be
  suppressions are recorded in `policy.json`/the decision store but nothing
  is hidden — review them before going live;
- the shadow counter counts only armed runs and **resets whenever
  suppression-relevant policy config changes**;
- crypto (G1) and critical (G7) findings are never auto-suppressed, at any
  threshold; a panel refutation of a deterministic-scanner finding without a
  fully-verified defender citation escalates to `needs_human` instead of
  demoting (G2) — and `needs_human` still fails the gate.

## Sharing decisions across a team

Everything lives under `<target>/.security-council/`:

```
decisions/by-root-cause/<fp>.json   # append-only history per root cause
baseline/latest.json
runs/<id>/...                       # keep these ignored
```

This repo's own `.gitignore` excludes the whole directory. A team that wants
shared suppressions/baselines should un-ignore `decisions/` and `baseline/`
in *their* repo and commit them — the records are plain, reviewable JSON, so
suppression changes show up in code review like any other change. Honest
limitation: records are not cryptographically signed yet; git history is the
audit trail.
