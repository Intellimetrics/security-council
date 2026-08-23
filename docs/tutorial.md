# Tutorial: your first scan, first report, first triage

**Who this is for:** anyone — no security background needed. In ~15 minutes
you'll scan a deliberately vulnerable practice repo, read the report,
understand what a finding is, and handle one like an operator would.

**You'll need:** Python 3.11+, Docker running, and a terminal. Everything in
this tutorial is free and offline — no API keys, and no code leaves your
machine.

Every output block below is real output, captured from these exact commands.

## 1. Install and check readiness

```bash
pip install git+https://github.com/Intellimetrics/security-council
git clone https://github.com/Intellimetrics/security-council
cd security-council          # we'll use its bundled practice repo
security-council doctor
```

```text
security-council doctor
  docker         ready  /usr/bin/docker
  semgrep       ready       docker: semgrep/semgrep
  gitleaks      ready       docker: zricethezav/gitleaks:latest
  osv-scanner   ready       docker: ghcr.io/google/osv-scanner:latest
  claude        ready       local: /home/you/.local/bin/claude
  ...
```

`doctor` never changes anything — it just reports which **arms** (independent
scanning tools) can run on this machine, and why not if they can't. You only
need the first four lines to be `ready` for this tutorial. The rows below
them are the optional AI arms; ignore them for now.

## 2. Scan the practice repo

`tests/fixtures/seedrepo/` is a tiny fake web app that ships with this
repository. It is **intentionally vulnerable** — seeded with real bug
patterns (and one deliberate decoy) so there's something to find. Scan it
with two of the free arms:

```bash
security-council scan tests/fixtures/seedrepo --arms semgrep,gitleaks
```

```text
security-council scan 20260823_101557  (target .../tests/fixtures/seedrepo)
  semgrep       ok        raw=3 normalized=3 2.41s
  gitleaks      ok        raw=2 normalized=2 0.17s
findings: 2 clusters  severity={'high': 1, 'medium': 1}
reports: .../tests/fixtures/seedrepo/.security-council/runs/20260823_101557  (summary.md, ...)
exit 1
```

Read that bottom-up:

- **`exit 1`** — the scan "failed the gate": at least one finding at or above
  the `high` severity threshold is open. In CI, this is what fails the build.
  (`0` would mean clean; `3` would mean a scanner broke.)
- **`2 clusters`** from `3 + 2 = 5` raw alerts — the tools' overlapping
  alerts were recognized as **two underlying problems**. You triage 2 things,
  not 5.
- Each arm line shows what it found and how long it took.

## 3. Read the report

Every scan writes a folder under `.security-council/runs/<timestamp>/`. The
human-readable piece is `summary.md` — open it in anything that renders
Markdown (or just read it as text):

```text
- **Gate:** FAIL — gating findings present (exit 1)

## At a glance
- **2 findings** (root-cause clusters): 1 high · 1 medium
- **Corroboration:** 1 confirmed by ≥2 independent vendor families · 1 only one eligible arm (singleton-by-policy)

## Findings register
| # | Severity | State | Family / CWE   | Title                      | Location          | Sources                              |
| 1 | **HIGH** | new   | secrets/CWE-798| AWS Access Key ID detected | app/settings.py:2 | gitleaks, semgrep (2 src / 2 vendor) |
| 2 | MEDIUM   | new   | injection/CWE-89| Formatted SQL query       | app/reports.py:9  | semgrep (1 src / 1 vendor) ⚠ singleton-by-policy |
```

The two most useful columns for a newcomer:

- **Sources** — finding #1 was reported by *two independent vendors*
  (gitleaks and semgrep both flagged the same hardcoded AWS key). When tools
  that work completely differently agree, it's very likely real. Finding #2
  has one source, but the ⚠ note explains *why* that's not suspicious:
  gitleaks only hunts secrets, so semgrep was the only runner *eligible* to
  catch a SQL issue ("singleton-by-policy" — alone, but expectedly so).
- **CWE** — a standard ID for the *kind* of weakness (CWE-798 = hardcoded
  credentials, CWE-89 = SQL injection). Handy for looking things up; the
  report links each one.

Scroll down in the real file and each finding has a detail section:
where it is, a code snippet (secrets are redacted — you'll see the location
but never the credential itself), which tools reported it, and a suggested
fix.

Machine-readable versions of the same content sit next to it:
`merged.sarif` (the industry-standard format GitHub/ADO understand),
`findings.json` (full data), `manifest.json` (what ran, versions, timings).

## 4. Handle a finding like an operator

Say your team reviews finding #2 and decides it's acceptable for now (this
is a demo — in the practice repo it's actually a real bug). First grab its
ID from the report (the `id` line in its detail section, e.g.
`14a881449f73c63d` — a unique fingerprint-derived name for this exact
problem). Then record a decision:

```bash
security-council suppress 14a881449f73c63d \
  --operator "$USER" \
  --justification "demo: accepted until Q4 refactor" \
  --target tests/fixtures/seedrepo
```

```text
recorded human suppressed for 14a881449f73c63d (root cause rootCause/v1:...);
applies on future scans, expires in 90 days
```

Three things just happened, and they're the heart of this tool's philosophy:

1. The decision is **scoped to this one root cause** — not "ignore rule X
   everywhere", which is how real bugs get missed.
2. It **expires in 90 days** and automatically cancels if the code around
   the finding changes — suppressions can't quietly outlive their reasons.
3. It's **recorded with your name and justification** in
   `.security-council/decisions/` — plain JSON your team can code-review.

Re-scan and watch it take effect — the finding is suppressed automatically
on every future scan (until expiry), and it *still appears in the report*,
just marked as suppressed. Nothing is ever silently deleted.

Two related commands you'll meet in real use:

```bash
# Adopting on an existing repo with old findings? Snapshot them once...
security-council baseline set --target tests/fixtures/seedrepo
# ...then only NEW findings fail the build:
security-council scan tests/fixtures/seedrepo --arms semgrep,gitleaks --gate-baseline new

# Teach the scorer your ground truth (was a finding real or not?):
security-council outcome mark <finding-id> --verdict fp --target tests/fixtures/seedrepo
```

## 5. Clean up

Everything the tutorial created lives in two folders inside the practice
repo, both ignored by git:

```bash
rm -rf tests/fixtures/seedrepo/.security-council
```

## Where to next

- **"What did those words mean?"** → [concepts.md](concepts.md)
- **Scan your own project** → `security-council scan .` in your repo, then
  [getting-started.md](getting-started.md) for configuration
- **Make it fail your CI builds** → [ci/](ci/)
- **Try the AI reviewers** (they find cross-file logic bugs the free
  scanners can't — but they cost money and send code to AI vendors; read
  the warning first) → [arms.md](arms.md) + [data-boundaries.md](data-boundaries.md)
- **"Why should I trust the automation?"** → [safety-model.md](safety-model.md)
