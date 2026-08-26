# Concepts & glossary

**Who this is for:** anyone who hit an unfamiliar term. Plain language first;
the deep-dive links go to the expert pages.

### Arm
One independent tool that hunts for problems. Some arms are traditional
scanners (fast, free, pattern-based); some are AI reviewers (slower, paid,
can follow logic across files). They all run in parallel and their results
are merged. *Why the name:* they're the independent limbs of one body — each
reaches places the others can't. Catalog: [arms.md](arms.md).

### Finding
One security problem, described with: where it is (file and lines), what
kind it is (CWE), how bad it is (severity), who found it, and what to do
about it. The tutorial walks through reading one: [tutorial.md](tutorial.md).

### Cluster / root cause
Different tools describe the same underlying bug differently — one flags the
database line, another flags the request handler two files away. Clustering
recognizes these as **one problem with one root cause** and merges them, so
five overlapping alerts become one finding with five pieces of supporting
evidence. You triage problems, not alerts.

### Corroboration / vendor family
How many *independent* sources agree a finding is real. Independence is
measured by **vendor family** — two Anthropic-based arms agreeing counts
barely more than one, but an Anthropic arm, an OpenAI arm, and a traditional
scanner agreeing is strong evidence. "Singleton-by-policy" means only one
arm was even *eligible* to find this category (e.g. only gitleaks hunts
secrets in a scanners-only run), so being alone is expected, not suspicious.

### Severity & the gate
Findings are ranked `critical / high / medium / low / info`. The **gate** is
the pass/fail decision for CI: if any finding at or above your threshold
(default `high`) is open and unresolved, the scan exits with code `1` and
the build fails. Exit `0` = clean, `3` = a scanner itself broke (result
incomplete), `2` = you invoked it wrong.

### CWE
An industry-standard catalog of *kinds* of weakness — CWE-89 is SQL
injection, CWE-798 is a hardcoded credential. Using standard IDs is what
lets different tools' findings be compared, merged, and exported to
compliance systems.

### SARIF
The industry-standard JSON format for static-analysis results. GitHub, Azure
DevOps, and many other tools consume it natively — it's how findings become
PR annotations and code-scanning alerts. Every run writes `merged.sarif`.

### Disposition (and *demote* vs *suppress*)
A finding's current standing. Three moves matter:

- **Demoted** — judged a likely false positive (e.g. by the validator
  panel). It stops failing the build but **stays visible** in every report,
  listed in an appendix. Nothing is deleted.
- **Suppressed** — a recorded decision (usually by a human, with name and
  justification) to hide it from operator-facing exports. It expires (90
  days) and self-cancels if the nearby code changes.
- **Reopened** — a suppressed finding whose suppression expired or whose
  code drifted; it's back and gates again.

The iron rule: *demote, never silently delete* — [safety-model.md](safety-model.md).

### Baseline
A snapshot of the findings you've decided to live with for now. With
`--gate-baseline new`, only findings **not** in the snapshot fail the build —
that's how you adopt the tool on a codebase with an existing backlog without
turning CI permanently red. [triage.md](triage.md).

### Signed decision
A suppression, baseline or ground-truth mark that carries a signature made
with the operator's **SSH key** (the same key that pushes to your git host).
Every scan checks it against `allowed_signers`, a short list of trusted keys
committed with the decisions. If it doesn't check out — no signature, edited
afterwards, unknown key, copied from another repo — the decision is not
applied and the finding comes back. It proves *who* decided, not that they
were right. [signing.md](signing.md).

### Validator panel
An optional cross-examination step (`--validate`): for each finding, three
AI seats on **different vendors** argue it out — a prosecutor (argues it's
real), a defender (argues it's not, and must point at actual mitigating
code), and an adjudicator. Every citation is checked against your repo; a
defender that cites code that doesn't exist can never win. Verdicts demote
findings or escalate them to human review — never delete them.

### Shadow mode
The rehearsal phase for automatic suppression (which is off by default).
When first armed, the system spends five runs *recording what it would have
suppressed* without actually doing it, so you can audit its judgment before
trusting it.

### Fingerprint
Every finding gets identity hashes computed from *what* the problem is —
never from line numbers. So when your code shifts down three lines, the
finding keeps its identity: baselines still match, suppressions still apply,
and nothing "reappears" spuriously.

### Run directory
Each scan writes `.security-council/runs/<timestamp>/` inside the scanned
repo: `summary.md` (read this one), `merged.sarif`, `findings.json`,
`policy.json` (the scoring audit trail), `manifest.json` (what ran, versions,
cost). Ignored by git.
