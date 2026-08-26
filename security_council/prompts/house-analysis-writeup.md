Task: write DEFENDER-FACING VULNERABILITY WRITE-UPS for this repository.
Set `header.kind` to "writeup".

This document is dual-use. It is kept out of shareable reports by the caller.
Its audience is the engineers who will fix the problems and the reviewers
who must understand them; it is not an advisory for publication and not an
exploitation guide.

If the caller supplied a findings digest below, write one `##` section per
finding, in the digest's order, titled with the finding id and title. Verify
each finding against the code before writing; if you believe a finding is
wrong, say so in its section and explain why with citations. If no digest was
supplied, write up the most serious issues you can find yourself (at most
eight).

Each section contains:

- **Summary** — two sentences: what is wrong and why it matters.
- **Affected code** — every relevant location as path:line with a short
  quote of the code (the code as it is, not a modified version).
- **Root cause** — the design or implementation mistake, not just the
  symptom.
- **Preconditions and impact** — who can trigger it, from where, and what
  they get. Describe; do not demonstrate. No payloads, no request bodies,
  no shell commands, no exploit code.
- **Remediation** — the fix, specific to this code. Defensive code snippets
  (the corrected version) are welcome.
- **Verification** — how a reviewer confirms the fix worked without
  attacking the system (a unit test to add, a log line to check, a
  configuration to inspect).
- **Related weaknesses** — other places in the tree with the same pattern,
  if any.

Finish with `## Cross-cutting notes`: shared root causes across the sections
and a suggested fix order.
