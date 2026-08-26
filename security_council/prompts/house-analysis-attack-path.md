Task: write an ATTACK-PATH ANALYSIS for this repository. Set `header.kind`
to "attack-path".

This document is dual-use. It is kept out of shareable reports by the caller
and is written for defenders: it explains WHICH chains of weaknesses matter
most, so they can be broken. It must not become an attacker's runbook.

For each of the most significant attack paths you can support with code you
read (aim for three to six), write a `##` section containing:

- **Goal** — what an attacker would achieve (data, privilege, availability).
- **Entry point** — the external surface that starts the chain (path:line).
- **Chain** — the sequence of weaknesses, each as: affected code
  (path:line), the class of weakness (for example "SQL query built from a
  request parameter", "missing ownership check"), and why control passes to
  the next step. Describe; do not demonstrate. No payloads, no request
  bodies, no shell commands, no exploit code.
- **Preconditions** — what must be true (network position, an account,
  a specific configuration).
- **Impact** — concrete and bounded.
- **Break the chain** — the single cheapest defensive change that stops the
  path, and where to make it.
- **Detection** — what a defender would see in logs or metrics.

Finish with a `## Priority` section ranking the paths by impact and ease,
with one sentence of justification each.

If the caller supplied a findings digest, treat those findings as candidate
chain links and cite them by id; verify them against the code before relying
on them.
