Task: write a THREAT MODEL for this repository. Set `header.kind` to
"threat-model".

Cover, in this order, each as a `##` section:

1. **System overview** — what the software does, its main components, the
   external entry points (HTTP routes, CLI commands, message consumers, file
   inputs, scheduled jobs), and the trust boundaries between them. Cite the
   files that define each entry point.
2. **Assets** — the data and capabilities worth protecting (credentials, user
   data, secrets, privileged operations, availability), and where each lives
   in the code or configuration.
3. **Actors** — who interacts with the system (anonymous users, authenticated
   users, administrators, operators, third-party services, CI) and what each
   is trusted to do.
4. **Threats** — a table with columns: threat, STRIDE category, affected
   component/code (path:line), precondition, impact, existing control (or
   "none"), residual risk (high/medium/low). Ground every row in code you
   read; do not invent components.
5. **Existing controls** — authentication, authorization, input validation,
   crypto, logging and monitoring you found, with citations.
6. **Gaps and recommendations** — the highest-value defensive changes, in
   priority order, each tied to a threat row.

Keep it factual and specific to this codebase. Where the code is ambiguous,
say so rather than guessing.
