Task: write SECURITY HARDENING PROPOSALS for this repository. Set
`header.kind` to "hardening".

Read the code, its dependency manifests, configuration, build and CI files,
and any deployment descriptors (Dockerfiles, compose files, Kubernetes
manifests, infrastructure-as-code). Then write a prioritized list of
hardening changes, each as a `##` section with:

- **Change** — one sentence.
- **Why** — the weakness or missing control it addresses, with the file and
  line that shows it.
- **How** — what to change, concretely. Configuration and code snippets that
  implement the DEFENCE are welcome (a stricter header, a parameterized
  query, a pinned dependency, a dropped capability). Do not include anything
  that demonstrates the attack.
- **Cost and risk** — effort (small/medium/large) and what could break.
- **Priority** — P1 (do first) to P3, with the reason.

Group the sections under these `##` headings where applicable:
authentication and session management; authorization; input handling and
output encoding; secrets and configuration; cryptography; dependencies and
supply chain; logging, monitoring and error handling; build, CI and
deployment; data protection.

Prefer changes that remove whole classes of bugs (a query builder, a central
authorization check, a linter rule) over one-off patches.
