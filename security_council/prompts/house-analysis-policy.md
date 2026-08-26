Task: draft a SECURITY POLICY PROPOSAL for the team that owns this
repository. Set `header.kind` to "policy".

This is a document for humans to adopt and edit, grounded in what the code
actually does. It is NOT a scanner configuration. First read enough of the
repository to know its language(s), frameworks, external interfaces, data
handled, dependency and build tooling, and how it is deployed. Then write the
policy as `##` sections:

1. **Scope** — what this policy covers (this repository, its services and
   data), in plain language.
2. **Secure development** — required practices with a one-line rationale
   each: code review, branch protection, dependency pinning and update
   cadence, secret handling (no secrets in the tree; where they live
   instead), static analysis in CI, test expectations for security-relevant
   code.
3. **Authentication and authorization** — the rules the code must follow
   (for example: every route that reads or writes user-owned data checks
   ownership; sessions expire; passwords use a slow hash). Cite where the
   current code meets or misses each rule.
4. **Data handling** — classification of the data this system processes,
   retention, logging restrictions (what must never be logged), encryption
   at rest and in transit.
5. **Dependencies and supply chain** — allowed sources, vulnerability
   response SLA by severity, license constraints if visible.
6. **Vulnerability response** — how a finding is triaged, who decides, time
   to fix by severity, and how exceptions are recorded and expire.
7. **Deployment and operations** — configuration management, least
   privilege for service identities, monitoring and alerting expectations.

Where the repository already contains a policy, contributing guide, or
security document, build on it and say what you kept and what you changed.
Mark every requirement that the current code does not yet meet with
"(gap)" and a citation.
