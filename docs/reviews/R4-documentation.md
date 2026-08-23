# R4 — Documentation review for the public repo (2026-08-23)

Council run on the README/docs gap after publishing to GitHub. Mode `quick`,
claude ("yes") + antigravity ("tradeoff") converged; codex timed out (quorum
2/2, not degraded, $0). Transcript:
`.llm-council/runs/20260823_052944_463596_8be58996b0a34ee9868a707aed4e48ee.md`.

## Two release-blockers (both peers, fixed in `5414ffd`)

1. **License incoherence** — public source + `Proprietary` pyproject metadata
   + no LICENSE file + CI docs inviting template copying. Fixed with explicit
   source-available terms (LICENSE.md): evaluation permitted, templates/action
   expressly copyable, all else reserved. *Owner may still swap in an OSS or
   BSL license — this was the conservative default matching declared intent.*
2. **Silent data boundary** — nothing public said the LLM arms and validator
   send source code to vendor-hosted APIs. Fixed: inline warning in the
   README's LLM section + `docs/data-boundaries.md` with the per-arm table
   and the "vendor origin ≠ FedRAMP/IL" statement.

## Adopted page set

README rewrite (DevSecOps first screen: value prop → $0 quickstart → CI →
opt-in LLM arms w/ boundary warning → safety teaser → honest limitations) +
docs/{getting-started, arms, data-boundaries, triage, safety-model,
architecture, mcp, compliance/emass, ci/{github,azure-devops,gitlab}} +
SECURITY.md (intentional-vuln fixture disclosure + scanner allowlist) +
CONTRIBUTING.md + HANDOFF labeled internal + v0.1.0 tag so the Action pins a
release instead of `@main`.

## The five over-claiming traps (now doc policy)

1. Never the word "calibrated" until `calibration == "fitted"` (code-enforced;
   also a CONTRIBUTING rule).
2. CI surfaces and eMASS: say "schema-validated locally / spec-conformant,
   not yet run on real infrastructure / a live eMASS instance" — exactly.
3. The IDOR demo ran on the project's own 12-file fixture — always say so;
   the eval corpus is n=7 — always say so; no numeric FP-reduction claims.
4. Cost figures are fixture-scale floors, not estimates.
5. Third-party claims (Trivy compromise) carry the GHSA id; fixture hazards
   (fake AKIA creds, injection canary) are disclosed before someone reports
   the repo itself.

Pre-publish checks the council demanded, verified: no tracked run outputs
under the fixture; test count claim reconfirmed (233 + 1 skip).
