# GitLab CI

## Setup

```yaml
# .gitlab-ci.yml
include:
  - local: 'templates/security-council.gitlab-ci.yml'

security_council:
  variables:
    SECURITY_COUNCIL_ARMS: 'semgrep,gitleaks,osv-scanner'
    SECURITY_COUNCIL_FAIL_ON: 'high'
    SECURITY_COUNCIL_GATE_BASELINE: 'new'   # brownfield: docs/triage.md
```

Runner requirements: Python 3.11+; docker for the scanner arms (docker
socket, `docker:dind`, or install the scanner binaries in the image).

## What you get, per tier

| Artifact | GitLab feature | Tier |
|---|---|---|
| `gl-sast-report.json` (`artifacts:reports:sast`) | Security Dashboard + MR security widget | Ultimate |
| `gl-code-quality-report.json` (`artifacts:reports:codequality`) | **Inline MR diff annotations** | **All tiers, incl. Free** |
| `security-council.sarif`, `security-council-summary.md` | plain artifacts for humans/other tools | all |
| MR summary note | one comment per pipeline, gate verdict + top findings table | all (needs a token) |

The SAST report conforms to the **official GitLab security-report schema
15.2.4** (vendored in this repo's test suite; every payload is
schema-validated). Code-quality fingerprints are security-council's stable
derived finding ids, so annotations track across pushes.

## MR notes need a real token

`CI_JOB_TOKEN` cannot post notes. Create a project access token with `api`
scope and expose it to the job as `SECURITY_COUNCIL_GITLAB_TOKEN` (masked
CI/CD variable). Without it the note is skipped with a logged reason — never
an error.

## How the gate behaves

Same pattern as the other platforms: the scan's exit code is captured, all
reports and artifacts publish (`artifacts: when: always`), and the job exits
with the captured code last. Suppressed/demoted findings are withheld from
both reports per the disposition rules ([../triage.md](../triage.md)).

*Status: reports are validated against the official schema and the REST
payloads are tested; the job template has not yet run on a real GitLab
project — issue reports from real pipelines welcome.*
