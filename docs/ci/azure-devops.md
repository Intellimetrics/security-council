# Azure DevOps (Server and Services)

**Who this is for:** teams on Azure DevOps — including on-prem **Server**, which most security products neglect. **You'll need:** an agent with Python 3.11+ and docker, and repo permission to edit pipelines.

Azure DevOps **Server** is a first-class target: everything below works
on-prem with no GitHub-connected services (no GHAzDO required).

## Setup

Copy [`templates/security-council.yml`](../../templates/security-council.yml)
into your repo and extend it:

```yaml
steps:
  - template: templates/security-council.yml
    parameters:
      scanPath: '$(Build.SourcesDirectory)'
      arms: 'semgrep,gitleaks,osv-scanner'
      failOnSeverity: 'high'
      gateBaseline: 'new'        # brownfield: docs/triage.md
      postPrThread: true
```

Agent requirements: Python 3.11+, `pip install security-council`, docker for
the scanner arms. For PR threads, grant the build service **Contribute to
pull requests** on the repo.

## What you get

- **`CodeAnalysisLogs` build artifact** containing `merged.sarif` — install
  the marketplace "SARIF SAST Scans Tab" extension and the findings render
  as a tab on every build.
- **File/line annotations** via `##vso[task.logissue]` — errors for
  gate-failing findings, warnings below the threshold, using the exact same
  filter as the exit gate (including `gateBaseline: new`, so baselined
  findings demote to warnings).
- The run summary attached via `##vso[task.uploadsummary]`.
- **One PR comment thread** on PR builds (REST `api-version=6.0`, works on
  Server 2020+), authenticated with `System.AccessToken`. The thread is
  `active` when the gate failed and `closed` when clean — passing builds
  don't nag reviewers.

## How the gate behaves

The template captures the scan's exit code, always publishes artifacts and
annotations, and re-raises the code in the final "gate" step. The annotate
step itself never fails a build — a bug in annotation must not mask or
manufacture a gate result.

*Status: annotation output, escaping, and REST payloads are tested against
recorded runs; the template has not yet executed on a real ADO Server
instance — reports from real pipelines are especially valuable.*
