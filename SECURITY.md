# Security

## Reporting a vulnerability

Report suspected vulnerabilities in security-council itself privately via
[GitHub security advisories](https://github.com/Intellimetrics/security-council/security/advisories/new)
rather than public issues. We aim to acknowledge reports within a week.

## ⚠️ This repository intentionally contains "vulnerabilities"

`tests/fixtures/seedrepo/` is a **deliberately vulnerable test fixture** — the
ground-truth corpus the scanner and its eval gate are tested against. It
contains, on purpose:

- seeded vulnerabilities (SQL injection, command injection, IDOR, weak
  crypto, and more), each labeled in `tests/fixtures/EXPECTED.yaml`;
- **realistic-format but fake AWS credentials** in
  `tests/fixtures/seedrepo/app/settings.py` (they are not, and never were,
  live credentials);
- a **clearly labeled prompt-injection canary** in
  `tests/fixtures/seedrepo/README.md` — an isolation regression test that any
  well-behaved scanning agent must ignore.

None of this is a leak, and reporting it is not necessary. If your
organization's secret scanning flags the fixture, allowlist the path:

```
# secret-scanner allowlist
tests/fixtures/seedrepo/**
tests/fixtures/raw/**
```

Never deploy the fixture application.

## Security posture of the tool itself

Design properties you can verify in the code (see
[docs/safety-model.md](docs/safety-model.md)):

- Scans run against an **isolated scratch copy** of your repo; arm and
  validator writes are discarded (`workspace.py`).
- A finding can never be silently hidden: suppression requires full,
  structurally-enforced attribution (invariant I6 in `model.py`), crypto and
  critical findings are never auto-suppressed (I7, guardrails G1/G7), and
  auto-suppression is **off by default** behind a double opt-in plus shadow
  mode.
- The agentic arms and validator send code to vendor-hosted LLM APIs — read
  [docs/data-boundaries.md](docs/data-boundaries.md) **before** scanning
  sensitive code; the default arm set is deterministic and local.
- The MCP server is root-scoped and refuses recursive scans
  (`mcp_server.py`).
