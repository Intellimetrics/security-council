# MCP server

**Who this is for:** users of AI assistants (Claude Code or any MCP client) who want the assistant to run scans and triage on their behalf, safely.

Exposes security-council to AI assistants (Claude Code, or any MCP client)
as typed tools over stdio.

## Setup

```bash
pip install "security-council[mcp]"     # brings the mcp>=2 SDK
```

`.mcp.json` in the project you want scanned:

```json
{
  "mcpServers": {
    "security-council": {
      "command": "security-council-mcp",
      "env": {"SECURITY_COUNCIL_MCP_ROOT": "/abs/path/to/project"}
    }
  }
}
```

Transport status: live-handshaken against mcp 2.0.0 (protocol 2025-11-25);
`tests/test_mcp_handshake.py` keeps the real stdio handshake verified
wherever the extra is installed.

## Tools

| Tool | What it does |
|---|---|
| `sc_scan` | Run a scan (arms, validate, fail-on-severity, gate-baseline overrides); returns run summary + exit code |
| `sc_doctor` | Arm availability with reasons |
| `sc_report` | Summarize/export a run: `json`, `md`, or `emass` |
| `sc_last_run` | Latest run's summary for a target |
| `sc_baseline` | Show or set the operator baseline |
| `sc_suppress` | Record a **human** suppression/accepted-risk (operator + justification required, expiring, root-cause-scoped) |
| `sc_outcome_mark` | Record ground truth (tp/fp) — feeds the scoring history term |
| `sc_decisions_verify` | Audit every stored decision's signature against `allowed_signers`; says which the effective policy would refuse |
| `sc_config` | Effective merged configuration |

`sc_baseline` (set), `sc_suppress` and `sc_outcome_mark` accept `signing_key`
and honour `$SECURITY_COUNCIL_SIGNING_KEY` / `decisions.signing_key`; under
`require_signatures: enforce` a write without one is refused with the steps to
fix it. There is no terminal for a passphrase prompt over MCP, so pass a
`.pub` whose private half is loaded in `ssh-agent`, or an unencrypted key.
See [signing.md](signing.md).

Handler errors come back as `isError` tool results carrying the real message
(not sanitized protocol errors).

## Guards

- **Root scoping:** every path argument must be absolute and resolve inside
  `SECURITY_COUNCIL_MCP_ROOT`; escapes and relative paths are refused with
  actionable errors. One server serves one project tree.
- **Nesting guard:** every arm subprocess carries
  `SECURITY_COUNCIL_NESTED=1`. If the server finds it set, `sc_scan` refuses
  — an agentic arm that discovers this MCP server cannot recursively launch
  scans (read-only tools keep working).
- The suppression/outcome tools require explicit `operator` attribution,
  same as the CLI — an AI assistant using these tools is acting *for* a
  human, and the record says which one.

Mind the obvious implication of `sc_scan` + LLM arms: an assistant can spend
real money and send code to vendors. Configure `arms.enabled` in the target's
`.security-council.yaml` accordingly ([data-boundaries.md](data-boundaries.md)).
