---
name: llm-council
description: >-
  Read-only multi-agent council for second opinions before risky
  edits. Routes to the local CLI triad (Claude / Codex / Antigravity) plus
  optional OpenRouter / Ollama participants via the llm-council MCP server.
---

# LLM Council

When the user asks for a "council" review — natural triggers include
"use council", "go to council", "ask council", "take this to council",
or commands like /council, \council, /ask-council, \ask-council — call the
`llm-council` MCP tool `council_run`.

If the user wants to view or change configuration options (e.g. "open html automatically", "set defaults.auto_open_browser true"), or uses commands like /council config, \council config, /council-config, \council-config — call the `llm-council` MCP tool `council_config`.


Routing rules:
- Pass `current` as `claude` so transcripts record which host will
  synthesize and act on the council output.
- Omit `mode` to use the configured project default. Use `consensus` when the
  user explicitly wants assigned-stance debate (for/against/neutral). Use
  `peer-only` when the user wants to exclude this host from the council. Use
  `private-local` for loopback Ollama-only review. This prevents council
  routing to hosted/native peers but does not firewall the Ollama daemon;
  hard offline use also requires OS/network egress controls around it.
- Treat "on the diff" / "current diff" / "review my changes" as
  `include_diff: true`.
- Treat "with budget" or "max $X" as setting `max_cost_usd` to that
  value — the council will refuse to run if the pre-flight estimate
  exceeds the cap.
- Treat "continue from <run_id>" as setting `continuation_id` to that
  prior run; the new transcript will record `parent_run_id`.

Council output shape (when the host supports MCP outputSchema):
- `recommendation`: yes / no / tradeoff / leaning-yes / leaning-no /
  unknown — the unique leading final-round label; leaning-* when the top
  labels tie between a definite label and tradeoff with no opposing
  votes (peers agree on direction); unknown otherwise
- `agreement_count`: peers matching that unique leading label
- `degraded`: true when fewer than `min_quorum` peers labeled
- `transcript`: filesystem path to the markdown transcript

Before acting on council feedback, summarize agreements, surface real
disagreements, and ask the user before making large or risky edits.

Council is read-only by default. Council participants must not edit
files; this host agent remains responsible for deciding what to do next.

Do not send classified, regulated, secret, credential, or customer data
to council unless the user has explicitly confirmed the configured
participants are approved for that data.
