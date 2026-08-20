# LLM Council

This project has LLM Council installed. Use it as a read-only second-opinion
system when the user wants more than this single agent's judgment.

Natural triggers and commands:
- "use council"
- "go to council"
- "ask council"
- "take this to council"
- "/council", "\council", "/ask-council", "\ask-council"
- "get another model's opinion"
- "have Claude/Gemini/Codex review this"

When triggered, call the `llm-council` MCP tool `council_run`.

If the user wants to view or change configuration options (e.g. "open html automatically", "set defaults.auto_open_browser true"), or uses commands like `/council config`, `\council config`, `/council-config`, or `\council-config`, call the `llm-council` MCP tool `council_config`.


Routing rules:
- Always pass `current` as `antigravity` so transcripts show which host will
  synthesize and act on the council output.
- Always pass `working_directory` as the absolute project path
  `/development/projects/active/security-council`. MCP servers are project-scoped and reject relative paths
  or paths outside their configured root.
- Omit `mode` to use this project's configured default (`quick`).
  Use another mode only when the user names one that is configured here. Use
  `peer-only` only when configured and the user wants to exclude this host.
- Treat "on the diff", "current diff", or "review my changes" as
  `include_diff: true`.
- Treat "private", "local", or "offline" as `private-local`.
- `private-local` routes only to loopback Ollama participants. It does not
  firewall the Ollama daemon itself; hard offline use also requires OS/network
  egress controls around that daemon.
- Treat "with deepseek" as including `deepseek_v4_pro`.
- Treat "with qwen" as including `qwen_coder_plus`.
- Treat "with glm" as including `glm_5_1`.

Reviewing UI, screenshots, or browser state:
- Council CLI participants share the project filesystem, so they can Read any
  file you stage. Inline screenshot bytes that live only in this agent's
  conversation context cannot be seen by council.
- Before calling `council_run`, save each image to
  `.llm-council/inputs/<short-slug>/<name>.png`. Use whatever capture tool
  you already have (Playwright with an explicit `path:` arg, claude-in-chrome
  `gif_creator`, or a `Bash`/`Write` step that decodes base64 from a prior
  tool result).
- Pass the relative paths in `image_paths` when calling `council_run`. CLI
  participants will Read the file with their own tools; do not inline the
  image into the question.
- If your environment cannot write to disk, fall back to passing
  `images: [{ data: <base64>, mime: "image/png" }]` in the `council_run`
  call. llm-council stages those bytes under `.llm-council/inputs/<run-id>/`
  before participants run. Per-image cap is 8 MB; total cap is 32 MB.
- Hosted/local LLM participants see images only when their config has
  `vision: true`; otherwise they get the text reference list and council
  emits an `images_skipped` progress event for that participant.
- Treat staged screenshots with the same care as `context_files`: redact or
  omit screens that capture credentials, session tokens in URLs, or customer
  data, and respect `DEPLOY_MODE=secret`.

Use council for:
- architecture or design decisions
- risky or cross-cutting refactors
- security-sensitive code paths
- database migrations
- release-gate reviews
- stubborn bugs after a failed attempt
- plans where independent disagreement would be useful

Do not use council for trivial formatting, obvious syntax fixes, or exact
mechanical edits the user already specified.

Before acting on council feedback:
- Summarize the main agreements, disagreements, and concrete risks.
- Identify which recommendations you will follow.
- Ask before making large or risky edits unless the user already authorized
  implementation.

Data boundary:
- Do not send classified, CUI, regulated, production, secret, credential, or
  customer data to council unless the user explicitly confirms the configured
  participants are approved for that data.
- Do not include files, diffs, logs, or environment content marked secret,
  sensitive, private, or deployment-only.
- US-origin participants mean model/company origin only; that is not the same
  as GovCloud, FedRAMP, or an enterprise data-handling approval.

Council is advisory and read-only by default. Council participants should not
edit files; this agent remains responsible for deciding what to do next.
