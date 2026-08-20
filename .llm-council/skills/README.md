# Host-installable agent skills for llm-council

This directory holds host-specific skill / instruction files you can install
into your coding agent's *global* config so every project picks up the
council routing rules — not just this project. They are independent of the
per-project files in `.llm-council/instructions/` (which the README install
flow appends to your project's `CLAUDE.md` / `AGENTS.md` / `GEMINI.md`).

Pick the host(s) you use:

## Claude Code

```bash
mkdir -p ~/.claude/skills/llm-council
cp .llm-council/skills/claude-code/SKILL.md ~/.claude/skills/llm-council/SKILL.md
```

Restart Claude Code. The skill becomes discoverable; it has YAML frontmatter
naming it `llm-council` so the host can surface it where it surfaces other
skills.

## Codex CLI

```bash
mkdir -p ~/.codex
cat .llm-council/skills/codex-cli/AGENTS.md >> ~/.codex/AGENTS.md
```

Codex CLI reads `~/.codex/AGENTS.md` as global agent instructions. Append
(don't overwrite) so existing entries are preserved.

## Antigravity CLI

```bash
mkdir -p ~/.gemini
cat .llm-council/skills/antigravity/GEMINI.md >> ~/.gemini/GEMINI.md
```

Antigravity CLI reads global instructions from `~/.gemini/GEMINI.md`.

After installing on any host, the prerequisite is that `llm-council` is on
PATH (via `uv tool install` or `pipx install`) and that an MCP transport is
wired up in the host's MCP config. See the project README's primary install
path for that.
