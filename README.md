# security-council

Parallel, multi-agent security scanning for government and commercial codebases.
Runs the coding-agent CLIs (Claude Code, Codex, Antigravity) and deterministic
scanners as independent "arms," cross-validates every finding with an adversarial
validator panel to remove false positives, and emits standards-based reports
(SARIF 2.1.0, OpenVEX, OSCAL, eMASS, CKLB, SBOM).

Status: **M0 — spikes and scaffolding.** Not yet functional.

Design: see `security-council-is-to-be-snoopy-prism.md` in the author's plan store.

Derived from [llm-council](https://github.com/Intellimetrics/llm-council); the
validator panel is a specialization of llm-council's `consensus` mode.
