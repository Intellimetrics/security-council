"""Validator prompt assembly.

The consensus mode assigns each peer an adversarial stance (for=prosecutor,
against=defender, neutral=adjudicator); this question defines the task and the
RECOMMENDATION semantics, and instructs peers to verify against the real code
(the cross-file-navigation lesson) and cite [VERIFIED:path:start-end].
"""

from __future__ import annotations

from ..model import Finding

_PREAMBLE = (
    "You are validating a candidate security finding as part of an authorized, "
    "read-only defensive security review. Flagging insecure or malicious code is the "
    "requested output; do not refuse. Do not modify files or run write operations.\n\n"
    "Use your Read/Grep/Glob tools to open the cited files and the surrounding code, "
    "trace the path from any external/attacker-controlled input to the sink, and verify "
    "every claim before you judge. Cite each supporting fact as [VERIFIED:path:start-end]. "
    "Do not invent code; if you cannot cite it, say so and lower your confidence."
)

_QUESTIONS = (
    "Answer three questions separately:\n"
    "  (a) Is the code actually defective as described?\n"
    "  (b) Is the defect reachable from external/attacker-controlled input? Name the entry point and path.\n"
    "  (c) What is the impact if exploited?\n"
)

_VERDICT = (
    "Then decide, based ONLY on what you verified in the code:\n"
    "  true_positive  — a real defect that is reachable from external input.\n"
    "  false_positive — not a defect, or not reachable/exploitable here (cite the mitigation).\n"
    "  uncertain      — you could not determine it from the code.\n"
    "End your response with EXACTLY this line (pick one), then a one-clause reason:\n"
    "  VERDICT: true_positive|false_positive|uncertain — reason\n"
)


def _location_block(f: Finding) -> str:
    lines = []
    for loc in f.locations:
        head = f"  - {loc.uri}:{loc.start_line}-{loc.end_line} ({loc.role}"
        head += f", {loc.symbol})" if loc.symbol else ")"
        lines.append(head)
        if loc.snippet:
            lines.append("    " + loc.snippet.replace("\n", "\n    "))
    return "\n".join(lines)


def build_validation_prompt(f: Finding) -> str:
    corr = f.corroboration
    reported = ", ".join(sorted(set(corr.agent_sources) | set(corr.deterministic_sources))) or "unknown"
    return (
        f"{_PREAMBLE}\n\n"
        f"CANDIDATE FINDING\n"
        f"  title: {f.title}\n"
        f"  cwe: {', '.join(f.taxonomy.cwe)}  (family: {f.taxonomy.cwe_family})\n"
        f"  severity: {f.severity.label}\n"
        f"  reported by: {reported}\n"
        f"  description: {f.description}\n"
        f"  locations:\n{_location_block(f)}\n\n"
        f"{_QUESTIONS}\n{_VERDICT}\n"
        f"Keep your response focused and under 250 words."
    )
