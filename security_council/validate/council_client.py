"""Transport to `llm-council run --json` (subprocess, per design decision D2).

security-council does not import llm_council; it shells out to the CLI and parses
the JSON. This survives llm-council's refactors and keeps its recursion guard
intact. We deliberately clear LLM_COUNCIL_NESTED for this call because we are
explicitly convening a council, not accidentally recursing inside one.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import proc


@dataclass
class PeerResult:
    name: str
    ok: bool
    label: str | None                  # yes | no | tradeoff  (RECOMMENDATION)
    stance: str | None                 # for | against | neutral
    model: str | None
    confidence: str | None
    verdict: str | None = None       # parsed from an explicit "VERDICT:" line
    blockers: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    error: str = ""
    # llm-council >= 0.23.0 classifies per-peer failures (cli.py emits
    # `error_kind` in --json results). `content_refused` = the provider's
    # content policy declined the prompt — an operator-actionable failure
    # (rephrase as verification, R14), distinct from a crash or timeout.
    error_kind: str | None = None


@dataclass
class CouncilResult:
    ok: bool
    degraded: bool
    results: list[PeerResult]
    metadata: dict = field(default_factory=dict)
    transcript_path: str | None = None
    error: str = ""


def parse(payload: dict) -> CouncilResult:
    meta = payload.get("metadata", {}) or {}
    peers = []
    for r in payload.get("results", []) or []:
        peers.append(PeerResult(
            name=r.get("name"), ok=bool(r.get("ok")), label=r.get("label"),
            stance=r.get("stance"), model=r.get("model"), confidence=r.get("confidence"),
            blockers=list(r.get("blockers", []) or []),
            evidence=list(r.get("evidence", []) or []), error=r.get("error", "") or "",
            error_kind=r.get("error_kind") or None))
    return CouncilResult(
        ok=any(p.ok for p in peers), degraded=bool(meta.get("degraded")),
        results=peers, metadata=meta, transcript_path=payload.get("transcript"))


_VERDICT_RE = re.compile(r"VERDICT:\s*(true_positive|false_positive|uncertain)", re.I)
_SECTION_RE = re.compile(r"^###\s+([\w.-]+)\s*\(", re.M)


def _verdicts_from_transcript(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return {}
    out: dict[str, str] = {}
    marks = list(_SECTION_RE.finditer(text))
    for i, mo in enumerate(marks):
        name = mo.group(1)
        body = text[mo.end():(marks[i + 1].start() if i + 1 < len(marks) else len(text))]
        vm = _VERDICT_RE.search(body)
        if vm:
            out[name] = vm.group(1).lower()
    return out


def run_council(question: str, *, cwd, mode: str = "consensus",
                context_files: list[str] | None = None, max_cost_usd: float | None = None,
                timeout: int = 600, llm_council_bin: str = "llm-council",
                config_file: str | Path | None = None,
                current: str | None = None,
                participants: tuple[str, ...] | list[str] | None = None,
                stances: dict[str, str] | None = None) -> CouncilResult:
    cmd = [llm_council_bin, "run", "--mode", mode, "--json", "--cwd", str(cwd)]
    if config_file:
        cmd += ["--config", str(config_file)]
    if current:
        cmd += ["--current", current]
    if participants:
        cmd += ["--participants", ",".join(participants)]
    for participant, stance in (stances or {}).items():
        cmd += ["--stance", f"{participant}={stance}"]
    for c in context_files or []:
        cmd += ["--context", c]
    if max_cost_usd is not None:
        cmd += ["--max-cost-usd", str(max_cost_usd)]
    cmd += [question]
    env = {k: v for k, v in os.environ.items() if k != "LLM_COUNCIL_NESTED"}
    r = proc.run_command(cmd, timeout=timeout, cwd=str(cwd), env=env,
                         kill_process_group=True)
    if not r.stdout.strip():
        return CouncilResult(False, True, [], error=(r.stderr or "no output")[:500])
    try:
        payload = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        return CouncilResult(False, True, [], error=f"bad council json: {e}")
    result = parse(payload)
    verdicts = _verdicts_from_transcript(result.transcript_path)
    for peer in result.results:
        if peer.name in verdicts:
            peer.verdict = verdicts[peer.name]
    return result
