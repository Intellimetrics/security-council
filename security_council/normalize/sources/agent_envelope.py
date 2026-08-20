"""Agent finding envelope (sc-agent-finding/1) -> RawFinding + scan metadata."""

from __future__ import annotations

from ..base import RawFinding


def parse_envelope(env: dict) -> tuple[list[RawFinding], dict]:
    raws: list[RawFinding] = []
    for f in env.get("findings", []) or []:
        locs = f.get("locations", []) or []
        prim = next((loc for loc in locs if loc.get("role") == "primary"), locs[0] if locs else None)
        if not prim:
            continue
        raws.append(RawFinding(
            path=prim.get("path", ""), start_line=prim.get("start_line", 1),
            end_line=prim.get("end_line", prim.get("start_line", 1)),
            title=f.get("title", ""), description=f.get("description", ""),
            declared_cwe=list(f.get("cwe", []) or []), category=f.get("category"),
            severity_label=f.get("severity"), symbol=prim.get("symbol"),
            snippet=prim.get("snippet"), remediation=f.get("remediation"),
        ))
    scan = env.get("scan", {}) or {}
    meta = {
        "angle": scan.get("angle"),
        "completion": scan.get("completion"),
        "declined_categories": scan.get("declined_categories", []),
        "files_examined": scan.get("files_examined", []),
    }
    return raws, meta
