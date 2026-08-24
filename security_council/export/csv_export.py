"""CSV export — the full triage register, one row per finding.

This is a *triage* format, not a compliance export: demoted / suppressed /
refuted findings are INCLUDED with their state and lifecycle spelled out
(demote-never-hide), unlike the D7-withholding compliance exporters
(eMASS / OpenVEX / OSCAL / CKLB). Anyone filtering should do it on the
`state` / `lifecycle` columns, in the open.

Hardening: every cell passes one boundary that neutralizes spreadsheet formula
injection — a leading ``= + - @`` or tab/CR is prefixed with ``'`` (the OWASP
CSV-injection guidance). LLM- and repo-derived text lands in these cells, so
this is a real attack surface, same as the markdown escaping boundary.
"""

from __future__ import annotations

import csv
import io

from ..model import Finding

COLUMNS = [
    "finding_id", "cluster_id", "severity", "state", "lifecycle", "cwe_family",
    "cwe", "title", "rule", "path", "start_line", "end_line", "sources",
    "vendor_families", "deterministic_sources", "agent_sources",
    "validation_verdict", "confidence", "calibration", "vex_status", "expires",
]


def _neutralize(value: object) -> str:
    s = "" if value is None else str(value)
    return f"'{s}" if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _row(f: Finding) -> list[str]:
    loc = f.locations[0] if f.locations else None
    v = f.validation
    return [_neutralize(x) for x in (
        f.id, f.cluster_id or "", f.severity.label, f.disposition.state,
        f.disposition.lifecycle, f.taxonomy.cwe_family or "",
        " ".join(f.taxonomy.cwe), f.title, f.rule.id,
        loc.uri if loc else "", loc.start_line if loc else "",
        loc.end_line if loc else "",
        " ".join(sorted({p.source_id for p in f.provenance})),
        " ".join(sorted(set(f.corroboration.vendor_families))),
        " ".join(f.corroboration.deterministic_sources),
        " ".join(f.corroboration.agent_sources),
        v.verdict if v else "", f"{v.confidence:.3f}" if v else "",
        v.calibration if v else "", f.disposition.vex_status or "",
        f.disposition.expires_at or "",
    )]


def to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\n")
    w.writerow(COLUMNS)
    for f in findings:
        w.writerow(_row(f))
    return buf.getvalue()
