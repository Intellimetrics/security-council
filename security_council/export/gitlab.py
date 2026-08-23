"""GitLab exports: the native SAST security report + the Code Quality report.

Verified 2026-08-23 against the OFFICIAL schema — gitlab-org/security-products/
security-report-schemas ``dist/sast-report-format.json`` v15.2.4, vendored
verbatim at ``tests/fixtures/schemas/gitlab-sast-report-15.2.4.schema.json``
(draft-07; every test payload validates against it). Contract facts encoded:

- top-level requires ``scan`` / ``version`` / ``vulnerabilities``; ``version``
  declares the SCHEMA version ("15.2.4"), not ours;
- ``scan.start_time``/``end_time`` match ``YYYY-MM-DDTHH:MM:SS`` — **no
  timezone suffix** (the classic rejected-report gotcha);
- ``scan.analyzer``/``scanner`` require id/name/version/vendor{name};
- every vulnerability requires ``id`` (stable string — we use the derived
  finding id), ``location``, and **>=1 identifier**; severity enum is
  ``Info|Unknown|Low|Medium|High|Critical``.

``gl-sast-report.json`` (via ``artifacts:reports:sast``) feeds the Security
Dashboard / MR security widget on Ultimate. ``gl-code-quality-report.json``
(via ``artifacts:reports:codequality``, GitLab's documented CodeClimate
subset: description/check_name/fingerprint/severity/location.path/lines.begin)
gives inline MR diff annotations on EVERY tier including Free — fingerprints
are the derived finding id, stable across scans by construction.

Both render from dispositions (D7): suppressed / accepted-risk / demoted
findings are withheld, identically to the eMASS and gate semantics.
"""

from __future__ import annotations

import re
from datetime import datetime

from .. import __version__
from ..model import Finding, canonical_cwe
from . import open_unresolved

SCHEMA_VERSION = "15.2.4"
_CWE_NUM_RE = re.compile(r"^CWE-(\d+)$")
SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info"}
# CodeClimate severities (GitLab code-quality subset)
CODE_QUALITY_SEVERITY = {"critical": "blocker", "high": "critical",
                         "medium": "major", "low": "minor", "info": "info"}

_TOOL = {"id": "security-council", "name": "security-council",
         "version": __version__ or "0.0.0",
         "vendor": {"name": "Intellimetrics"}}


def _gl_time(stamp: str) -> str:
    """ISO input -> the schema's timezone-less `YYYY-MM-DDTHH:MM:SS`."""
    dt = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _identifiers(f: Finding) -> list[dict]:
    """>=1 identifier, numeric CWEs first (they drive GitLab's grouping),
    then our rule id so a CWE-noinfo finding still satisfies minItems 1."""
    out = []
    for c in f.taxonomy.cwe:
        c = canonical_cwe(c)
        m = _CWE_NUM_RE.match(c)
        if m:
            out.append({"type": "cwe", "name": c, "value": m.group(1),
                        "url": f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"})
    out.append({"type": "security_council_rule", "name": f.rule.id, "value": f.rule.id})
    return out


def to_gitlab_sast(findings: list[Finding], manifest: dict) -> tuple[dict, dict]:
    """-> (gl-sast-report.json document, meta with withheld accounting)."""
    vulns, withheld = [], 0
    for f in findings:
        if not open_unresolved(f):
            withheld += 1
            continue
        loc = f.locations[0]
        vulns.append({
            "id": f.id,
            "name": f.title,
            "description": f.description,
            "severity": SEVERITY.get(f.severity.label, "Unknown"),
            "identifiers": _identifiers(f),
            "location": {"file": loc.uri, "start_line": loc.start_line,
                         "end_line": loc.end_line},
        })
    doc = {
        "version": SCHEMA_VERSION,
        "scan": {
            "analyzer": dict(_TOOL),
            "scanner": dict(_TOOL),
            "type": "sast",
            "status": "success",
            "start_time": _gl_time(manifest.get("started_at")),
            "end_time": _gl_time(manifest.get("finished_at") or manifest.get("started_at")),
        },
        "vulnerabilities": vulns,
    }
    return doc, {"vulnerabilities": len(vulns), "withheld_by_disposition": withheld}


def to_gitlab_code_quality(findings: list[Finding]) -> tuple[list[dict], dict]:
    """-> (gl-code-quality-report.json array, meta). GitLab's documented
    CodeClimate subset; renders as inline MR diff annotations on all tiers."""
    rows, withheld = [], 0
    for f in findings:
        if not open_unresolved(f):
            withheld += 1
            continue
        loc = f.locations[0]
        cwe = canonical_cwe(f.taxonomy.cwe[0]) if f.taxonomy.cwe else "CWE-noinfo"
        rows.append({
            "description": f"[{cwe}] {f.title}",
            "check_name": f.rule.id,
            "fingerprint": f.id,
            "severity": CODE_QUALITY_SEVERITY.get(f.severity.label, "info"),
            "location": {"path": loc.uri, "lines": {"begin": loc.start_line}},
        })
    return rows, {"rows": len(rows), "withheld_by_disposition": withheld}
