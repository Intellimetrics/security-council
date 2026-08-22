"""eMASS static-code-scans export (DoD lane, D6/D7).

Target: POST ``/api/systems/{systemId}/static-code-scans`` per the official
eMASS REST OpenAPI spec (mitre/emass_client ``docs/eMASSRestOpenApi.yaml``,
verified 2026-08-22) and MITRE's ``emasser`` reference client. Contract facts
this module encodes — all verified against the spec, not assumed:

- The request body is an **array** of ``{application, applicationFindings}``
  objects (the spec's own example and the emasser client both wrap in an
  array, even though the schema component says object — we emit the array).
- ``applicationFindings`` rows are ``additionalProperties: false``: exactly
  ``codeCheckName`` (str), ``scanDate`` (unix int), ``cweId`` (str), ``count``
  (int), optional ``rawSeverity`` — nothing else may be present.
- ``cweId`` is a **numeric string without the "CWE-" prefix** (spec example
  ``'155'``). Findings whose primary CWE has no number (``CWE-noinfo``) cannot
  be represented and are returned in ``meta["skipped"]`` — never silently
  dropped.
- ``rawSeverity`` enum is ``Low | Medium | Moderate | High | Critical``. We map
  medium -> ``Moderate`` (the eMASS/RMF-native term; ``Medium`` also exists in
  the enum but one spelling keeps rows stable). ``info`` has no enum value, so
  info-only rows omit the optional field.
- To clear an application's findings: a body whose only finding row is
  ``{"clearFindings": true}``.

Disposition semantics (D7: one ``render_decision`` feeds every export): only
findings an operator must still act on are exported — open/reopened lifecycle
and not panel-refuted. Suppressed / accepted-risk / demoted findings stay in
summary.md's appendix and the (future) VEX lane; they do not pollute the
assets module feed.

Rows are CWE-keyed: one row per primary CWE, ``codeCheckName`` =
``"CWE-<n> (<family>)"`` — deliberately stable across scans so eMASS can track
the same weakness row over time — ``count`` = number of distinct root-cause
clusters, ``rawSeverity`` = the worst severity in the group.
"""

from __future__ import annotations

import re
from datetime import datetime

from ..model import Finding, canonical_cwe

_CWE_NUM_RE = re.compile(r"^CWE-(\d+)$")
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
# medium -> Moderate: the RMF-native spelling (enum also allows "Medium").
SEV_TO_RAW = {"critical": "Critical", "high": "High", "medium": "Moderate",
              "low": "Low", "info": None}


def _exportable(f: Finding) -> bool:
    return (f.disposition.lifecycle in ("open", "reopened")
            and f.disposition.state != "refuted")


def _cwe_number(f: Finding) -> str | None:
    if f.taxonomy.cwe:
        m = _CWE_NUM_RE.match(canonical_cwe(f.taxonomy.cwe[0]))
        if m:
            return m.group(1)
    return None


def scan_date_from_manifest(manifest: dict) -> int:
    stamp = manifest.get("finished_at") or manifest.get("started_at")
    return int(datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp())


def to_emass_static_code_scans(findings: list[Finding], *, application_name: str,
                               version: str, scan_date: int) -> tuple[list, dict]:
    """-> (request body array, meta). meta lists exported/skipped/withheld so a
    caller can never mistake a partial export for a complete one."""
    groups: dict[str, list[Finding]] = {}
    skipped: list[dict] = []
    withheld = 0
    for f in findings:
        if not _exportable(f):
            withheld += 1
            continue
        num = _cwe_number(f)
        if num is None:
            skipped.append({"finding_id": f.id, "reason": "no numeric primary CWE",
                            "cwe": list(f.taxonomy.cwe)})
            continue
        groups.setdefault(num, []).append(f)

    rows = []
    for num in sorted(groups, key=int):
        members = groups[num]
        worst = max(members, key=lambda f: _SEV_RANK.get(f.severity.label, 0))
        row = {"codeCheckName": f"CWE-{num} ({worst.taxonomy.cwe_family})",
               "scanDate": int(scan_date),
               "cweId": num,
               "count": len(members)}
        raw = SEV_TO_RAW.get(worst.severity.label)
        if raw:
            row["rawSeverity"] = raw
        rows.append(row)

    body = [{"application": {"applicationName": application_name, "version": version},
             "applicationFindings": rows}]
    meta = {"rows": len(rows),
            "findings_exported": sum(len(v) for v in groups.values()),
            "withheld_by_disposition": withheld,
            "skipped": skipped}
    return body, meta


def clear_findings_payload(*, application_name: str, version: str) -> list:
    """The documented clear form: the only finding row is `clearFindings: true`."""
    return [{"application": {"applicationName": application_name, "version": version},
             "applicationFindings": [{"clearFindings": True}]}]
