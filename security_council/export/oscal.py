"""OSCAL Assessment Results + POA&M export (gov/DoD lane, D6/D7).

Structure verified 2026-08-23 against NIST's official OSCAL content examples
(usnistgov/oscal-content `examples/ar` + `examples/poam`), oscal-version 1.1.2.

- **Assessment Results** (`assessment-results`): metadata + import-ap + one
  `results` entry carrying `observations[]` (one per finding, method TEST),
  `findings[]` (one per finding, target status satisfied/not-satisfied), and
  `risks[]` (one per finding; status maps from disposition — a suppressed
  finding is `deviation-approved`, an open validated one `open`, a needs-human
  one `investigating`).
- **POA&M** (`plan-of-action-and-milestones`): the projection — `poam-items[]`
  for the open, non-refuted, non-suppressed findings that still need action,
  referencing the same observations/risks.

UUIDs are deterministic UUIDv5 from the finding id (stable across re-exports of
the same run). Everything renders from the finding disposition (D7): one source
of truth feeds SARIF, VEX, and OSCAL alike.
"""

from __future__ import annotations

import uuid

from .. import __version__
from ..model import Finding

OSCAL_VERSION = "1.1.2"
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://intellimetrics.net/security-council/oscal")

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_NS, "\x00".join(parts)))


def _risk_status(f: Finding) -> str:
    d = f.disposition
    if d.lifecycle in ("suppressed", "accepted_risk"):
        return "deviation-approved"
    if d.lifecycle == "fixed":
        return "closed"
    if d.state in ("needs_human", "disputed") or d.state == "refuted":
        return "investigating"
    return "open"


def _finding_state(f: Finding) -> str:
    # a finding is "satisfied" (control met) only when it's closed out; an open,
    # non-refuted finding is not-satisfied
    d = f.disposition
    if d.lifecycle in ("suppressed", "accepted_risk", "fixed") or d.state == "refuted":
        return "satisfied"
    return "not-satisfied"


def _target_id(f: Finding) -> str:
    if f.compliance and f.compliance.nist_800_53:
        return f.compliance.nist_800_53[0]
    return f.taxonomy.cwe[0] if f.taxonomy.cwe else "CWE-noinfo"


def _loc(f: Finding) -> str:
    loc = f.locations[0] if f.locations else None
    return f"{loc.uri}:{loc.start_line}" if loc else "unknown"


def _observation(f: Finding, collected: str) -> dict:
    return {
        "uuid": _uuid("obs", f.id),
        "title": f"{f.taxonomy.cwe[0] if f.taxonomy.cwe else 'CWE-noinfo'} at {_loc(f)}",
        "description": f.description or f.title,
        "methods": ["TEST"],
        "types": ["finding"],
        "props": [{"name": "cwe", "value": f.taxonomy.cwe[0] if f.taxonomy.cwe else "CWE-noinfo"},
                  {"name": "severity", "value": f.severity.label},
                  {"name": "location", "value": _loc(f)},
                  {"name": "finding-id", "value": f.id}],
        "collected": collected,
    }


def _finding_entry(f: Finding) -> dict:
    return {
        "uuid": _uuid("finding", f.id),
        "title": f.title,
        "description": f.description or f.title,
        "target": {"type": "objective-id", "target-id": _target_id(f),
                   "status": {"state": _finding_state(f)}},
        "related-observations": [{"observation-uuid": _uuid("obs", f.id)}],
        "related-risks": [{"risk-uuid": _uuid("risk", f.id)}],
    }


def _risk(f: Finding) -> dict:
    return {
        "uuid": _uuid("risk", f.id),
        "title": f.title,
        "description": f.description or f.title,
        "statement": (f.remediation.summary if f.remediation else "See the finding description."),
        "status": _risk_status(f),
        "props": [{"name": "severity", "value": f.severity.label},
                  {"name": "security-severity", "value": str(f.severity.security_severity)}],
    }


def _metadata(manifest: dict, title: str) -> dict:
    return {
        "title": title,
        "last-modified": manifest.get("finished_at") or "1970-01-01T00:00:00Z",
        "version": str((manifest.get("tool") or {}).get("security_council", __version__)),
        "oscal-version": OSCAL_VERSION,
    }


def to_oscal_ar(findings: list[Finding], manifest: dict) -> dict:
    run_id = manifest.get("run_id", "run")
    started = manifest.get("started_at") or "1970-01-01T00:00:00Z"
    finished = manifest.get("finished_at") or started
    result = {
        "uuid": _uuid("result", run_id),
        "title": "security-council automated static assessment",
        "description": "Findings from security-council's multi-arm scan, cross-validated.",
        "start": started,
        "observations": [_observation(f, finished) for f in findings],
        "findings": [_finding_entry(f) for f in findings],
        "risks": [_risk(f) for f in findings],
    }
    return {"assessment-results": {
        "uuid": _uuid("ar", run_id),
        "metadata": _metadata(manifest, "security-council Assessment Results"),
        "import-ap": {"href": "./assessment-plan.oscal.json"},
        "results": [result],
    }}


def _poam_eligible(f: Finding) -> bool:
    # POA&M tracks open, non-refuted, non-suppressed findings that need action
    return (f.disposition.lifecycle in ("open", "reopened")
            and f.disposition.state != "refuted")


def to_oscal_poam(findings: list[Finding], manifest: dict) -> dict:
    run_id = manifest.get("run_id", "run")
    finished = manifest.get("finished_at") or "1970-01-01T00:00:00Z"
    actionable = [f for f in findings if _poam_eligible(f)]
    actionable.sort(key=lambda f: -_SEV_RANK.get(f.severity.label, 0))
    poam_items = [{
        "uuid": _uuid("poam-item", f.id),
        "title": f"{f.severity.label.upper()}: {f.title}",
        "description": f.description or f.title,
        "related-observations": [{"observation-uuid": _uuid("obs", f.id)}],
        "related-risks": [{"risk-uuid": _uuid("risk", f.id)}],
    } for f in actionable]
    return {"plan-of-action-and-milestones": {
        "uuid": _uuid("poam", run_id),
        "metadata": _metadata(manifest, "security-council Plan of Action & Milestones"),
        "import-ssp": {"href": "./ssp.oscal.json"},
        "system-id": {"id": (manifest.get("target") or {}).get("root", "system")},
        "observations": [_observation(f, finished) for f in actionable],
        "risks": [_risk(f) for f in actionable],
        "poam-items": poam_items,
    }}
