"""SARIF 2.1.0 export/import.

SARIF is the interop artifact, not the system of record: the full Finding is
carried losslessly under ``result.properties.securityCouncil`` (so from_sarif
round-trips), while the standard fields drive GitHub/Azure DevOps/IDE consumers.
``partialFingerprints`` carry the three content hashes and **never a line number**.
"""

from __future__ import annotations

from ..model import Finding
from ..jsonio import finding_from_dict, to_dict

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/Intellimetrics/security-council"


def _fp_body(fp: str) -> str:
    return fp.split(":", 1)[1]


def _partial_fingerprints(f: Finding) -> dict:
    return {
        "pathCweSink/v1": _fp_body(f.fingerprints.path_cwe_sink),
        "contextHash/v1": _fp_body(f.fingerprints.context_hash),
        "rootCause/v1": _fp_body(f.fingerprints.root_cause),
    }


def _rule_for(f: Finding) -> dict:
    tags = [f"external/cwe/{c.lower()}" for c in f.taxonomy.cwe]
    tags += [f"security-council/{f.taxonomy.cwe_family}"]
    tags += [f"OWASP-2025-{o}" for o in f.taxonomy.owasp_2025]
    return {
        "id": f.rule.id,
        "name": f.rule.name or f.rule.id,
        "shortDescription": {"text": f.title or f.rule.id},
        "properties": {
            "tags": tags,
            "security-severity": f"{f.severity.security_severity:.1f}",
            "cwe": list(f.taxonomy.cwe),
        },
    }


def _physical(loc) -> dict:
    region: dict = {"startLine": loc.start_line, "endLine": loc.end_line}
    if loc.start_column is not None:
        region["startColumn"] = loc.start_column
    if loc.end_column is not None:
        region["endColumn"] = loc.end_column
    if loc.snippet:
        region["snippet"] = {"text": loc.snippet}
    return {
        "physicalLocation": {"artifactLocation": {"uri": loc.uri}, "region": region},
        "properties": {"role": loc.role},
    }


def _suppressions(f: Finding) -> list | None:
    d = f.disposition
    closed = d.lifecycle in ("suppressed", "accepted_risk", "fixed") \
        or d.vex_status in ("not_affected", "fixed")
    if not closed and d.state != "refuted":
        return None
    status = "accepted" if d.lifecycle in ("suppressed", "accepted_risk") else "underReview"
    just = d.vex_justification
    if not just and f.validation and f.validation.reachability:
        just = f.validation.reachability.path_summary
    return [{"kind": "external", "status": status, "justification": just or f"disposition={d.state}"}]


def _result(f: Finding, rule_index: int) -> dict:
    r: dict = {
        "ruleId": f.rule.id,
        "ruleIndex": rule_index,
        "level": f.severity.sarif_level,
        "message": {"text": f.title or f.description or f.rule.id},
        "locations": [_physical(f.locations[0])],
        "partialFingerprints": _partial_fingerprints(f),
        "properties": {"securityCouncil": to_dict(f)},
    }
    if len(f.locations) > 1:
        r["relatedLocations"] = [_physical(loc) for loc in f.locations[1:]]
    if f.baseline_state:
        r["baselineState"] = f.baseline_state
    sup = _suppressions(f)
    if sup:
        r["suppressions"] = sup
    if f.data_flow:
        r["codeFlows"] = [{"threadFlows": [{"locations":
                          [{"location": _physical(s.location)} for s in f.data_flow]}]}]
    return r


def _run(findings: list[Finding], *, tool_name: str, tool_version: str,
         automation_id: str | None = None) -> dict:
    rules: list[dict] = []
    index: dict[str, int] = {}
    for f in findings:
        if f.rule.id not in index:
            index[f.rule.id] = len(rules)
            rules.append(_rule_for(f))
    run: dict = {
        "tool": {"driver": {"name": tool_name, "version": tool_version,
                            "informationUri": _INFO_URI, "rules": rules}},
        "results": [_result(f, index[f.rule.id]) for f in findings],
    }
    if automation_id:
        run["automationDetails"] = {"id": automation_id}
    return run


def to_sarif(findings: list[Finding], *, tool_name: str = "security-council",
             tool_version: str = "0.0.0", run_id: str | None = None) -> dict:
    """One merged run carrying the adjudicated findings (the council verdict)."""
    run = _run(findings, tool_name=tool_name, tool_version=tool_version,
               automation_id=f"security-council/{run_id}" if run_id else None)
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def raw_sarif(findings_by_source: dict[str, list[Finding]], *, tool_version: str = "0.0.0") -> dict:
    """One run per (source) carrying that producer's raw findings (immutable)."""
    runs = [_run(fs, tool_name=src, tool_version=tool_version, automation_id=f"raw/{src}")
            for src, fs in findings_by_source.items()]
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": runs}


def from_sarif(sarif: dict) -> list[Finding]:
    """Reconstruct Findings from the lossless securityCouncil property bag."""
    out: list[Finding] = []
    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            sc = (res.get("properties") or {}).get("securityCouncil")
            if sc is not None:
                out.append(finding_from_dict(sc))
    return out
