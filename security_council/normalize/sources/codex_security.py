"""@openai/codex-security canonical bundle (findings.json) -> RawFinding.

We ingest the *semantic* findings document, not the SARIF projection: the tool's
own docs say SARIF is lossy ("lifecycle, rich validation evidence, attack-path
context, and coverage ... preserve them in semantic JSON"). Schema:
``_bundled_plugin/schemas/findings.schema.json`` (vendored copy under
tests/fixtures/schemas). Each finding has one or more role-tagged locations; we
pick the ``sink``/``root_control`` one as primary and keep the semantic
fingerprint (``codex-security/v1``) + ids as source fingerprints.
"""

from __future__ import annotations

from ..base import RawFinding

PRIMARY_ROLES = ("sink", "root_control", "outcome", "propagation", "entrypoint", "user_input")
# CWEs whose quoted line *is* the secret; never carry the snippet.
SECRET_CWES = frozenset({"CWE-798", "CWE-259", "CWE-321", "CWE-312", "CWE-540"})


def bundle_meta(doc: dict, manifest: dict | None = None, coverage: dict | None = None) -> dict:
    scan = (manifest or {}).get("scan") or {}
    return {
        "scan_id": doc.get("scanId") or scan.get("id"),
        "document_type": doc.get("documentType"),
        "schema_version": doc.get("schemaVersion"),
        "status": scan.get("status"),
        "producer": scan.get("producer"),
        "target": scan.get("target"),
        "scope": scan.get("scope"),
        "started_at": scan.get("startedAt"),
        "completed_at": scan.get("completedAt"),
        "sealed_at": scan.get("sealedAt"),
        "completeness": (coverage or {}).get("completeness"),
        "coverage_mode": (coverage or {}).get("mode"),
        "results": len(doc.get("findings") or []),
    }


def _primary_location(locs: list) -> dict | None:
    locs = [loc for loc in locs if isinstance(loc, dict) and loc.get("path")]
    if not locs:
        return None
    for role in PRIMARY_ROLES:
        for loc in locs:
            if loc.get("role") == role:
                return loc
    return locs[0]


def _description(f: dict) -> str:
    parts = [f.get("summary") or ""]
    rc = f.get("rootCause")
    if isinstance(rc, dict) and rc.get("summary"):
        parts.append(f"Root cause: {rc['summary']}")
    conf = f.get("confidence") or {}
    if isinstance(conf, dict) and conf.get("level"):
        line = f"Codex Security confidence: {conf['level']}"
        if conf.get("rationale"):
            line += f" — {conf['rationale']}"
        parts.append(line + ".")
    val = f.get("validation")
    if isinstance(val, dict):
        # live bundles (producer 0.1.22) say result="confirmed"/"confirmed-with-prerequisite"
        # + status="validated"; older drafts said disposition. Render only what exists.
        outcome = val.get("result") or val.get("disposition") or val.get("status")
        method = val.get("method")
        if outcome and method:
            line = f"Validation: {outcome} — {method}"
        elif outcome or method:
            line = f"Validation: {outcome or method}"
        else:
            line = None
        if line:
            if val.get("confidence"):
                line += f" ({val['confidence']})"
            parts.append(line.rstrip(".") + ".")
    ap = f.get("attackPath")
    if isinstance(ap, dict) and ap.get("decision"):
        bits = [f"decision {ap['decision']}"]
        for k in ("reachability", "impact", "likelihood"):
            if ap.get(k):
                bits.append(f"{k} {ap[k]}")
        parts.append("Attack path: " + ", ".join(bits) + ".")
    return "\n\n".join(p for p in parts if p)


def _snippet_for(f: dict, loc: dict) -> str | None:
    for ev in f.get("codeEvidence") or []:
        if not isinstance(ev, dict):
            continue
        if ev.get("path") == loc.get("path") and ev.get("startLine") == loc.get("startLine") \
                and isinstance(ev.get("code"), str) and ev["code"].strip():
            return ev["code"].splitlines()[0].strip()
    return None


def parse_findings(doc: dict) -> list[RawFinding]:
    out: list[RawFinding] = []
    for f in doc.get("findings") or []:
        if not isinstance(f, dict):
            continue
        loc = _primary_location(f.get("locations") or [])
        if loc is None:
            continue
        start = loc.get("startLine")
        if not isinstance(start, int) or start < 1:
            start = 1
        end = loc.get("endLine") if isinstance(loc.get("endLine"), int) else start
        tax = f.get("taxonomy") or {}
        cwes = [str(c).strip().upper() for c in (tax.get("cwe") or []) if str(c).strip()]
        sev = (f.get("severity") or {}).get("level") if isinstance(f.get("severity"), dict) else None
        secret = bool(set(cwes) & SECRET_CWES) or (tax.get("category") or "").lower() in ("secrets", "secret")
        fps = {}
        fpo = f.get("fingerprints") or {}
        if isinstance(fpo, dict) and fpo.get("primary"):
            fps[fpo.get("algorithm") or "codex-security/v1"] = str(fpo["primary"])
        for key, src in (("codexSecurity/findingId", "findingId"),
                         ("codexSecurity/occurrenceId", "occurrenceId")):
            if f.get(src):
                fps[key] = str(f[src])
        anchor = (f.get("identity") or {}).get("anchor") if isinstance(f.get("identity"), dict) else None
        if anchor:
            fps["codexSecurity/anchor"] = str(anchor)
        out.append(RawFinding(
            path=str(loc["path"]).replace("\\", "/").lstrip("/"), start_line=start, end_line=max(start, end),
            title=f.get("title") or f.get("ruleId") or "finding",
            description=_description(f),
            rule_id=f"codex-security/{f.get('ruleId') or 'unknown'}",
            declared_cwe=cwes, category=tax.get("category") or None, severity_label=sev,
            snippet=None if secret else _snippet_for(f, loc),
            remediation=f.get("remediation") if isinstance(f.get("remediation"), str) else None,
            source_fingerprints=fps, redact=secret,
        ))
    return out
