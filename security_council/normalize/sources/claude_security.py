"""claude-security plugin output (CLAUDE-SECURITY-RESULTS.sarif) -> RawFinding.

The plugin's renderer writes one SARIF 2.1.0 run per scan: rules keyed by the
CWE Simplified-Mapping entry (``CWE-89``) or ``uncategorized``; each result
carries the full JSONL record plus the panel vote under
``properties.claudeSecurityPlugin``; the run's own property bag is the revision
stamp (``verification.status``, ``effort``, ``scan_prefix``, ...). We read the
record (authoritative) and fall back to the SARIF location. A hard-coded
credential's snippet is already withheld by the plugin and is redacted again
here (``redact=True``) so our own snippet capture never quotes it either.
"""

from __future__ import annotations

from urllib.parse import unquote

from ..base import RawFinding

PROPERTY_BAG = "claudeSecurityPlugin"
FINGERPRINT_KEY = "claude-security-plugin/v2"
# CWEs the plugin's secret.py rolls up to Use of Hard-coded Credentials (798).
CREDENTIAL_CWES = frozenset({"CWE-798", "CWE-259", "CWE-321", "CWE-671"})
_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_meta(sarif: dict) -> dict:
    """The stamp the renderer put on the run + the driver version (empty if absent)."""
    runs = sarif.get("runs") or []
    if not runs:
        return {}
    run = runs[0]
    props = (run.get("properties") or {}).get(PROPERTY_BAG) or {}
    ver = (props.get("verification") or {}) if isinstance(props.get("verification"), dict) else {}
    return {
        "plugin_version": ((run.get("tool") or {}).get("driver") or {}).get("version"),
        "verification_status": ver.get("status"),
        "verification_reason": ver.get("reason"),
        "verification": ver,
        "effort": props.get("effort"),
        "mode": props.get("mode"),
        "scan_prefix": props.get("scan_prefix") or "",
        "scope": props.get("scope") or [],
        "revision": props.get("revision"),
        "run_shape": props.get("run_shape"),
        "findings": props.get("findings"),
        "generated_at": props.get("generated_at"),
        "scan_id": props.get("scan_id"),
        "model": props.get("model"),
        "results": sum(len(r.get("results") or []) for r in runs),
    }


def _description(rec: dict, panel: dict | None) -> str:
    parts = [rec.get("description") or ""]
    for label, key in (("Impact", "impact"), ("Exploit scenario", "exploit_scenario"),
                       ("Recommendation", None)):
        if key and rec.get(key):
            parts.append(f"{label}: {rec[key]}")
    pre = rec.get("preconditions") or []
    if pre:
        parts.append("Preconditions: " + "; ".join(str(p) for p in pre))
    conf = rec.get("confidence")
    if panel:
        parts.append(f"Claude Security panel: {panel.get('true', 0)}/{panel.get('voters', 3)} "
                     f"verifiers confirmed (confidence {conf or 'unknown'}).")
    elif conf:
        parts.append(f"Claude Security confidence: {conf}.")
    return "\n\n".join(p for p in parts if p)


def parse_sarif(sarif: dict) -> tuple[list[RawFinding], dict]:
    meta = run_meta(sarif)
    prefix = meta.get("scan_prefix") or ""
    out: list[RawFinding] = []
    for run in sarif.get("runs") or []:
        for res in run.get("results") or []:
            props = (res.get("properties") or {}).get(PROPERTY_BAG) or {}
            rec = props if isinstance(props, dict) else {}
            ploc = ((res.get("locations") or [{}])[0]).get("physicalLocation") or {}
            uri = unquote((ploc.get("artifactLocation") or {}).get("uri") or "")
            # strip the plugin's own scan prefix only at a path-segment boundary
            # (R15c: a bare startswith turned `/srcfoo/x.py` under prefix `/src`
            # into `foo/x.py` — a different file)
            if prefix:
                pre = prefix.rstrip("/")
                if uri == pre:
                    uri = ""
                elif uri.startswith(pre + "/"):
                    uri = uri[len(pre) + 1:]
            # verbatim otherwise: separator policy and absolute-path refusal
            # live in normalize.paths / invariant I1 (R15b)
            path = rec.get("file") or uri
            if not path:
                continue
            region = ploc.get("region") or {}
            line = rec.get("line")
            if not isinstance(line, int) or line < 1:
                line = region.get("startLine") or 1
            line = max(1, int(line))
            cwe = str(rec.get("cwe_id") or "").strip().upper()
            rule_cwe = str(res.get("ruleId") or "").strip().upper()
            declared = [c for c in (cwe, rule_cwe) if c.startswith("CWE-")]
            declared = list(dict.fromkeys(declared))
            category = rec.get("category") or None
            credential = bool(set(declared) & CREDENTIAL_CWES) or \
                "credential" in (category or "").lower()
            panel = ((rec.get("verification") or {}).get("panel")
                     if isinstance(rec.get("verification"), dict) else None)
            sev = _SEVERITY.get(str(rec.get("severity") or "").upper()) or res.get("level")
            fps = dict(res.get("partialFingerprints") or {})
            if rec.get("id"):
                fps["claudeSecurity/id"] = str(rec["id"])
            out.append(RawFinding(
                path=path, start_line=line, end_line=line,
                title=rec.get("title") or ((res.get("message") or {}).get("text") or "")[:120],
                description=_description(rec, panel),
                rule_id=f"claude-security/{cwe or rule_cwe or 'uncategorized'}",
                declared_cwe=declared, category=category, severity_label=sev,
                symbol=(rec.get("symbol") or "").strip() or None,
                snippet=(rec.get("snippet") or (region.get("snippet") or {}).get("text") or None)
                if not credential else None,
                remediation=rec.get("recommendation") or None,
                source_fingerprints=fps, redact=credential,
            ))
    return out, meta
