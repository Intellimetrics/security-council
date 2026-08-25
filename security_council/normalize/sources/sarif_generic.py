"""Generic SARIF 2.1.0 -> RawFinding, with thin per-tool wrappers."""

from __future__ import annotations

import re
from pathlib import Path

from ..base import RawFinding
from ...model import PackageRef

_CWE_TAG = re.compile(r"CWE[-_ ]?(\d+)", re.I)
_PURL = re.compile(r"pkg:[a-zA-Z0-9._-]+/[^\s\"']+")
_PKG_AT = re.compile(r"([A-Za-z0-9._-]+)@([0-9][\w.\-+]*)")


def _cwes_from_tags(tags: list) -> list[str]:
    out = []
    for t in tags or []:
        if not isinstance(t, str):
            continue
        m = _CWE_TAG.search(t)
        if m:
            c = f"CWE-{m.group(1)}"
            if c not in out:
                out.append(c)
    return out


def _package_from_result(res: dict, rule_id: str | None, uri: str) -> PackageRef:
    msg = (res.get("message") or {}).get("text", "") or ""
    purl_m = _PURL.search(msg)
    if purl_m:
        purl = purl_m.group(0)
    else:
        at = _PKG_AT.search(msg)
        purl = f"pkg:generic/{at.group(1)}@{at.group(2)}" if at else f"pkg:generic/{Path(uri).name}"
    advisories = [rule_id] if rule_id else []
    return PackageRef(purl=purl, advisory_ids=advisories)


def parse_sarif(sarif: dict, *, source_id: str, redact: bool = False,
                category: str | None = None, package_mode: bool = False,
                default_cwe: str | None = None) -> list[RawFinding]:
    out: list[RawFinding] = []
    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules: dict = {}
        for idx, r in enumerate(driver.get("rules", []) or []):
            rules[r.get("id")] = r
            rules[idx] = r
        for res in run.get("results", []):
            rid = res.get("ruleId")
            rule = rules.get(rid) or rules.get(res.get("ruleIndex")) or {}
            props = rule.get("properties", {}) or {}
            declared = _cwes_from_tags(props.get("tags", []))
            if props.get("cwe"):
                declared += _cwes_from_tags([props["cwe"]])
            if not declared and default_cwe:
                declared = [default_cwe]
            numeric = None
            if props.get("security-severity") is not None:
                try:
                    numeric = float(props["security-severity"])
                except (TypeError, ValueError):
                    numeric = None
            ploc = ((res.get("locations") or [{}])[0]).get("physicalLocation", {}) or {}
            uri = (ploc.get("artifactLocation") or {}).get("uri")
            if not uri:
                continue
            region = ploc.get("region", {}) or {}
            start = region.get("startLine", 1)
            end = region.get("endLine", start)
            title = ((rule.get("shortDescription") or {}).get("text")) or rid or "finding"
            pkg = _package_from_result(res, rid, uri) if package_mode else None
            out.append(RawFinding(
                path=uri, start_line=start, end_line=end, title=title,
                description=(res.get("message") or {}).get("text", ""),
                rule_id=rid, declared_cwe=declared, category=category,
                # SARIF 2.1.0 §3.27.10: a result without `level` INHERITS
                # `rule.defaultConfiguration.level`. R12 round 15: we read only
                # the result's own level, so a scanner that declares severity
                # once on the rule — compliant and common — had every finding
                # under-severitised and dropped below the default `high` gate.
                severity_label=(res.get("level")
                                or (rule.get("defaultConfiguration") or {}).get("level")),
                numeric_severity=numeric,
                start_column=region.get("startColumn"), end_column=region.get("endColumn"),
                snippet=(region.get("snippet") or {}).get("text"),
                source_fingerprints=res.get("partialFingerprints", {}) or {},
                package=pkg, redact=redact,
            ))
    return out


def semgrep(sarif: dict) -> list[RawFinding]:
    return parse_sarif(sarif, source_id="semgrep")


def gitleaks(sarif: dict) -> list[RawFinding]:
    return parse_sarif(sarif, source_id="gitleaks", redact=True, category="secrets",
                       default_cwe="CWE-798")


def osv(sarif: dict) -> list[RawFinding]:
    return parse_sarif(sarif, source_id="osv-scanner", package_mode=True, default_cwe="CWE-1395")
