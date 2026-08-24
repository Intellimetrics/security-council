"""CycloneDX 1.6 VDR export (`report --format cyclonedx`).

A Vulnerability Disclosure Report: the run's open findings as CycloneDX
`vulnerabilities` over a minimal component tree. This is NOT an SBOM — we do
not inventory the repo's components (that's a future syft/cdxgen arm; Trivy
stays banned). Components listed here are only (a) the scanned repository as
`metadata.component` and (b) packages that carry findings (real purls from
osv). Consumers get a spec-valid document that says exactly which
vulnerabilities affect which refs — nothing pretends to be a full inventory.

Contract verified 2026-08-24 against the OFFICIAL `bom-1.6.schema.json`
(cyclonedx/specification, vendored with its spdx/jsf companions under
`tests/fixtures/schemas/`): required top-level = bomFormat + specVersion;
`vulnerabilities[].affects[].ref` must resolve to a declared `bom-ref`;
`ratings[].severity` enum = critical|high|medium|low|info|none|unknown;
`cwes` = array of integers. D7: only open, unresolved findings are exported
(suppressed / demoted are withheld and counted in meta).
"""

from __future__ import annotations

import uuid

from ..model import Finding, canonical_cwe
from . import open_unresolved

_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
SPEC_VERSION = "1.6"
_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium",
             "low": "low", "info": "info"}


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_NS, "security-council/cyclonedx\x00" + "\x00".join(parts)))


def _cwe_ints(f: Finding) -> list[int]:
    out = []
    for c in f.taxonomy.cwe:
        num = canonical_cwe(c).removeprefix("CWE-")
        if num.isdigit():
            out.append(int(num))
    return out


def _root_component(manifest: dict) -> dict:
    tgt = manifest.get("target") or {}
    name = str(tgt.get("root") or "repository").rstrip("/").rsplit("/", 1)[-1]
    comp = {"type": "application", "bom-ref": f"app:{name}", "name": name}
    if tgt.get("git_commit"):
        comp["version"] = tgt["git_commit"][:12]
    return comp


def _vuln(f: Finding, affect_ref: str) -> dict:
    if f.package and f.package.advisory_ids:
        vid = f.package.advisory_ids[0]
        source = {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"}
    else:
        vid = f"security-council/{f.id}"       # SAST findings have no CVE (same as VEX)
        source = {"name": "security-council"}
    loc = f.locations[0] if f.locations else None
    v = {
        "bom-ref": _uuid("vuln", f.id),
        "id": vid,
        "source": source,
        "description": f.title,
        "ratings": [{"severity": _SEVERITY.get(f.severity.label, "unknown"),
                     "method": "other"}],
        "affects": [{"ref": affect_ref}],
        "properties": [
            {"name": "security-council:finding-id", "value": f.id},
            {"name": "security-council:state", "value": f.disposition.state},
            {"name": "security-council:sources",
             "value": " ".join(sorted({p.source_id for p in f.provenance}))},
        ],
    }
    if (cwes := _cwe_ints(f)):
        v["cwes"] = cwes
    if f.description:
        v["detail"] = f.description
    if loc:
        v["properties"].append({"name": "security-council:location",
                                "value": f"{loc.uri}:{loc.start_line}-{loc.end_line}"})
    return v


def to_cyclonedx(findings: list[Finding], manifest: dict) -> tuple[dict, dict]:
    """-> (bom document, meta). Deterministic for a given run manifest."""
    run_id = str(manifest.get("run_id", "run"))
    root = _root_component(manifest)
    components: dict[str, dict] = {}
    vulns = []
    withheld = 0
    for f in findings:
        if not open_unresolved(f):
            withheld += 1
            continue
        if f.package and f.package.purl:
            ref = f.package.purl
            components.setdefault(ref, {
                "type": "library", "bom-ref": ref, "purl": f.package.purl,
                "name": f.package.purl.rsplit("/", 1)[-1].split("@")[0],
                **({"version": f.package.version} if f.package.version else {}),
            })
        else:
            ref = root["bom-ref"]
        vulns.append(_vuln(f, ref))

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{_uuid('bom', run_id)}",
        "version": 1,
        "metadata": {
            **({"timestamp": manifest["finished_at"]} if manifest.get("finished_at") else {}),
            "tools": {"components": [{
                "type": "application", "name": "security-council",
                "version": str((manifest.get("tool") or {}).get("security_council", "0")),
            }]},
            "component": root,
        },
        "components": [components[k] for k in sorted(components)],
        "vulnerabilities": vulns,
    }
    meta = {"vulnerabilities": len(vulns), "package_components": len(components),
            "withheld_by_disposition": withheld,
            "note": "VDR only — not an SBOM; no component inventory is claimed"}
    return doc, meta
