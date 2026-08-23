"""OpenVEX export (gov lane, D7).

Verified 2026-08-23 against the official OpenVEX JSON schema (openvex/spec
`openvex_json_schema.json`, v0.2.0, vendored at
`tests/fixtures/schemas/openvex-0.2.0.schema.json`). Contract:
- Document requires `@context`/`@id`/`author`/`timestamp`/`version`/`statements`.
- Statement requires `vulnerability` + `status`; `status` ∈ not_affected |
  affected | fixed | under_investigation; a `not_affected` statement MUST carry
  a `justification` (the fixed label set — identical to the finding model's
  `OPENVEX_JUSTIFICATIONS`).

Every statement is derived from ONE finding's disposition (D7): the same
render_decision that drives SARIF suppressions and eMASS withholding drives the
VEX status here — a suppression is `not_affected` with its stored justification,
a validated open finding is `affected` with an action statement, a
demoted/needs-human finding is `under_investigation`.
"""

from __future__ import annotations

from ..model import Finding

_CONTEXT = "https://openvex.dev/ns/v0.2.0"


def _product_id(manifest: dict) -> str:
    tgt = manifest.get("target") or {}
    root = str(tgt.get("root") or "repository").rstrip("/").rsplit("/", 1)[-1]
    commit = tgt.get("git_commit")
    return f"pkg:generic/{root}" + (f"@{commit[:12]}" if commit else "")


def _vuln(f: Finding) -> dict:
    cwes = list(f.taxonomy.cwe)
    if f.package and f.package.advisory_ids:
        name = f.package.advisory_ids[0]
        aliases = f.package.advisory_ids[1:] + cwes
    else:
        # SAST findings have no CVE — use a stable, namespaced synthetic id and
        # carry the CWE(s) as aliases so consumers can still key on the weakness
        name = f"security-council/{f.id}"
        aliases = cwes
    v = {"@id": name, "name": name, "description": f.title}
    if aliases:
        v["aliases"] = aliases
    return v


def render_status(f: Finding) -> tuple[str, str | None, str | None]:
    """(status, justification, action_statement) from the finding's disposition."""
    d = f.disposition
    if d.lifecycle in ("suppressed", "accepted_risk"):
        just = d.vex_justification or "inline_mitigations_already_exist"
        return "not_affected", just, None
    if d.lifecycle == "fixed":
        return "fixed", None, None
    if d.state == "refuted":
        # demoted false positive: only assert not_affected when a machine-readable
        # justification exists (unreachable); otherwise stay under_investigation
        reach = f.validation.reachability if f.validation else None
        if reach and reach.verdict == "unreachable":
            return "not_affected", "vulnerable_code_not_in_execute_path", None
        return "under_investigation", None, None
    if d.state in ("validated", "likely"):
        action = (f.remediation.summary if f.remediation else
                  "Remediate the finding; see the security-council report.")
        return "affected", None, action
    return "under_investigation", None, None


def _statement(f: Finding, product: str, timestamp: str) -> dict:
    status, justification, action = render_status(f)
    st: dict = {"vulnerability": _vuln(f), "products": [{"@id": product}],
                "status": status, "timestamp": timestamp}
    loc = f.locations[0] if f.locations else None
    if loc:
        st["status_notes"] = f"{loc.uri}:{loc.start_line} ({f.taxonomy.cwe_family})"
    if status == "not_affected" and justification:
        st["justification"] = justification
    if status == "affected" and action:
        st["action_statement"] = action
    return st


def to_openvex(findings: list[Finding], manifest: dict, *,
               author: str = "security-council", doc_version: int = 1) -> dict:
    ts = manifest.get("finished_at") or manifest.get("started_at") or "1970-01-01T00:00:00Z"
    product = _product_id(manifest)
    run_id = manifest.get("run_id", "run")
    return {
        "@context": _CONTEXT,
        "@id": f"https://openvex.dev/docs/security-council/{run_id}",
        "author": author,
        "role": "Software Security Assessment Tool",
        "timestamp": ts,
        "version": int(doc_version),
        "tooling": f"security-council {(manifest.get('tool') or {}).get('security_council', '')}".strip(),
        "statements": [_statement(f, product, ts) for f in findings],
    }
