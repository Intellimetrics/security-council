"""Adapter framework: RawFinding intermediate + build_finding (the ingress boundary)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .. import fingerprint as fp
from ..model import (
    SCHEMA_VERSION,
    CodeLocation,
    Corroboration,
    DecidedBy,
    Disposition,
    Finding,
    Fingerprints,
    PackageRef,
    ProvenanceEntry,
    Remediation,
    RuleRef,
    Taxonomy,
    finding_id,
    validate_finding,
)
from . import cwe as _cwe
from . import severity as _sev
from . import snippets as _snip
from .paths import to_repo_relative


@dataclass
class ParseContext:
    """Identity + config for one adapter run (one producer, one scan)."""
    repo_root: str | Path
    source_id: str
    source_kind: str            # agent_cli | scanner | import
    family: str                 # vendor family
    scan_root: str | Path | None = None
    run_id: str = ""
    collected_at: str = "1970-01-01T00:00:00Z"
    prompt_sha256: str = ""     # required (sha-shaped) for agent_cli
    model_id: Optional[str] = None
    cli_version: Optional[str] = None
    tool_version: Optional[str] = None
    rule_pack_version: Optional[str] = None
    angle: Optional[str] = None
    entitlement: Optional[str] = None
    safeguard_posture: str = "unknown"
    skipped: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def skip(self, reason: str) -> None:
        self.skipped[reason] += 1


@dataclass
class RawFinding:
    path: str
    start_line: int
    end_line: int
    title: str = ""
    description: str = ""
    rule_id: Optional[str] = None
    declared_cwe: list[str] = field(default_factory=list)
    category: Optional[str] = None
    severity_label: Optional[str] = None
    numeric_severity: Optional[float] = None
    cvss_v3: Optional[str] = None
    cvss_v4: Optional[str] = None
    epss: Optional[float] = None
    kev: bool = False
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    symbol: Optional[str] = None
    snippet: Optional[str] = None
    remediation: Optional[str] = None
    package: Optional[PackageRef] = None
    source_fingerprints: dict = field(default_factory=dict)
    owasp_2025: list[str] = field(default_factory=list)
    redact: bool = False


def _sink_token(raw: RawFinding, snip: _snip.Snippet) -> str:
    if raw.symbol:
        return raw.symbol
    line = fp.normalize_line(raw.snippet or (snip.raw_context[len(snip.raw_context) // 2]
                                             if snip.raw_context else ""))
    return line or (raw.rule_id or "?")


def build_finding(raw: RawFinding, ctx: ParseContext) -> Optional[Finding]:
    """Turn a RawFinding into a canonical Finding, or None (counted) if it is
    unresolvable/invalid. This is a trust boundary: invariants are enforced here."""
    path = to_repo_relative(raw.path, repo_root=ctx.repo_root, scan_root=ctx.scan_root)
    redact = raw.redact or ctx.family == "gitleaks" or raw.category == "secrets"
    snip = _snip.capture(path, raw.start_line, raw.end_line, repo_root=ctx.repo_root, redact=redact)
    if snip is None:
        ctx.skip("unresolvable_location")
        return None

    cwe_a = _cwe.normalize_cwe(source_id=ctx.source_id, rule_id=raw.rule_id,
                              declared_cwe=raw.declared_cwe, category=raw.category,
                              title=raw.title, description=raw.description)
    sev = _sev.normalize_severity(source_id=ctx.source_id, raw_label=raw.severity_label,
                                 numeric_severity=raw.numeric_severity, cwe_family=cwe_a.family,
                                 cvss_v3=raw.cvss_v3, cvss_v4=raw.cvss_v4, epss=raw.epss, kev=raw.kev)

    sink = _sink_token(raw, snip)
    fps = Fingerprints(
        path_cwe_sink=fp.path_cwe_sink(path=path, cwe=cwe_a.cwe[0], sink_token=sink),
        context_hash=fp.context_hash(snip.raw_context),
        root_cause=fp.root_cause(cwe_family=cwe_a.family, root_symbol=raw.symbol or path,
                                 sink_expr=raw.snippet or sink, package=raw.package),
        # the producer's own identity keys (semgrep matchBasedId, claude-security-plugin/v2,
        # codex-security/v1 ...), namespaced by source so they never collide across arms
        source_fingerprints={f"{ctx.source_id}:{k}": str(v)
                             for k, v in (raw.source_fingerprints or {}).items() if v is not None},
    )
    loc = CodeLocation(
        uri=path, start_line=raw.start_line, end_line=max(raw.start_line, raw.end_line),
        role="primary", snippet_sha256=snip.sha256, start_column=raw.start_column,
        end_column=raw.end_column, symbol=raw.symbol, snippet=snip.text or None,
    )
    prov = ProvenanceEntry(
        source_id=ctx.source_id, source_kind=ctx.source_kind, family=ctx.family,
        prompt_sha256=ctx.prompt_sha256, collected_at=ctx.collected_at, model_id=ctx.model_id,
        cli_version=ctx.cli_version, tool_version=ctx.tool_version,
        rule_pack_version=ctx.rule_pack_version, angle=ctx.angle, entitlement=ctx.entitlement,
        safeguard_posture=ctx.safeguard_posture,
    )
    corr = Corroboration(
        agent_sources=[ctx.source_id] if ctx.source_kind == "agent_cli" else [],
        deterministic_sources=[ctx.source_id] if ctx.source_kind == "scanner" else [],
        count=1,
    )
    finding = Finding(
        id=finding_id(fps), schema_version=SCHEMA_VERSION, cluster_id=None,
        rule=RuleRef(id=raw.rule_id or f"sc/{cwe_a.family}", source=ctx.source_id,
                     source_rule_id=raw.rule_id),
        taxonomy=Taxonomy(cwe=cwe_a.cwe, cwe_family=cwe_a.family,
                          cwe_confidence=cwe_a.confidence, source_category=cwe_a.source_category,
                          owasp_2025=raw.owasp_2025),
        severity=sev, locations=[loc], fingerprints=fps, provenance=[prov], corroboration=corr,
        disposition=Disposition(state="new", lifecycle="open",
                                decided_by=DecidedBy(kind="auto", decided_at=ctx.collected_at)),
        title=raw.title or (raw.rule_id or "finding"), description=raw.description,
        remediation=Remediation(summary=raw.remediation) if raw.remediation else None,
        package=raw.package,
    )
    errs = validate_finding(finding)
    if errs:
        ctx.skip(f"invalid:{errs[0].split(':',1)[0]}")
        return None
    return finding
