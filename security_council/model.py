"""Canonical internal finding model for security-council.

Stdlib-only (dataclasses + hashlib + re), matching llm-council's style. This is
the trust surface: every producer's output normalizes into `Finding`, and every
report renders from it. The I1-I10 invariants (see `assert_invariants`) are the
structural guarantees behind the design's safety claims — e.g. a suppressed
finding that is not fully attributed simply cannot be constructed, and a crypto
finding can never be auto-suppressed.

Round-tripping to SARIF / OpenVEX / OSCAL lives in `export/`; (de)serialization
lives in `jsonio.py`. This module is pure data + validation.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Literal, Optional

SCHEMA_VERSION = 1

# --------------------------------------------------------------------------- #
# Enums (as Literal + frozenset validators)
# --------------------------------------------------------------------------- #

Severity = Literal["critical", "high", "medium", "low", "info"]
SarifLevel = Literal["error", "warning", "note", "none"]
SourceKind = Literal["agent_cli", "scanner", "import", "human"]
LocationRole = Literal["primary", "source", "sink", "sanitizer", "related"]
PanelRole = Literal["prosecutor", "defender", "adjudicator"]
Verdict = Literal["true_positive", "false_positive", "uncertain", "needs_human"]
DispositionState = Literal[
    "new", "validated", "likely", "disputed", "refuted", "needs_human"
]
Lifecycle = Literal["open", "suppressed", "accepted_risk", "fixed", "reopened"]
VexStatus = Literal["not_affected", "affected", "fixed", "under_investigation"]
CweFamily = Literal[
    "injection", "authz", "authn", "crypto", "secrets", "deserialization",
    "ssrf", "path_traversal", "xss", "memory", "supply_chain", "config",
    "llm_safety", "dos", "logging", "other",
]

SEVERITIES: frozenset[str] = frozenset(
    ("critical", "high", "medium", "low", "info")
)
CWE_FAMILIES: frozenset[str] = frozenset(
    (
        "injection", "authz", "authn", "crypto", "secrets", "deserialization",
        "ssrf", "path_traversal", "xss", "memory", "supply_chain", "config",
        "llm_safety", "dos", "logging", "other",
    )
)

SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}
SEVERITY_TO_SECURITY_SEVERITY: dict[str, float] = {
    "critical": 9.5, "high": 8.0, "medium": 5.0, "low": 3.0, "info": 0.0,
}

# CWEs whose family is `crypto`; guardrail G1/I7 keys on this family, so the
# mapping below is the single source of truth for "is this a crypto finding".
CRYPTO_CWES: frozenset[str] = frozenset(
    (
        "CWE-261", "CWE-321", "CWE-323", "CWE-325", "CWE-326", "CWE-327",
        "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-338", "CWE-347",
        "CWE-759", "CWE-760", "CWE-916",
    )
)

# Coarse CWE -> family, dispatched on by severity policy, coverage, clustering,
# and the crypto guardrail. Not exhaustive; unmapped CWEs accept the declared
# family (which the normalizer derives from the producer's `category`).
CWE_TO_FAMILY: dict[str, str] = {
    # injection
    "CWE-89": "injection", "CWE-564": "injection", "CWE-78": "injection",
    "CWE-77": "injection", "CWE-943": "injection", "CWE-91": "injection",
    "CWE-90": "injection", "CWE-94": "injection", "CWE-95": "injection",
    "CWE-1336": "injection",
    # xss
    "CWE-79": "xss", "CWE-80": "xss",
    # authz
    "CWE-639": "authz", "CWE-862": "authz", "CWE-863": "authz",
    "CWE-284": "authz", "CWE-285": "authz", "CWE-732": "authz",
    # authn
    "CWE-287": "authn", "CWE-306": "authn", "CWE-384": "authn",
    "CWE-521": "authn", "CWE-798": "secrets",
    # crypto (from CRYPTO_CWES; listed for direct lookup)
    **{c: "crypto" for c in (
        "CWE-261", "CWE-321", "CWE-323", "CWE-325", "CWE-326", "CWE-327",
        "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-338", "CWE-347",
        "CWE-759", "CWE-760", "CWE-916",
    )},
    # deserialization
    "CWE-502": "deserialization",
    # ssrf / path traversal
    "CWE-918": "ssrf", "CWE-22": "path_traversal", "CWE-23": "path_traversal",
    "CWE-36": "path_traversal", "CWE-73": "path_traversal",
    # memory
    "CWE-119": "memory", "CWE-120": "memory", "CWE-125": "memory",
    "CWE-787": "memory", "CWE-416": "memory", "CWE-476": "memory",
    # supply chain
    "CWE-1395": "supply_chain", "CWE-1104": "supply_chain",
    "CWE-937": "supply_chain",
    # config
    # dos
    "CWE-400": "dos", "CWE-1333": "dos", "CWE-770": "dos",
    # logging
    "CWE-778": "logging", "CWE-532": "logging",
    # other
    "CWE-601": "other", "CWE-noinfo": "other",
}

_CWE_RE = re.compile(r"^CWE-(?:\d+|noinfo)(?:-[a-z]+)?$")
_URI_RE = re.compile(r"^(?!/)(?!.*\.\.)[^\\]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT_RE = re.compile(r"^[A-Za-z]+/v\d+:[0-9a-f]{32}$")


def canonical_cwe(cwe: str) -> str:
    """Uppercase/trim a CWE id for consistent lookup."""
    return cwe.strip().upper().replace("CWE-NOINFO", "CWE-noinfo")


def family_for_cwe(cwe: str) -> Optional[str]:
    """Known family for a CWE, or None if unmapped (caller keeps declared family)."""
    return CWE_TO_FAMILY.get(canonical_cwe(cwe))


class FindingInvariantError(ValueError):
    """Raised by `assert_invariants` when a Finding violates I1-I10."""


# --------------------------------------------------------------------------- #
# Value objects
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CodeLocation:
    uri: str  # repo-relative, POSIX
    start_line: int
    end_line: int
    role: LocationRole
    snippet_sha256: str
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    symbol: Optional[str] = None
    snippet: Optional[str] = None  # may be dropped for redaction (secrets)


@dataclass(frozen=True)
class DataFlowStep:
    order: int
    location: CodeLocation
    note: str
    kind: Optional[Literal["source", "propagator", "sanitizer", "sink"]] = None


@dataclass
class Taxonomy:
    cwe: list[str]
    cwe_family: CweFamily
    cwe_confidence: Literal["exact", "mapped", "heuristic", "none"] = "heuristic"
    owasp_2025: list[str] = field(default_factory=list)
    asvs_5: list[str] = field(default_factory=list)
    capec: list[str] = field(default_factory=list)
    source_category: Optional[str] = None


@dataclass
class SeverityBlock:
    label: Severity
    sarif_level: SarifLevel
    security_severity: float
    cvss_v4: Optional[str] = None
    cvss_v3: Optional[str] = None
    cvss_vector: Optional[str] = None
    epss: Optional[float] = None
    kev: bool = False
    ssvc: Optional[dict] = None
    source_label: Optional[str] = None


@dataclass(frozen=True)
class Fingerprints:
    path_cwe_sink: str
    context_hash: str
    root_cause: str
    source_fingerprints: dict[str, str] = field(default_factory=dict)


@dataclass
class ProvenanceEntry:
    source_id: str
    source_kind: SourceKind
    family: str
    prompt_sha256: str
    collected_at: str
    model_id: Optional[str] = None
    model_snapshot: Optional[str] = None
    entitlement: Optional[str] = None
    safeguard_posture: Literal["relaxed", "default", "unknown"] = "unknown"
    classifier_fallback: bool = False
    angle: Optional[str] = None
    cli_version: Optional[str] = None
    tool_version: Optional[str] = None
    rule_pack_version: Optional[str] = None
    skill_sha256: Optional[str] = None
    raw_ref: Optional[str] = None
    local_id: Optional[str] = None
    degraded_parse: bool = False


@dataclass
class Corroboration:
    agent_sources: list[str] = field(default_factory=list)
    deterministic_sources: list[str] = field(default_factory=list)
    count: int = 0
    vendor_families: list[str] = field(default_factory=list)
    independent_family_count: int = 0
    corroboration_score: float = 0.0
    declined_sources: list[str] = field(default_factory=list)
    policy_excluded_sources: list[str] = field(default_factory=list)
    eligible_sources: list[str] = field(default_factory=list)
    coverage_denominator: float = 0.0
    singleton_by_policy: bool = False
    uncovered: bool = False
    independence_warning: Optional[dict] = None


@dataclass(frozen=True)
class EvidenceCitation:
    path: str
    start_line: int
    end_line: int
    claim: str
    verified: Optional[bool] = None
    snippet_sha256: Optional[str] = None


@dataclass
class PanelOpinion:
    role: PanelRole
    participant: str
    family: str
    prompt_sha256: str
    verdict: str
    rationale: str
    model_id: Optional[str] = None
    model_snapshot: Optional[str] = None
    citations: list[EvidenceCitation] = field(default_factory=list)
    citation_pass_rate: Optional[float] = None
    status: Literal["ok", "unevidenced", "unreliable", "absent"] = "ok"
    weight: float = 1.0
    elapsed_seconds: Optional[float] = None
    cost_usd: Optional[float] = None


@dataclass
class Reachability:
    verdict: Literal["external", "internal", "unreachable", "unknown"] = "unknown"
    entrypoints: list[str] = field(default_factory=list)
    trust_boundary: Optional[str] = None
    path_summary: Optional[str] = None


@dataclass
class Validation:
    verdict: Verdict
    confidence: float
    panel: list[PanelOpinion] = field(default_factory=list)
    evidence_check: dict = field(default_factory=dict)
    calibration: Literal["prior", "fitted", "uncalibrated"] = "prior"
    reachability: Optional[Reachability] = None
    impact: Optional[str] = None
    poc: None = None  # v1 (Blue) is defensive-only; I10 enforces this stays None
    human_review: Optional[dict] = None
    batched_with: list[str] = field(default_factory=list)
    no_cross_file_navigation: bool = False


@dataclass
class DecidedBy:
    kind: Literal["auto", "human"]
    decided_at: str
    model_id: Optional[str] = None
    model_snapshot: Optional[str] = None
    prompt_sha256: Optional[str] = None
    panel_sha256: Optional[str] = None
    template_version: Optional[str] = None
    operator: Optional[str] = None


@dataclass
class Disposition:
    state: DispositionState
    lifecycle: Lifecycle
    decided_by: DecidedBy
    sarif_suppression: Optional[dict] = None
    vex_status: Optional[VexStatus] = None
    vex_justification: Optional[str] = None
    decision_ref: Optional[str] = None
    expires_at: Optional[str] = None
    shadow: bool = False
    reopen_reason: Optional[str] = None


@dataclass
class Remediation:
    summary: str
    guidance: Optional[str] = None
    patch_ref: Optional[str] = None
    effort: Optional[Literal["S", "M", "L"]] = None
    references: list[str] = field(default_factory=list)


@dataclass
class Compliance:
    nist_800_53: list[str] = field(default_factory=list)
    ssdf: list[str] = field(default_factory=list)
    poam_due_date: Optional[str] = None
    control_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RuleRef:
    id: str
    source: str
    source_rule_id: Optional[str] = None
    name: Optional[str] = None
    help_uri: Optional[str] = None
    precision: Optional[str] = None


@dataclass
class PackageRef:
    purl: str
    version: Optional[str] = None
    fixed_version: Optional[str] = None
    advisory_ids: list[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    schema_version: int
    cluster_id: Optional[str]
    rule: RuleRef
    taxonomy: Taxonomy
    severity: SeverityBlock
    locations: list[CodeLocation]
    fingerprints: Fingerprints
    provenance: list[ProvenanceEntry]
    corroboration: Corroboration
    disposition: Disposition
    title: str
    description: str
    data_flow: list[DataFlowStep] = field(default_factory=list)
    baseline_state: Optional[Literal["new", "unchanged", "updated", "absent"]] = None
    validation: Optional[Validation] = None
    remediation: Optional[Remediation] = None
    compliance: Optional[Compliance] = None
    package: Optional[PackageRef] = None
    first_seen_run: Optional[str] = None
    last_seen_run: Optional[str] = None

# --------------------------------------------------------------------------- #
# Constants used by the invariants
# --------------------------------------------------------------------------- #

VALID_DECISION_KINDS: frozenset[str] = frozenset(("auto", "human"))
HIDDEN_LIFECYCLES: frozenset[str] = frozenset(("suppressed", "accepted_risk"))
CLOSED_LIFECYCLES: frozenset[str] = frozenset(("suppressed", "accepted_risk", "fixed"))
OPEN_LIFECYCLES: frozenset[str] = frozenset(("open", "reopened"))
# OpenVEX v0.2.0 justification strings (required when status == not_affected).
OPENVEX_JUSTIFICATIONS: frozenset[str] = frozenset((
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
))


def is_crypto_finding(f: "Finding") -> bool:
    """True if the finding is crypto-family by declared family OR by ANY cwe.

    The crypto guardrail (I7) keys on this, not on cwe[0] alone, so a crypto CWE
    hidden behind a non-crypto primary cannot evade auto-suppression.
    """
    if f.taxonomy.cwe_family == "crypto":
        return True
    return any(canonical_cwe(c) in CRYPTO_CWES for c in f.taxonomy.cwe)


def _is_sha256(s: object) -> bool:
    return isinstance(s, str) and bool(_SHA256_RE.match(s))


def _valid_rfc3339(s: object) -> bool:
    """Parseable RFC3339/ISO-8601 timestamp (rejects 'never', '', etc.)."""
    if not isinstance(s, str) or not s:
        return False
    try:
        datetime.fromisoformat(s.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _check_location_like(uri: str, start: int, end: int, sha: object, label: str,
                         errs: list[str], *, require_sha: bool) -> None:
    if not _URI_RE.match(uri or ""):
        errs.append(f"{label}: uri not repo-relative POSIX: {uri!r}")
    if not isinstance(start, int) or start < 1:
        errs.append(f"{label}: start_line must be >= 1")
    if isinstance(start, int) and isinstance(end, int) and end < start:
        errs.append(f"{label}: end_line < start_line")
    if require_sha and not _is_sha256(sha):
        errs.append(f"{label}: snippet_sha256 not a sha256 hex")


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #


def finding_id(fingerprints: "Fingerprints") -> str:
    """Derived, verifiable id: sha256(root_cause \x00 path_cwe_sink)[:16]."""
    payload = fingerprints.root_cause + "\x00" + fingerprints.path_cwe_sink
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Invariants I1-I12
# --------------------------------------------------------------------------- #


def validate_finding(f: "Finding") -> list[str]:
    """Return a list of invariant-violation messages (empty == valid).

    Fail-closed: unknown/ill-typed values are treated as violations rather than
    silently skipped, so a hidden disposition can never evade attribution.
    """
    errs: list[str] = []

    # I1 - primary locations (and their snippet hashes)
    if not f.locations:
        errs.append("I1: finding has no locations")
    for i, loc in enumerate(f.locations):
        _check_location_like(loc.uri, loc.start_line, loc.end_line, loc.snippet_sha256,
                             f"I1: locations[{i}]", errs, require_sha=True)
    for i, step in enumerate(f.data_flow):
        loc = step.location
        _check_location_like(loc.uri, loc.start_line, loc.end_line, loc.snippet_sha256,
                             f"I1: data_flow[{i}].location", errs, require_sha=True)

    # I2 - provenance (prompt_sha256 required only for agent_cli)
    if not f.provenance:
        errs.append("I2: finding has no provenance")
    for i, p in enumerate(f.provenance):
        if not p.source_id:
            errs.append(f"I2: provenance[{i}] missing source_id")
        if p.source_kind == "agent_cli":
            if not p.model_id:
                errs.append(f"I2: provenance[{i}] agent_cli requires model_id")
            if not _is_sha256(p.prompt_sha256):
                errs.append(f"I2: provenance[{i}] agent_cli requires sha256 prompt_sha256")
        elif p.source_kind == "scanner" and not p.tool_version:
            errs.append(f"I2: provenance[{i}] scanner requires tool_version")

    # I3 - fingerprints (line-number free by shape)
    for name in ("path_cwe_sink", "context_hash", "root_cause"):
        val = getattr(f.fingerprints, name)
        if not _FINGERPRINT_RE.match(val or ""):
            errs.append(f"I3: fingerprints.{name} malformed: {val!r}")

    # I4 - taxonomy, with crypto stickiness
    if not f.taxonomy.cwe:
        errs.append("I4: taxonomy.cwe is empty")
    else:
        for c in f.taxonomy.cwe:
            if not _CWE_RE.match(canonical_cwe(c)):
                errs.append(f"I4: taxonomy.cwe entry malformed: {c!r}")
        known = family_for_cwe(f.taxonomy.cwe[0])
        if known is not None and known != f.taxonomy.cwe_family:
            errs.append(
                f"I4: cwe_family {f.taxonomy.cwe_family!r} inconsistent with "
                f"{f.taxonomy.cwe[0]} (expected {known!r})"
            )
        if (any(canonical_cwe(c) in CRYPTO_CWES for c in f.taxonomy.cwe)
                and f.taxonomy.cwe_family != "crypto"):
            errs.append("I4: a crypto CWE is present but cwe_family is not 'crypto'")
        if f.taxonomy.cwe_family not in CWE_FAMILIES:
            errs.append(f"I4: cwe_family not a known family: {f.taxonomy.cwe_family!r}")

    # I5 - severity label valid and level derived from it
    if f.severity.label not in SEVERITIES:
        errs.append(f"I5: severity.label not a known severity: {f.severity.label!r}")
    else:
        expected_level = SEVERITY_TO_SARIF_LEVEL[f.severity.label]
        if expected_level != f.severity.sarif_level:
            errs.append(
                f"I5: severity.sarif_level {f.severity.sarif_level!r} != "
                f"{expected_level!r} for label {f.severity.label!r}"
            )

    db = f.disposition.decided_by
    # I6 - hidden dispositions must be fully, verifiably attributed
    if f.disposition.lifecycle in HIDDEN_LIFECYCLES:
        if db.kind not in VALID_DECISION_KINDS:
            errs.append(f"I6: decided_by.kind invalid: {db.kind!r}")
        if db.kind == "human":
            if not db.operator:
                errs.append(f"I6: human {f.disposition.lifecycle} missing decided_by.operator")
        else:  # fail-closed: anything not an explicit human decision is treated as auto
            if not db.model_id:
                errs.append(f"I6: auto {f.disposition.lifecycle} missing decided_by.model_id")
            if not _is_sha256(db.prompt_sha256):
                errs.append(f"I6: auto {f.disposition.lifecycle} needs sha256 prompt_sha256")
            if not _is_sha256(db.panel_sha256):
                errs.append(f"I6: auto {f.disposition.lifecycle} needs sha256 panel_sha256")
        if not f.disposition.decision_ref:
            errs.append(f"I6: {f.disposition.lifecycle} missing decision_ref")
        if not _valid_rfc3339(f.disposition.expires_at):
            errs.append(f"I6: {f.disposition.lifecycle} needs RFC3339 expires_at")
    # never auto-close: auto 'fixed' requires baseline evidence the finding is gone
    if f.disposition.lifecycle == "fixed" and db.kind != "human" and f.baseline_state != "absent":
        errs.append("I6: auto 'fixed' requires baseline_state == 'absent' (never auto-close)")

    # I7 - crypto is never auto-hidden (fail-closed on kind)
    if (is_crypto_finding(f)
            and f.disposition.lifecycle in HIDDEN_LIFECYCLES
            and db.kind != "human"):
        errs.append("I7: crypto finding auto-hidden (forbidden)")

    # I8 - corroboration count arithmetic
    distinct = len(set(f.corroboration.agent_sources) | set(f.corroboration.deterministic_sources))
    if f.corroboration.count != distinct:
        errs.append(
            f"I8: corroboration.count {f.corroboration.count} != distinct sources {distinct}"
        )

    # I9 - id derivation
    expected_id = finding_id(f.fingerprints)
    if f.id != expected_id:
        errs.append(f"I9: id {f.id!r} != derived {expected_id!r}")

    # I10 - no PoC in the defensive (Blue) profile
    if f.validation is not None and f.validation.poc is not None:
        errs.append("I10: validation.poc must be None in the defensive (Blue) profile")

    # I11 - suppression representations must cohere with a closed lifecycle
    d = f.disposition
    suppressed_repr = d.sarif_suppression is not None or d.vex_status in ("not_affected", "fixed")
    if suppressed_repr and d.lifecycle not in CLOSED_LIFECYCLES:
        errs.append(
            f"I11: suppression/not_affected/fixed representation on non-closed lifecycle "
            f"{d.lifecycle!r}"
        )
    if d.vex_status == "not_affected" and d.vex_justification not in OPENVEX_JUSTIFICATIONS:
        errs.append("I11: vex_status not_affected requires an OpenVEX justification")
    if d.vex_status in ("affected", "under_investigation") and d.lifecycle not in OPEN_LIFECYCLES:
        errs.append(f"I11: vex_status {d.vex_status!r} requires an open lifecycle")

    # I12 - panel evidence citations must be repo-relative and in-bounds
    if f.validation is not None:
        for oi, op in enumerate(f.validation.panel):
            for ci, cit in enumerate(op.citations):
                _check_location_like(cit.path, cit.start_line, cit.end_line, None,
                                     f"I12: validation.panel[{oi}].citations[{ci}]", errs,
                                     require_sha=False)

    return errs


def assert_invariants(f: "Finding") -> None:
    """Raise FindingInvariantError if any invariant is violated."""
    errs = validate_finding(f)
    if errs:
        raise FindingInvariantError("; ".join(errs))
