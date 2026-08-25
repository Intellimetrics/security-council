"""Category-aware corroboration.

Naive N-of-M voting is wrong when arms have different remits: Claude suppresses
whole vulnerability classes by policy, gitleaks only reports secrets, osv only
dependencies. This computes corroboration against the sources that were actually
*eligible* to report a finding's category, with vendor-family independence
weighting — so a finding only one arm could have reported is not penalized for
the silence of arms that were never allowed to agree.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model import CWE_FAMILIES, Corroboration, Finding

# Per-source category stance. Keyed by source_id; "*" is the source default.
# Derived from R2 (each producer's documented detection scope / exclusions);
# adjust as real behavior is measured. reports|suppresses|not_applicable|unknown.
CATEGORY_POLICY: dict[str, dict[str, str]] = {
    "semgrep": {"injection": "reports", "xss": "reports", "path_traversal": "reports",
                "ssrf": "reports", "deserialization": "reports", "crypto": "reports",
                "secrets": "reports", "config": "reports", "supply_chain": "not_applicable",
                "dos": "not_applicable", "logging": "not_applicable", "llm_safety": "not_applicable",
                "*": "unknown"},
    "gitleaks": {"secrets": "reports", "*": "not_applicable"},
    "osv-scanner": {"supply_chain": "reports", "*": "not_applicable"},
    "claude-security": {"supply_chain": "suppresses", "dos": "suppresses", "logging": "suppresses",
                        "llm_safety": "unknown", "*": "reports"},
    "house": {"llm_safety": "unknown", "*": "reports"},
    "codex-security": {"llm_safety": "unknown", "dos": "unknown", "logging": "unknown",
                       "*": "reports"},
    "agy": {"llm_safety": "reports", "dos": "reports", "authn": "unknown", "memory": "unknown",
            "supply_chain": "unknown", "deserialization": "unknown", "logging": "unknown",
            "*": "reports"},
}

# Arm names (arms/registry) that run the generic house prompt and therefore carry
# the "house" stance table. Without this, a source with no policy entry is
# "unknown" for every family and can never count as eligible -- which mislabels
# a 2-vendor-corroborated finding as singleton-by-policy.
POLICY_ALIASES: dict[str, str] = {"claude": "house", "codex": "house"}


@dataclass
class SourceRun:
    source_id: str
    kind: str                       # agent_cli | scanner
    family: str                     # vendor family (independence unit)
    ran: bool = True
    supported_families: frozenset[str] | None = None   # None = all
    # Whether this source's SILENCE is evidence. A partial run covered an
    # unknown subset, so "it didn't report this" tells you nothing — but what it
    # DID report still counts. Only a fully-verified source may decline.
    may_decline: bool = True


# --------------------------------------------------------------------------- #
# Coverage verdict (R12) — what an arm actually examined, not merely whether it
# exited 0.
# --------------------------------------------------------------------------- #

VERIFIED, PARTIAL, NONE = "verified", "partial", "none"


def coverage_verdict(result) -> str:
    """Tri-state: what this arm can vouch for having examined.

    The 0.1.0 ship review spent four council rounds here. Coverage was a per-arm
    BOOLEAN (`ArmResult.ok`, plus an easily-forgotten `coverage_unverified`),
    and every round turned up a fresh way for a scan that examined less than it
    claimed to report clean — a missing report, an unreadable report, zero arms
    with `min_arms_ok: 0`, an arm that declined every category, a timed-out
    scanner resurrected by partial findings. Patching each one produced the
    next. This is the single place that answers the question.

    - ``none``     the arm examined nothing it can vouch for: it failed, wrote
                   no report, wrote an unreadable one, or declined everything.
    - ``partial``  it ran, but over less than its full scope: a timeout, an
                   incomplete vendor bundle, a cost stop, declined categories.
    - ``verified`` it completed and can vouch for the scope it was given.
                   ``not_applicable`` lands here on purpose: nothing was in
                   scope (a repo with no dependency manifests, for osv), which
                   is an honest clean for that arm's categories.
    """
    if not getattr(result, "ok", False):
        return NONE
    cov = getattr(result, "coverage", None) or {}
    # order matters: `coverage_unverified` is the stronger signal, so a
    # not-applicable marker can never rescue an arm that vouches for nothing
    if cov.get("coverage_unverified"):
        return NONE
    # every PARTIAL signal is checked BEFORE not_applicable: "nothing was in
    # scope" is only an honest clean when the arm actually finished looking
    if (cov.get("ignore_files")            # the repo told the tool to skip things
            or cov.get("partial_scan") or cov.get("cost_stopped")
            or cov.get("completion") in ("partial", "declined")
            or cov.get("declined_categories")):
        return PARTIAL
    # R12: a scanner that reported N results but could only normalise fewer has
    # silently dropped findings (an unresolvable location, a path outside the
    # scanned root). The run covered less than the tool actually reported.
    raw, norm = cov.get("raw_results"), cov.get("normalized")
    if isinstance(raw, int) and isinstance(norm, int) and norm < raw:
        return PARTIAL
    if cov.get("not_applicable"):
        return VERIFIED
    # An AGENT arm is required to self-report `completion`; the house envelope
    # has a `scan` block for exactly that. A missing or unrecognised value means
    # it never said it finished, and absence of a claim is not a claim of
    # completeness — it fell through to `verified` before. Scanners never report
    # completion (their report IS the claim), so they are unaffected.
    if getattr(result, "kind", "") == "agent_cli" and cov.get("completion") != "complete":
        return PARTIAL
    return VERIFIED


def declined_families(result) -> frozenset[str]:
    """The families an arm explicitly reported it did not look at."""
    cov = getattr(result, "coverage", None) or {}
    return frozenset({str(x) for x in (cov.get("declined_categories") or [])} & CWE_FAMILIES)


def source_run_for(result) -> "SourceRun":
    """The corroboration source for an arm, honouring what it really covered.

    A ``none`` arm never votes — it has no standing to agree with a finding or
    to be counted as silently declining one. A ``partial`` arm votes only on the
    families it did NOT decline, so it is neither credited for agreement nor
    penalised as silent on ground it never covered. That distinction is the
    whole point of the tri-state: silence only means something from a source
    that was actually looking.
    """
    verdict = coverage_verdict(result)
    declined = declined_families(result)
    return SourceRun(result.name, result.kind, result.family,
                     ran=verdict != NONE,
                     supported_families=(frozenset(CWE_FAMILIES) - declined) if declined else None,
                     may_decline=verdict == VERIFIED)


@dataclass
class RunContext:
    sources: list[SourceRun] = field(default_factory=list)
    min_distinct_vendors: int = 2


def stance_of(source_id: str, family: str) -> str:
    pol = CATEGORY_POLICY.get(source_id) or CATEGORY_POLICY.get(POLICY_ALIASES.get(source_id, ""))
    if pol is None:
        return "unknown"
    return pol.get(family, pol.get("*", "unknown"))


def _weight(s: SourceRun, stance: str, family_seen: set[str]) -> float:
    if s.kind == "scanner":
        return 1.25
    if stance == "unknown":
        return 0.5
    if s.family in family_seen:
        return 0.35
    return 1.0


def compute(finding: Finding, run_ctx: RunContext) -> Corroboration:
    fam = finding.taxonomy.cwe_family
    reporting = {p.source_id for p in finding.provenance}

    denom = 0.0
    score = 0.0
    decline_w = 0.0
    eligible, declined, excluded = [], [], []
    family_seen: set[str] = set()

    for s in sorted(run_ctx.sources, key=lambda x: x.source_id):
        stance = stance_of(s.source_id, fam)
        if stance == "suppresses":
            excluded.append(s.source_id)
            continue
        supported = s.supported_families is None or fam in s.supported_families
        is_eligible = s.ran and stance == "reports" and supported
        if not is_eligible:
            continue
        is_reporting = s.source_id in reporting
        if not is_reporting and not s.may_decline:
            # partial scope: it may simply never have looked here. Neither
            # credit nor penalty, and it does not dilute the denominator.
            continue
        w = _weight(s, stance, family_seen)
        family_seen.add(s.family)
        denom += w
        eligible.append(s.source_id)
        if is_reporting:
            score += w
        else:
            decline_w += w
            declined.append(s.source_id)

    agent = sorted({p.source_id for p in finding.provenance if p.source_kind == "agent_cli"})
    det = sorted({p.source_id for p in finding.provenance if p.source_kind == "scanner"})
    families = sorted({p.family for p in finding.provenance})
    warn = None
    if len(families) < run_ctx.min_distinct_vendors:
        warn = {"distinct_vendors": len(families), "required": run_ctx.min_distinct_vendors,
                "families": families, "reporting_sources": sorted(reporting)}

    return Corroboration(
        agent_sources=agent, deterministic_sources=det,
        count=len(set(agent) | set(det)),
        vendor_families=families, independent_family_count=len(families),
        corroboration_score=round(score, 4),
        declined_sources=sorted(declined), policy_excluded_sources=sorted(excluded),
        eligible_sources=sorted(eligible), coverage_denominator=round(denom, 4),
        singleton_by_policy=(len(eligible) == 1),
        uncovered=(len(eligible) == 0),
        independence_warning=warn,
    )


def apply(finding: Finding, run_ctx: RunContext) -> Finding:
    """Replace the finding's corroboration with the category-aware computation."""
    finding.corroboration = compute(finding, run_ctx)
    return finding


def decline_ratio(corr: Corroboration) -> float:
    if corr.coverage_denominator <= 0:
        return 0.0
    reported_w = corr.corroboration_score
    return round(max(0.0, corr.coverage_denominator - reported_w) / corr.coverage_denominator, 4)
