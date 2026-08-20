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

from ..model import Corroboration, Finding

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
        w = _weight(s, stance, family_seen)
        family_seen.add(s.family)
        denom += w
        eligible.append(s.source_id)
        if s.source_id in reporting:
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
