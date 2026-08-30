"""Root-cause clustering across arms.

Generalizes llm-council's line-overlap clustering into four tiered join rules,
resolved with union-find (near-linear, not the O(n^3) of the original):

  T1 root_cause   identical rootCause fingerprint
  T2 location     same primary path AND same cwe_family AND line ranges overlap +-3
  T3 context      identical contextHash AND same cwe_family (moved / duplicated code)
  T4 package      same purl-without-version AND a shared advisory id

Unlike the upstream, **single-source clusters are kept** — corroboration is a
score input, not an admission gate (dropping singletons is exactly how the
published FP filters lose ~22% of true positives).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, replace

from .fingerprint import purl_without_version
from .model import (
    SCHEMA_VERSION,
    SEVERITY_TO_SARIF_LEVEL,
    SEVERITY_TO_SECURITY_SEVERITY,
    CRYPTO_CWES,
    CodeLocation,
    Corroboration,
    Disposition,
    Finding,
    SeverityBlock,
    Taxonomy,
    canonical_cwe,
    family_for_cwe,
    finding_id,
)

_RANGE_SLOP = 3
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@dataclass
class FindingCluster:
    id: str
    root_cause: str
    representative: Finding
    members: list[Finding]
    sources: list[str]
    vendor_families: list[str]
    join_tiers: list[str]
    independence_warning: dict | None = field(default=None)


# --------------------------------------------------------------------------- #
# union-find with per-cluster tier tracking
# --------------------------------------------------------------------------- #


class _DisjointSet:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.rank = [0] * n
        self.tiers: list[set[str]] = [set() for _ in range(n)]

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int, tier: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            self.tiers[ra].add(tier)
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.tiers[ra] |= self.tiers[rb]
        self.tiers[ra].add(tier)
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1

    def groups(self) -> dict[int, list[int]]:
        g: dict[int, list[int]] = defaultdict(list)
        for i in range(len(self.parent)):
            g[self.find(i)].append(i)
        return g


def primary_location(f: Finding) -> CodeLocation:
    for loc in f.locations:
        if loc.role == "primary":
            return loc
    return f.locations[0]


def _ranges_overlap(a: Finding, b: Finding) -> bool:
    la, lb = primary_location(a), primary_location(b)
    return not (la.end_line + _RANGE_SLOP < lb.start_line
                or lb.end_line + _RANGE_SLOP < la.start_line)


def cluster_findings(findings: list[Finding], *, min_distinct_vendors: int = 2) -> list[FindingCluster]:
    n = len(findings)
    ds = _DisjointSet(n)

    # T1 root_cause — hash bucket, O(n)
    by_rc: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(findings):
        by_rc[f.fingerprints.root_cause].append(i)
    for idxs in by_rc.values():
        for j in idxs[1:]:
            ds.union(idxs[0], j, "root_cause")

    # T3 context_hash + family — hash bucket, O(n). Package findings excluded: their
    # "context" is the manifest file (identical for every advisory), so they must
    # cluster only by root_cause (T1) and package+advisory (T4).
    by_ctx: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, f in enumerate(findings):
        if f.package is not None:
            continue
        by_ctx[(f.fingerprints.context_hash, f.taxonomy.cwe_family)].append(i)
    for idxs in by_ctx.values():
        for j in idxs[1:]:
            ds.union(idxs[0], j, "context")

    # T4 package — bucket by (purl-sans-version, advisory)
    by_pkg: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, f in enumerate(findings):
        if f.package is not None:
            for adv in (f.package.advisory_ids or ["-"]):
                by_pkg[(purl_without_version(f.package.purl), adv)].append(i)
    for idxs in by_pkg.values():
        for j in idxs[1:]:
            ds.union(idxs[0], j, "package")

    # T2 location — bucket by (primary path, family), pairwise overlap within bucket.
    # Package/dependency findings are excluded: they all sit at the manifest file,
    # so location overlap would wrongly merge distinct advisories (they cluster via T4).
    by_pf: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, f in enumerate(findings):
        if f.package is not None:
            continue
        by_pf[(primary_location(f).uri, f.taxonomy.cwe_family)].append(i)
    for idxs in by_pf.values():
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                if _ranges_overlap(findings[idxs[a]], findings[idxs[b]]):
                    ds.union(idxs[a], idxs[b], "location")

    clusters: list[FindingCluster] = []
    for root, idxs in ds.groups().items():
        members = [findings[i] for i in idxs]
        rep = _representative(members)
        rc = rep.fingerprints.root_cause
        agent, det, families = _sources(members)
        indep = len(families)
        warn = None
        if indep < min_distinct_vendors:
            warn = {"distinct_vendors": indep, "required": min_distinct_vendors,
                    "families": families, "reporting_sources": sorted(set(agent) | set(det))}
        clusters.append(FindingCluster(
            id="C" + rc.split(":", 1)[1][:12],
            root_cause=rc,
            representative=rep,
            members=members,
            sources=sorted(set(agent) | set(det)),
            vendor_families=families,
            join_tiers=sorted(ds.tiers[root]),
            independence_warning=warn,
        ))
    return clusters


def _representative(members: list[Finding]) -> Finding:
    return sorted(members, key=lambda f: (-_SEV_RANK[f.severity.label], -len(f.locations), f.id))[0]


def _sources(members: list[Finding]) -> tuple[list[str], list[str], list[str]]:
    agent, det, fams = set(), set(), set()
    for m in members:
        for p in m.provenance:
            fams.add(p.family)
            if p.source_kind == "agent_cli":
                agent.add(p.source_id)
            elif p.source_kind == "scanner":
                det.add(p.source_id)
    return sorted(agent), sorted(det), sorted(fams)


def _merge_taxonomy(members: list[Finding]) -> Taxonomy:
    cwes: list[str] = []
    for m in members:
        for c in m.taxonomy.cwe:
            cc = canonical_cwe(c)
            if cc not in cwes:
                cwes.append(cc)
    is_crypto = (any(cc in CRYPTO_CWES for cc in cwes)
                 or any(m.taxonomy.cwe_family == "crypto" for m in members))
    if is_crypto:
        cryptos = [c for c in cwes if c in CRYPTO_CWES]
        if cryptos:  # keep cwe[0] consistent with the crypto family (I4)
            cwes = [cryptos[0]] + [c for c in cwes if c != cryptos[0]]
            family = "crypto"
        else:
            family = members[0].taxonomy.cwe_family
    else:
        family = family_for_cwe(cwes[0]) or members[0].taxonomy.cwe_family
    conf = "exact" if any(m.taxonomy.cwe_confidence == "exact" for m in members) \
        else members[0].taxonomy.cwe_confidence
    return Taxonomy(
        cwe=cwes, cwe_family=family, cwe_confidence=conf,
        owasp_2025=sorted({o for m in members for o in m.taxonomy.owasp_2025}),
        asvs_5=sorted({a for m in members for a in m.taxonomy.asvs_5}),
    )


def _merge_locations(members: list[Finding]) -> list[CodeLocation]:
    seen: set[tuple] = set()
    out: list[CodeLocation] = []
    for m in members:
        for loc in m.locations:
            key = (loc.uri, loc.start_line, loc.end_line, loc.role)
            if key not in seen:
                seen.add(key)
                out.append(loc)
    return out


def merge_cluster(cluster: FindingCluster) -> Finding:
    """Collapse a cluster into a single canonical Finding (invariant-valid)."""
    members = cluster.members
    rep = cluster.representative
    tax = _merge_taxonomy(members)
    label = max((m.severity.label for m in members), key=lambda s: _SEV_RANK[s])
    sev = SeverityBlock(
        label=label,
        sarif_level=SEVERITY_TO_SARIF_LEVEL[label],
        security_severity=max(m.severity.security_severity for m in members)
        or SEVERITY_TO_SECURITY_SEVERITY[label],
    )
    agent, det, _ = _sources(members)
    corr = Corroboration(
        agent_sources=agent,
        deterministic_sources=det,
        count=len(set(agent) | set(det)),
        vendor_families=cluster.vendor_families,
        independent_family_count=len(cluster.vendor_families),
        independence_warning=cluster.independence_warning,
    )
    provenance = [p for m in members for p in m.provenance]
    merged_sfp: dict[str, str] = {}
    for mem in members:
        merged_sfp.update(mem.fingerprints.source_fingerprints or {})
    fp = replace(rep.fingerprints, source_fingerprints=merged_sfp)
    # Revision-bound import arms may carry a completed validation.  Keep the
    # strongest one through clustering so a later cross-vendor panel can add
    # opinions to it instead of erasing the host's source/control/sink trace.
    prior_validations = [m.validation for m in members if m.validation is not None]
    validation = max(prior_validations, key=lambda value: value.confidence, default=None)
    state = "new"
    if validation is not None and validation.verdict == "true_positive":
        state = "validated" if (corr.independent_family_count >= 2
                                or bool(corr.deterministic_sources)) else "likely"
    return Finding(
        id=finding_id(fp),
        schema_version=SCHEMA_VERSION,
        cluster_id=cluster.id,
        rule=rep.rule,
        taxonomy=tax,
        severity=sev,
        locations=_merge_locations(members),
        fingerprints=fp,
        provenance=provenance,
        corroboration=corr,
        disposition=Disposition(state=state, lifecycle="open",
                                decided_by=rep.disposition.decided_by),
        title=rep.title,
        description=rep.description,
        data_flow=rep.data_flow,
        remediation=rep.remediation,
        compliance=rep.compliance,
        package=rep.package,
        validation=validation,
    )
