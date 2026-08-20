"""P1 tests: root-cause clustering (union-find, tiered joins) + merge validity."""
import hashlib

from security_council import cluster as cl
from security_council import fingerprint as fp
from security_council import model as m


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def mk(*, path="app/x.py", start=10, end=12, cwe="CWE-89", family="injection",
       source_id="house", source_kind="agent_cli", vendor="claude", sink="q",
       root_symbol=None, ctx=None, package=None, sev="high",
       root_cause=None, context_hash=None) -> m.Finding:
    sym = root_symbol or f"{path}:{sink}"
    fps = m.Fingerprints(
        path_cwe_sink=fp.path_cwe_sink(path=path, cwe=cwe, sink_token=sym),
        context_hash=context_hash or fp.context_hash(ctx or [f"stmt_{sink}(x)"]),
        root_cause=root_cause or fp.root_cause(cwe_family=family, root_symbol=sym,
                                               sink_expr=sink, package=package),
    )
    prov = m.ProvenanceEntry(
        source_id=source_id, source_kind=source_kind, family=vendor,
        prompt_sha256=_sha("p") if source_kind == "agent_cli" else "",
        collected_at="2026-08-20T00:00:00Z",
        model_id="claude-fable-5" if source_kind == "agent_cli" else None,
        tool_version="1.0" if source_kind == "scanner" else None,
    )
    corr = m.Corroboration(
        agent_sources=[source_id] if source_kind == "agent_cli" else [],
        deterministic_sources=[source_id] if source_kind == "scanner" else [],
        count=1)
    return m.Finding(
        id=m.finding_id(fps), schema_version=m.SCHEMA_VERSION, cluster_id=None,
        rule=m.RuleRef(id="sc/x", source=source_id), taxonomy=m.Taxonomy(cwe=[cwe], cwe_family=family),
        severity=m.SeverityBlock(label=sev, sarif_level=m.SEVERITY_TO_SARIF_LEVEL[sev],
                                 security_severity=m.SEVERITY_TO_SECURITY_SEVERITY[sev]),
        locations=[m.CodeLocation(uri=path, start_line=start, end_line=end, role="primary",
                                  snippet_sha256=_sha(f"{path}:{start}"))],
        fingerprints=fps, provenance=[prov], corroboration=corr,
        disposition=m.Disposition(state="new", lifecycle="open",
                                  decided_by=m.DecidedBy(kind="auto", decided_at="2026-08-20T00:00:00Z")),
        title="t", description="d", package=package)


def test_same_root_cause_merges():
    a = mk(root_cause="rootCause/v1:" + _sha("shared")[:32])
    b = mk(path="app/y.py", start=99, root_cause="rootCause/v1:" + _sha("shared")[:32])
    cs = cl.cluster_findings([a, b])
    assert len(cs) == 1 and len(cs[0].members) == 2
    assert "root_cause" in cs[0].join_tiers


def test_cross_file_idor_call_sites_merge_via_location():
    # same file, same family, overlapping lines, but different root_cause/context
    a = mk(path="app/repo.py", start=10, end=12, family="authz", cwe="CWE-639", sink="s1")
    b = mk(path="app/repo.py", start=13, end=14, family="authz", cwe="CWE-639", sink="s2")
    cs = cl.cluster_findings([a, b])
    assert len(cs) == 1
    assert "location" in cs[0].join_tiers


def test_different_family_same_line_does_not_merge():
    a = mk(path="app/v.py", start=10, end=10, family="xss", cwe="CWE-79")
    b = mk(path="app/v.py", start=10, end=10, family="injection", cwe="CWE-89")
    cs = cl.cluster_findings([a, b])
    assert len(cs) == 2


def test_transitive_merge_across_tiers():
    shared_rc = "rootCause/v1:" + _sha("rc")[:32]
    shared_ctx = "contextHash/v1:" + _sha("ctx")[:32]
    a = mk(source_id="s1", root_cause=shared_rc)
    b = mk(source_id="s2", root_cause=shared_rc, context_hash=shared_ctx)  # ~a via rc
    c = mk(source_id="s3", path="app/z.py", start=200, context_hash=shared_ctx)  # ~b via context
    cs = cl.cluster_findings([a, b, c])
    assert len(cs) == 1 and len(cs[0].members) == 3
    assert {"root_cause", "context"} <= set(cs[0].join_tiers)


def test_singletons_are_kept_with_independence_warning():
    a = mk(source_id="only")
    cs = cl.cluster_findings([a], min_distinct_vendors=2)
    assert len(cs) == 1
    assert cs[0].independence_warning["distinct_vendors"] == 1


def test_merge_cluster_is_invariant_valid_and_counts_sources():
    rc = "rootCause/v1:" + _sha("shared2")[:32]
    a = mk(source_id="house", source_kind="agent_cli", vendor="claude", root_cause=rc)
    b = mk(source_id="semgrep", source_kind="scanner", vendor="semgrep", root_cause=rc, path="app/y.py")
    [c] = cl.cluster_findings([a, b])
    merged = cl.merge_cluster(c)
    m.assert_invariants(merged)  # boundary check — must not raise
    assert merged.corroboration.count == 2
    assert merged.corroboration.agent_sources == ["house"]
    assert merged.corroboration.deterministic_sources == ["semgrep"]
    assert merged.corroboration.independence_warning is None  # 2 distinct vendors
    assert len(merged.locations) == 2
    assert merged.cluster_id == c.id


def test_merge_cluster_crypto_sticky():
    rc = "rootCause/v1:" + _sha("shared3")[:32]
    a = mk(cwe="CWE-79", family="xss", root_cause=rc)
    b = mk(cwe="CWE-327", family="crypto", root_cause=rc, path="app/y.py")
    [c] = cl.cluster_findings([a, b])
    merged = cl.merge_cluster(c)
    m.assert_invariants(merged)
    assert merged.taxonomy.cwe_family == "crypto"
    assert merged.taxonomy.cwe[0] == "CWE-327"  # crypto cwe pulled to front for I4


def test_package_findings_merge_across_versions():
    pa = m.PackageRef(purl="pkg:pypi/urllib3@1.24.1", advisory_ids=["CVE-2024-37891"])
    pb = m.PackageRef(purl="pkg:pypi/urllib3@2.0.0", advisory_ids=["CVE-2024-37891"])
    a = mk(family="supply_chain", cwe="CWE-1395", package=pa, path="requirements.txt", start=3, end=3)
    b = mk(family="supply_chain", cwe="CWE-1395", package=pb, path="requirements.txt", start=3, end=3)
    cs = cl.cluster_findings([a, b])
    assert len(cs) == 1
    assert "package" in cs[0].join_tiers


def test_scales_to_5000_findings():
    # 1000 root-cause groups x 5 duplicates each -> 1000 clusters, near-linear.
    findings = []
    for g in range(1000):
        rc = "rootCause/v1:" + _sha(f"g{g}")[:32]
        for k in range(5):
            findings.append(mk(source_id=f"s{k}", vendor=f"v{k}", root_cause=rc,
                               ctx=[f"stmt_g{g}(x)"], path=f"app/f{g}.py", start=10 + k))
    cs = cl.cluster_findings(findings)
    assert len(cs) == 1000
    assert all(len(c.members) == 5 for c in cs)
