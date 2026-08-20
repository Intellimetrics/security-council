"""P2 tests: category-aware corroboration weighting."""
import hashlib

from security_council import model as m
from security_council.normalize import coverage as cov


def _sha(s): return hashlib.sha256(s.encode()).hexdigest()


def _prov(source_id, kind, family):
    return m.ProvenanceEntry(
        source_id=source_id, source_kind=kind, family=family,
        prompt_sha256=_sha("p") if kind == "agent_cli" else "",
        collected_at="t", model_id="mdl" if kind == "agent_cli" else None,
        tool_version="1" if kind == "scanner" else None)


def _finding(reporters, family="injection"):
    fps = m.Fingerprints(path_cwe_sink="pathCweSink/v1:" + _sha("a")[:32],
                         context_hash="contextHash/v1:" + _sha("b")[:32],
                         root_cause="rootCause/v1:" + _sha("c")[:32])
    return m.Finding(
        id=m.finding_id(fps), schema_version=1, cluster_id=None,
        rule=m.RuleRef(id="r", source="x"),
        taxonomy=m.Taxonomy(cwe=["CWE-89"] if family == "injection" else ["CWE-noinfo"],
                            cwe_family=family),
        severity=m.SeverityBlock(label="high", sarif_level="error", security_severity=8.0),
        locations=[m.CodeLocation(uri="a.py", start_line=1, end_line=1, role="primary",
                                  snippet_sha256=_sha("s"))],
        fingerprints=fps, provenance=[_prov(*r) for r in reporters],
        corroboration=m.Corroboration(), disposition=m.Disposition(
            state="new", lifecycle="open", decided_by=m.DecidedBy(kind="auto", decided_at="t")),
        title="t", description="d")


def _rc(sources):
    return cov.RunContext(sources=[cov.SourceRun(*s) for s in sources])


def test_declining_eligible_arms_raise_decline_ratio():
    f = _finding([("house", "agent_cli", "claude")])  # only house reported
    rc = _rc([("semgrep", "scanner", "semgrep"), ("house", "agent_cli", "claude"),
              ("agy", "agent_cli", "google")])
    c = cov.compute(f, rc)
    assert len(c.eligible_sources) == 3 and not c.singleton_by_policy
    assert c.corroboration_score == 1.0                 # house only
    assert cov.decline_ratio(c) > 0.6                    # semgrep + agy declined


def test_singleton_by_policy_has_no_fp_prior():
    f = _finding([("osv-scanner", "scanner", "google")], family="supply_chain")
    rc = _rc([("osv-scanner", "scanner", "google"), ("claude-security", "agent_cli", "claude")])
    c = cov.compute(f, rc)
    assert c.singleton_by_policy is True                 # only osv is eligible
    assert "claude-security" in c.policy_excluded_sources  # it suppresses supply_chain
    assert cov.decline_ratio(c) == 0.0


def test_same_family_independence_is_weighted_down():
    f = _finding([("house", "agent_cli", "claude"), ("claude-security", "agent_cli", "claude")])
    rc = _rc([("house", "agent_cli", "claude"), ("claude-security", "agent_cli", "claude")])
    c = cov.compute(f, rc)
    assert c.corroboration_score == 1.35                 # 1.0 + 0.35 (same family), not 2.0
    assert c.independence_warning is not None            # one vendor family


def test_deterministic_plus_independent_is_strongest():
    f = _finding([("semgrep", "scanner", "semgrep"), ("house", "agent_cli", "claude")])
    rc = _rc([("semgrep", "scanner", "semgrep"), ("house", "agent_cli", "claude")])
    c = cov.compute(f, rc)
    assert c.corroboration_score == 2.25                 # 1.25 deterministic + 1.0 independent
    assert c.independence_warning is None                # 2 distinct families


def test_uncovered_category_flagged():
    f = _finding([("house", "agent_cli", "claude")], family="llm_safety")
    rc = _rc([("semgrep", "scanner", "semgrep"), ("house", "agent_cli", "claude")])
    c = cov.compute(f, rc)
    # semgrep=not_applicable, house=unknown for llm_safety -> nobody eligible
    assert c.uncovered is True and c.eligible_sources == []


def test_apply_keeps_i8_arithmetic():
    f = _finding([("semgrep", "scanner", "semgrep"), ("house", "agent_cli", "claude")])
    rc = _rc([("semgrep", "scanner", "semgrep"), ("house", "agent_cli", "claude")])
    cov.apply(f, rc)
    m.assert_invariants(f)   # I8 count must match after coverage overwrites corroboration
