"""Validator panel tests with an injected fake council runner."""
import hashlib

from security_council import model as m
from security_council.export import sarif
from security_council.validate import panel
from security_council.validate.council_client import CouncilResult, PeerResult


def _sha(s): return hashlib.sha256(s.encode()).hexdigest()


def _finding(*, family="injection", sev="high", sources=(("semgrep", "scanner", "semgrep"),
                                                          ("house", "agent_cli", "claude"))):
    fps = m.Fingerprints(path_cwe_sink="pathCweSink/v1:" + _sha("p")[:32],
                         context_hash="contextHash/v1:" + _sha("c")[:32],
                         root_cause="rootCause/v1:" + _sha("r")[:32])
    prov = []
    for sid, kind, fam in sources:
        prov.append(m.ProvenanceEntry(source_id=sid, source_kind=kind, family=fam,
                    prompt_sha256=_sha("p") if kind == "agent_cli" else "", collected_at="t",
                    model_id="mdl" if kind == "agent_cli" else None,
                    tool_version="1" if kind == "scanner" else None))
    agent = [s for s, k, f in sources if k == "agent_cli"]
    det = [s for s, k, f in sources if k == "scanner"]
    return m.Finding(
        id=m.finding_id(fps), schema_version=1, cluster_id=None, rule=m.RuleRef(id="r", source="x"),
        taxonomy=m.Taxonomy(cwe=["CWE-89"], cwe_family=family),
        severity=m.SeverityBlock(label=sev, sarif_level=m.SEVERITY_TO_SARIF_LEVEL[sev],
                                 security_severity=m.SEVERITY_TO_SECURITY_SEVERITY[sev]),
        locations=[m.CodeLocation(uri="app/reports.py", start_line=9, end_line=9, role="primary",
                                  snippet_sha256=_sha("s"), snippet="q = f\"...{name}...\"")],
        fingerprints=fps, provenance=prov,
        corroboration=m.Corroboration(agent_sources=agent, deterministic_sources=det,
                                      count=len(set(agent) | set(det)),
                                      independent_family_count=len({f for _, _, f in sources})),
        disposition=m.Disposition(state="new", lifecycle="open",
                                  decided_by=m.DecidedBy(kind="auto", decided_at="t")),
        title="SQLi in reports", description="f-string SQL on request data")


def _cite(path="app/reports.py", verified=True):
    return {"path": path, "start_line": 9, "end_line": 9, "text": "user input into query", "verified": verified}


def _runner(votes, degraded=False):
    def run(prompt, *, cwd, mode="consensus", max_cost_usd=None, timeout=600):
        peers = [PeerResult(name=n, ok=True, label=lbl, stance=st, model="m", confidence="high",
                            blockers=["reachable from request"], evidence=cites) for n, st, lbl, cites in votes]
        return CouncilResult(ok=True, degraded=degraded, results=peers)
    return run


def test_unanimous_real_is_true_positive_validated():
    f = _finding()
    panel.validate_finding(f, repo_root=".", runner=_runner([
        ("claude", "for", "yes", [_cite()]),
        ("codex", "against", "no", [_cite()]),   # defender says FP but...
        ("antigravity", "neutral", "yes", [_cite()])]))
    # 2 reals (claude, antigravity) > 1 fp -> true_positive
    assert f.validation.verdict == "true_positive"
    assert f.disposition.state == "validated"       # deterministic corroboration present
    assert f.disposition.lifecycle == "open"        # never auto-closed
    m.assert_invariants(f)


def test_majority_fp_is_refuted_and_demoted_in_sarif():
    f = _finding()
    panel.validate_finding(f, repo_root=".", runner=_runner([
        ("claude", "for", "no", [_cite()]),
        ("codex", "against", "no", [_cite()]),
        ("antigravity", "neutral", "no", [_cite()])]))
    assert f.validation.verdict == "false_positive"
    assert f.disposition.state == "refuted"
    assert f.disposition.lifecycle == "open"         # demote, not suppress
    s = sarif.to_sarif([f])
    res = s["runs"][0]["results"][0]
    assert res["suppressions"][0]["status"] == "underReview"   # auto-demote


def test_degraded_is_needs_human():
    f = _finding()
    panel.validate_finding(f, repo_root=".", runner=_runner([
        ("claude", "for", "yes", [_cite()])], degraded=True))
    assert f.validation.verdict == "needs_human"
    assert f.disposition.state == "needs_human"


def test_defender_hallucinated_citation_escalates_to_needs_human():
    f = _finding()
    panel.validate_finding(f, repo_root=".", runner=_runner([
        ("claude", "for", "no", [_cite()]),
        ("codex", "against", "no", [_cite(verified=False)]),   # defender fabricated
        ("antigravity", "neutral", "no", [_cite()])]))
    assert f.validation.verdict == "needs_human"
    assert f.validation.evidence_check["defender_hallucinated"] is True


def test_true_positive_without_corroboration_is_likely():
    f = _finding(sources=(("house", "agent_cli", "claude"),))   # single source, one family
    panel.validate_finding(f, repo_root=".", runner=_runner([
        ("claude", "for", "yes", [_cite()]),
        ("codex", "against", "yes", [_cite()]),
        ("antigravity", "neutral", "yes", [_cite()])]))
    assert f.validation.verdict == "true_positive"
    assert f.disposition.state == "likely"           # no independent corroboration


def test_absolute_citation_is_dropped():
    f = _finding()
    panel.validate_finding(f, repo_root=".", runner=_runner([
        ("claude", "for", "yes", [{"path": "/etc/passwd", "start_line": 1, "end_line": 1,
                                   "text": "x", "verified": True}]),
        ("codex", "against", "yes", [_cite()]),
        ("antigravity", "neutral", "yes", [_cite()])]))
    m.assert_invariants(f)   # I12 would fail if the /etc/passwd citation survived
    claude_op = next(op for op in f.validation.panel if op.participant == "claude")
    assert claude_op.citations == []


def test_validate_findings_skips_supply_chain():
    calls = []
    def runner(prompt, *, cwd, mode="consensus", max_cost_usd=None, timeout=600):
        calls.append(prompt)
        return CouncilResult(ok=True, degraded=False, results=[
            PeerResult(name=n, ok=True, label="yes", stance=st, model="m", confidence="high",
                       blockers=[], evidence=[_cite()]) for n, st in
            (("claude", "for"), ("codex", "against"), ("antigravity", "neutral"))])
    dep = _finding(family="supply_chain")
    dep.taxonomy = m.Taxonomy(cwe=["CWE-1395"], cwe_family="supply_chain")
    code = _finding(family="injection")
    panel.validate_findings([dep, code], repo_root=".", runner=runner)
    assert len(calls) == 1                         # only the injection finding validated
    assert dep.validation is None
    assert code.validation is not None


def test_panel_that_never_convened_is_reported_as_a_failure():
    """0.2.0 release rehearsal: with no `llm-council` on PATH, `--validate` left
    every finding needs_human (fail-safe) but reported nothing — the summary
    said "1 cross-examined". The failure must be handed back to the caller."""
    def runner(prompt, *, cwd, mode="consensus", max_cost_usd=None, timeout=600):
        return CouncilResult(ok=False, degraded=True, results=[],
                             error="[not found] [Errno 2] No such file or directory: 'llm-council'")
    f = _finding(family="injection")
    failures: list = []
    panel.validate_findings([f], repo_root=".", runner=runner, failures=failures)
    assert f.validation is not None and f.validation.verdict == "needs_human"
    assert f.validation.panel == []
    assert failures == [{"finding_id": f.id, "error": runner(None, cwd=None).error}]
    # a convened-but-degraded panel (one peer answered) is NOT a failure
    ok_one = _finding(family="injection")
    failures2: list = []
    panel.validate_findings([ok_one], repo_root=".", failures=failures2, runner=_runner([
        ("claude", "for", "yes", [_cite()])]))
    assert ok_one.validation.verdict == "needs_human" and failures2 == []


def test_panel_where_every_peer_failed_is_not_cross_examined():
    """R15: llm-council ran but every peer failed (`ok=False`) — `results` is
    non-empty yet every seat is `absent`. That is not a cross-examination."""
    def runner(prompt, *, cwd, mode="consensus", max_cost_usd=None, timeout=600):
        return CouncilResult(ok=False, degraded=True, results=[
            PeerResult(name=n, ok=False, label=None, stance=st, model=None, confidence=None,
                       blockers=[], evidence=[], error=f"{n} timed out")
            for n, st in (("claude", "for"), ("codex", "against"), ("antigravity", "neutral"))])
    f = _finding(family="injection")
    failures: list = []
    panel.validate_findings([f], repo_root=".", runner=runner, failures=failures)
    assert f.validation.verdict == "needs_human"
    assert not f.validation.convened()
    assert len(f.validation.panel) == 3 and all(op.status == "absent" for op in f.validation.panel)
    assert failures and failures[0]["finding_id"] == f.id and "claude: claude timed out" in failures[0]["error"]
    # one peer answering IS a (degraded) convening
    one = _finding(family="injection")
    panel.validate_findings([one], repo_root=".", runner=_runner([("claude", "for", "yes", [_cite()])]))
    assert one.validation.convened()
