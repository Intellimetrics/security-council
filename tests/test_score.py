"""score.py: log-odds terms, clamps, calibration honesty, attach()."""
import hashlib
import math

from security_council import model as m
from security_council import score
from tests.test_model import valid_finding
from tests.test_validate import _finding


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _sigmoid(x):
    return 1.0 / (1.0 + math.exp(-x))


def _op(role, verdict, *, cites=1, verified=True, pass_rate=1.0, status="ok",
        weight=1.0, model="mdl-x"):
    citations = [m.EvidenceCitation(path="app/reports.py", start_line=9, end_line=9,
                                    claim="c", verified=verified) for _ in range(cites)]
    return m.PanelOpinion(role=role, participant=role[:4], family="claude",
                          prompt_sha256=_sha("p"), verdict=verdict, rationale="r",
                          model_id=model, citations=citations,
                          citation_pass_rate=pass_rate if citations else None,
                          status=status, weight=weight)


def _validated(f, verdict="false_positive", panel=(), **kw):
    f.validation = m.Validation(verdict=verdict, confidence=0.5, panel=list(panel), **kw)
    return f


def test_prior_only_uncorroborated():
    f = _finding(sources=(("house", "agent_cli", "claude"),))
    f.corroboration.independent_family_count = 1
    s = score.score_finding(f)
    assert s.terms == {} and s.clamps == [] and s.needs_human_reasons == []
    assert s.p == round(_sigmoid(score.PRIOR), 4)
    assert s.calibration == "prior"


def test_corroboration_and_deterministic_terms():
    f = _finding()   # semgrep (deterministic) + house, 2 vendor families
    s = score.score_finding(f)
    assert s.terms == {"corroboration": 0.7, "deterministic": 1.2}
    assert s.p == round(_sigmoid(-1.2 + 0.7 + 1.2), 4)
    assert s.clamps == []      # already above the deterministic floor


def test_family_term_is_capped():
    f = _finding()
    f.corroboration.independent_family_count = 5
    s = score.score_finding(f)
    assert s.terms["corroboration"] == score.FAMILY_CAP


def test_adjudicator_term_direction_and_weight():
    f = _validated(_finding(sources=(("house", "agent_cli", "claude"),)),
                   panel=[_op("adjudicator", "true_positive", weight=0.5)])
    f.corroboration.independent_family_count = 1
    up = score.score_finding(f)
    assert up.terms["adjudicator"] == 0.75 and "evidence" not in up.terms
    f.validation.panel = [_op("adjudicator", "false_positive")]
    down = score.score_finding(f)
    assert down.terms["adjudicator"] == -1.5


def test_absent_adjudicator_contributes_nothing():
    f = _validated(_finding(sources=(("house", "agent_cli", "claude"),)),
                   panel=[_op("adjudicator", "true_positive", status="absent")])
    assert "adjudicator" not in score.score_finding(f).terms


def test_reachability_term():
    f = _validated(_finding(sources=(("house", "agent_cli", "claude"),)),
                   reachability=m.Reachability(verdict="unreachable"))
    f.corroboration.independent_family_count = 1
    assert score.score_finding(f).terms["reachability"] == -1.2


def test_evidence_term_prosecutor_up_defender_down_capped():
    f = _validated(_finding(sources=(("house", "agent_cli", "claude"),)),
                   panel=[_op("prosecutor", "true_positive", cites=2),
                          _op("defender", "false_positive", cites=4)])
    f.corroboration.independent_family_count = 1
    s = score.score_finding(f)
    assert abs(s.terms["evidence"] - (0.6 - score.CITATION_CAP)) < 1e-9


def test_unverified_citations_carry_no_evidence_weight():
    f = _validated(_finding(sources=(("house", "agent_cli", "claude"),)),
                   panel=[_op("prosecutor", "true_positive", cites=2, verified=False,
                              pass_rate=0.0, status="unreliable")])
    f.corroboration.independent_family_count = 1
    assert "evidence" not in score.score_finding(f).terms


def test_coverage_decline_eligible_but_silent():
    f = _finding(sources=(("house", "agent_cli", "claude"),))
    f.corroboration.independent_family_count = 1
    f.corroboration.eligible_sources = ["house", "semgrep", "codex-security", "agy", "codex"]
    s = score.score_finding(f)
    assert s.terms["coverage_decline"] == score.SILENT_CAP   # 4 silent, capped


def test_history_term_capped_both_ways():
    f = _finding(sources=(("house", "agent_cli", "claude"),))
    f.corroboration.independent_family_count = 1
    up = score.score_finding(f, history={"confirmed_tp": 5})
    down = score.score_finding(f, history={"confirmed_fp": 5})
    assert up.terms["history"] == score.HISTORY_CAP
    assert down.terms["history"] == -score.HISTORY_CAP


def test_crypto_floor():
    f = valid_finding()          # CWE-916, family crypto, single agent source
    s = score.score_finding(f)
    assert s.p == score.CRYPTO_FLOOR and "crypto_floor" in s.clamps


def test_crypto_floor_via_secondary_cwe():
    f = _finding()               # injection primary...
    f.taxonomy.cwe = ["CWE-89", "CWE-327"]   # ...crypto hidden as secondary
    f.validation = m.Validation(verdict="false_positive", confidence=0.5,
                                panel=[_op("adjudicator", "false_positive"),
                                       _op("defender", "false_positive")])
    s = score.score_finding(f)
    assert s.p >= score.CRYPTO_FLOOR and "crypto_floor" in s.clamps


def test_deterministic_floor_without_verified_defender():
    f = _validated(_finding(), panel=[_op("adjudicator", "false_positive"),
                                      _op("defender", "false_positive", cites=0,
                                          status="unevidenced")])
    s = score.score_finding(f)
    assert s.p == score.DETERMINISTIC_FLOOR and "deterministic_floor" in s.clamps


def test_deterministic_floor_lifted_by_fully_verified_defender():
    f = _validated(_finding(), panel=[_op("adjudicator", "false_positive"),
                                      _op("defender", "false_positive", cites=2)])
    s = score.score_finding(f)
    assert "deterministic_floor" not in s.clamps and s.p < score.DETERMINISTIC_FLOOR


def test_unreliable_opinion_caps_and_flags_human():
    f = _validated(_finding(), panel=[_op("prosecutor", "true_positive", verified=False,
                                          pass_rate=0.5, status="unreliable")])
    s = score.score_finding(f)   # deterministic+corroboration would score 0.668
    assert s.p == score.UNRELIABLE_CAP and "unreliable_cap" in s.clamps
    assert "unreliable_panel_opinion" in s.needs_human_reasons


def test_no_navigation_and_uncovered_flag_human():
    f = _validated(_finding(), no_cross_file_navigation=True)
    f.corroboration.uncovered = True
    s = score.score_finding(f)
    assert "no_cross_file_navigation" in s.needs_human_reasons
    assert "category_uncovered" in s.needs_human_reasons


def test_attach_persists_score_and_calibration():
    f = _validated(_finding(), panel=[_op("adjudicator", "false_positive")])
    s = score.score_finding(f)
    score.attach(f, s)
    assert f.validation.confidence == round(s.p, 3)
    assert f.validation.calibration == "prior"     # never "fitted" in v1
    blob = f.validation.evidence_check["score"]
    assert blob["terms"] == s.terms and blob["log_odds"] == s.log_odds


def test_attach_noop_without_validation():
    f = _finding()
    score.attach(f, score.score_finding(f))   # must not raise or invent validation
    assert f.validation is None
