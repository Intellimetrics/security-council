"""calibration.py runtime: trust-boundary loader, scoped application, honesty.

Covers the R7 conditions: fail-closed record validation with logit clamping,
language/source/family scope gating, fitted-base composition under panel terms
(label stays "prior"), the strict-scope "fitted" label, floors over fit, the
adversarial-record bound on the eval gate, and the no-"calibrated"-wording rule
in rendered reports.
"""

import json
import math

import pytest

from security_council import calibration as cal
from security_council import policy, score
from tests.test_cluster import mk
from tests.test_score import _op, _validated

JAVA = "src/main/java/App.java"


def record_dict(*, logit=0.636, detections=154, families=None, languages=("java",),
                sources=("semgrep",), schema=cal.RECORD_SCHEMA):
    fams = families if families is not None else {
        "xss": {"logit": logit, "detections": detections}}
    return {"record": schema, "created_at": "2026-08-24T00:00:00Z",
            "corpus": {"corpus": "owasp-benchmark-java", "version": "1.2"},
            "scanner": {"arm": "semgrep", "family": "semgrep",
                        "tool_version": "1.173.0", "ruleset": "p/default"},
            "scope": {"deterministic_singleton": True,
                      "source_families": list(sources), "languages": list(languages)},
            "families": fams}


def write_record(tmp_path, rec, name="cal.json"):
    p = tmp_path / name
    p.write_text(json.dumps(rec))
    return p


def java_singleton(family="xss", cwe="CWE-79", path=JAVA):
    return mk(path=path, cwe=cwe, family=family, source_id="semgrep",
              source_kind="scanner", vendor="semgrep")


# --- loader: the trust boundary ---

def test_loader_accepts_valid_and_reports_id(tmp_path):
    c, problems = cal.load_record(write_record(tmp_path, record_dict()))
    assert problems == [] and c is not None
    assert c.record_id == "owasp-benchmark-java-1.2@2026-08-24"
    assert c.families == {"xss": 0.636}
    assert c.languages == frozenset({"java"}) and c.source_families == frozenset({"semgrep"})


@pytest.mark.parametrize("mutate,why", [
    (lambda r: r.update(record="something/else"), "schema"),
    (lambda r: r["scope"].update(deterministic_singleton=False), "scope kind"),
    (lambda r: r["scope"].update(source_families=[]), "sources"),
    (lambda r: r["scope"].update(languages=[]), "languages"),
    (lambda r: r.update(families={}), "no families"),
    (lambda r: r.update(families={"xss": {"logit": "high", "detections": 100}}), "bad logit"),
    (lambda r: r.update(families={"xss": {"logit": True, "detections": 100}}), "bool logit"),
])
def test_loader_fails_closed_on_structural_problems(tmp_path, mutate, why):
    rec = record_dict()
    mutate(rec)
    c, problems = cal.load_record(write_record(tmp_path, rec))
    assert c is None and problems, why


def test_loader_clamps_hostile_logits_and_drops_low_n(tmp_path):
    rec = record_dict(families={
        "xss": {"logit": -10.0, "detections": 100},        # hostile: clamped
        "crypto": {"logit": 5.38, "detections": 216},      # real: clamped down
        "injection": {"logit": 0.2, "detections": 5},      # low n: dropped
    })
    c, problems = cal.load_record(write_record(tmp_path, rec))
    assert problems == []
    assert c.families == {"xss": -cal.LOGIT_CLAMP, "crypto": cal.LOGIT_CLAMP}
    assert any("clamped" in w for w in c.warnings)
    assert any("injection" in w and "dropped" in w for w in c.warnings)


def test_loader_unreadable_is_fail_closed(tmp_path):
    c, problems = cal.load_record(tmp_path / "missing.json")
    assert c is None and problems


def test_packaged_record_loads_and_is_clamped():
    c, problems = cal.load_record(cal.PACKAGED_RECORD)
    assert problems == [] and c is not None
    assert set(c.families) == {"crypto", "injection", "path_traversal", "xss"}
    assert c.families["crypto"] == cal.LOGIT_CLAMP           # 5.38 measured, clamped
    assert all(abs(v) <= cal.LOGIT_CLAMP for v in c.families.values())
    assert c.languages == frozenset({"java"})


# --- scope of application ---

def load(tmp_path, rec=None):
    c, problems = cal.load_record(write_record(tmp_path, rec or record_dict()))
    assert problems == []
    return c


def test_base_for_in_scope_java_semgrep_singleton(tmp_path):
    c = load(tmp_path)
    assert c.base_for(java_singleton()) == 0.636


@pytest.mark.parametrize("f_kw,why", [
    (dict(path="app/reports.py"), "non-Java file out of language scope"),
    (dict(family="dos", cwe="CWE-400"), "family not in table"),
    (dict(source_id="gitleaks", vendor="gitleaks"), "arm family not fitted"),
])
def test_base_for_out_of_scope(tmp_path, f_kw, why):
    c = load(tmp_path)
    kw = dict(path=JAVA, cwe="CWE-79", family="xss",
              source_id="semgrep", source_kind="scanner", vendor="semgrep")
    kw.update(f_kw)
    assert c.base_for(mk(**kw)) is None, why


def test_base_for_refuses_agent_corroborated(tmp_path):
    c = load(tmp_path)
    f = java_singleton()
    f.corroboration.agent_sources = ["claude-security"]
    assert c.base_for(f) is None


# --- score integration ---

def test_fitted_base_replaces_prior_and_deterministic(tmp_path):
    c = load(tmp_path)
    s = score.score_finding(java_singleton(), calibration=c)
    assert s.terms == {"fitted_base": 0.636}
    assert "deterministic" not in s.terms
    assert s.log_odds == 0.636                               # no PRIOR added
    assert s.p == round(1 / (1 + math.exp(-0.636)), 4)
    assert s.calibration == "fitted"                         # strict scope
    assert s.calibration_record == c.record_id
    assert s.clamps == []                                    # 0.65 above the floor


def test_floor_binds_over_low_fitted_value(tmp_path):
    c = load(tmp_path, record_dict(families={"path_traversal": {"logit": 0.0, "detections": 116}}))
    f = java_singleton(family="path_traversal", cwe="CWE-22")
    s = score.score_finding(f, calibration=c)
    assert s.terms == {"fitted_base": 0.0}                   # measured p = 0.50
    assert s.p == score.DETERMINISTIC_FLOOR                  # deployed value floored
    assert "deterministic_floor" in s.clamps
    assert s.calibration == "fitted"                         # base is fitted; clamp visible


def test_composed_score_stays_prior_but_records_base(tmp_path):
    c = load(tmp_path)
    f = _validated(java_singleton(), verdict="true_positive",
                   panel=[_op("adjudicator", "true_positive")])
    s = score.score_finding(f, calibration=c)
    assert s.terms["fitted_base"] == 0.636
    assert s.terms["adjudicator"] == score.W_ADJUDICATOR
    assert s.calibration == "prior"                          # composed: no headline claim
    assert s.calibration_record == c.record_id               # but provenance kept


def test_coverage_decline_disqualifies_strict_label(tmp_path):
    c = load(tmp_path)
    f = java_singleton()
    f.corroboration.eligible_sources = ["semgrep", "claude"]  # claude silent
    s = score.score_finding(f, calibration=c)
    assert "coverage_decline" in s.terms and "fitted_base" in s.terms
    assert s.calibration == "prior"


def test_without_record_nothing_changes():
    s = score.score_finding(java_singleton())
    assert s.terms == {"deterministic": score.W_DETERMINISTIC}
    assert s.calibration == "prior" and s.calibration_record is None


def test_policy_rows_carry_calibration_record(tmp_path):
    c = load(tmp_path)
    f = java_singleton()
    decisions = policy.apply_policy([f], {}, now_iso="2026-08-24T00:00:00Z", calibration=c)
    rows = policy.decisions_to_json(decisions)
    assert rows[0]["score"]["calibration"] == "fitted"
    assert rows[0]["score"]["calibration_record"] == c.record_id
    smap = cal.fitted_scores(rows)
    assert smap[f.id]["p"] == rows[0]["p_true"] and smap[f.id]["record"] == c.record_id


# --- resolve(): config -> record, pin enforcement ---

class _ArmRow:
    def __init__(self, name="semgrep", ok=True, tool_version="1.173.0"):
        self.name, self.ok, self.tool_version = name, ok, tool_version


def test_resolve_off_and_invalid(tmp_path):
    assert cal.resolve("off", arm_results=[]) == (None, {"status": "off"})
    assert cal.resolve(None, arm_results=[]) == (None, {"status": "off"})
    c, meta = cal.resolve(str(tmp_path / "nope.json"), arm_results=[_ArmRow()])
    assert c is None and meta["status"] == "invalid"


def test_resolve_explicit_path_applies_and_warns_on_pin_mismatch(tmp_path):
    p = write_record(tmp_path, record_dict())
    c, meta = cal.resolve(str(p), arm_results=[_ArmRow(tool_version="1.999.0")])
    assert c is not None and meta["status"] == "active"
    assert any("pin mismatch" in w for w in meta["warnings"])
    c2, meta2 = cal.resolve(str(p), arm_results=[_ArmRow()])
    assert c2 is not None and meta2["warnings"] == []


def test_resolve_refuses_when_arm_missing(tmp_path):
    p = write_record(tmp_path, record_dict())
    c, meta = cal.resolve(str(p), arm_results=[_ArmRow(ok=False)])
    assert c is None and meta["status"] == "arm_not_run"


def test_resolve_auto_enforces_pins(monkeypatch, tmp_path):
    rec = record_dict()
    rec["scanner"]["tool_version"] = "9.9.9"
    monkeypatch.setattr(cal, "PACKAGED_RECORD", write_record(tmp_path, rec))
    c, meta = cal.resolve("auto", arm_results=[_ArmRow(tool_version="1.173.0")])
    assert c is None and meta["status"] == "refused_pin_mismatch"
    rec["scanner"]["tool_version"] = "1.173.0"
    monkeypatch.setattr(cal, "PACKAGED_RECORD", write_record(tmp_path, rec, "ok.json"))
    c2, meta2 = cal.resolve("auto", arm_results=[_ArmRow(tool_version="1.173.0")])
    assert c2 is not None and meta2["status"] == "active"


# --- the eval-gate bound (R7 Q3): real record inert off-scope, adversarial
# record cannot create violations ---

def _eval_gate(calibration):
    from security_council.eval import runner
    return runner.run_eval("tests/fixtures", calibration=calibration)


def test_eval_gate_with_packaged_record_is_inert_and_green():
    c, problems = cal.load_record(cal.PACKAGED_RECORD)
    assert problems == []
    base = _eval_gate(None)
    fitted = _eval_gate(c)
    assert fitted.report.violations == []
    # language scope: the seed corpus has no .java files -> identical actions
    assert policy.decisions_summary(fitted.decisions) == policy.decisions_summary(base.decisions)


def test_eval_gate_survives_adversarial_record(tmp_path):
    # a hostile record claiming every language and the lowest allowed logits
    fams = {f: {"logit": -cal.LOGIT_CLAMP, "detections": 999}
            for f in ("injection", "xss", "crypto", "path_traversal", "secrets",
                      "supply_chain", "deserialization", "other")}
    rec = record_dict(families=fams, languages=["py", "txt", "tf", "js", "json"])
    c, problems = cal.load_record(write_record(tmp_path, rec))
    assert problems == []
    base = _eval_gate(None)
    hostile = _eval_gate(c)
    assert hostile.report.violations == []                   # zero-tolerance gate holds
    # action-delta: nothing moved toward demote/suppress vs the prior baseline
    assert policy.decisions_summary(hostile.decisions) == policy.decisions_summary(base.decisions)


# --- rendered wording (R7): "fitted", never "calibrated" ---

def test_markdown_renders_fitted_wording_never_calibrated(tmp_path):
    from security_council.export import markdown
    c = load(tmp_path, record_dict(families={
        "xss": {"logit": 0.636, "detections": 154},
        "path_traversal": {"logit": 0.0, "detections": 116}}))
    findings = [java_singleton(),
                java_singleton(family="path_traversal", cwe="CWE-22", path="src/B.java")]
    decisions = policy.apply_policy(findings, {}, now_iso="2026-08-24T00:00:00Z", calibration=c)
    rows = policy.decisions_to_json(decisions)
    manifest = {"run_id": "t", "counts": {"total": 2, "by_severity": {}, "by_state": {}},
                "arms": [], "degradations": [], "reports": [],
                "calibration": {"status": "active", "record": c.record_id,
                                "applied_findings": 2, "warnings": []}}
    md = markdown.to_markdown(findings, manifest, scores=cal.fitted_scores(rows))
    assert "fitted" in md and c.record_id in md
    assert "p 0.65 fitted" in md                             # register cell, post-clamp
    assert "p 0.60 fitted" in md
    assert "measured 0.50; deployed value raised by" in md   # floored, honestly labeled
    assert "calibrat" not in md.lower().replace("calibration.json", "")   # banned word
    refused = dict(manifest, calibration={"status": "refused_pin_mismatch",
                                          "record": "r", "mismatches": ["tool_version"]})
    md2 = markdown.to_markdown(findings, refused)
    assert "Score fitting refused" in md2
