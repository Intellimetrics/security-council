"""policy.py: guardrails G1-G8 — demote-never-close, double-gated suppression,
shadow mode, escalation, attribution (I6) on every mutated finding."""
import hashlib
import json

from security_council import model as m
from security_council import policy, score
from security_council.arms.base import ArmResult
from security_council.orchestrator import _exit_code
from tests.test_orchestrator import FakeArm, _run as orch_run
from tests.test_validate import _finding

NOW = "2026-08-22T00:00:00Z"


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


# one family per seat, as a real panel has: `synthesize_validation` cannot
# return `false_positive` without >= 2 DISTINCT vendor families, so a
# single-family refuting panel is a state the pipeline never produces
_FAMILY_BY_ROLE = {"prosecutor": "claude", "defender": "codex", "adjudicator": "google"}


def _op(role, verdict, *, cites=1, verified=True, pass_rate=1.0, status="ok", model="mdl-x",
        family=None):
    citations = [m.EvidenceCitation(path="app/reports.py", start_line=9, end_line=9,
                                    claim="c", verified=verified) for _ in range(cites)]
    return m.PanelOpinion(role=role, participant=role[:4],
                          family=family or _FAMILY_BY_ROLE.get(role, "claude"),
                          prompt_sha256=_sha("p"), verdict=verdict, rationale="r",
                          model_id=model, citations=citations,
                          citation_pass_rate=pass_rate if citations else None, status=status)


def _refuted(*, agent_only=True, sev="high", panel=None):
    """A panel-refuted finding whose score lands below the suppress threshold."""
    sources = ((("house", "agent_cli", "claude"), ("codex", "agent_cli", "codex"))
               if agent_only else None)
    f = _finding(sev=sev, **({"sources": sources} if sources else {}))
    f.validation = m.Validation(
        verdict="false_positive", confidence=0.9,
        panel=panel if panel is not None else [
            _op("prosecutor", "false_positive"),
            _op("defender", "false_positive", cites=2),
            _op("adjudicator", "false_positive")])
    f.disposition.state = "refuted"
    return f


def _cfg(**over):
    return {"policy": {**policy.POLICY_DEFAULTS, **over}}


def _armed(**over):
    return _cfg(auto_suppress=True, accept_suppression_risk=True, **over)


# --------------------------------------------------------------------------- #
# default posture: demote, never suppress
# --------------------------------------------------------------------------- #


def test_default_config_demotes_never_suppresses():
    f = _refuted()
    [d] = policy.apply_policy([f], _cfg(), now_iso=NOW, prior_runs=99)
    assert d.action == "demote" and "auto_suppress_disabled" in d.guardrails_failed
    assert f.disposition.lifecycle == "open" and f.disposition.sarif_suppression is None
    assert f.disposition.state == "refuted"
    db = f.disposition.decided_by
    assert db.kind == "auto" and db.decided_at == NOW and db.model_id == "mdl-x"
    assert db.panel_sha256 and len(db.panel_sha256) == 64
    m.assert_invariants(f)


def test_unacknowledged_risk_blocks_suppression():
    f = _refuted()
    [d] = policy.apply_policy([f], _cfg(auto_suppress=True), now_iso=NOW, prior_runs=99)
    assert d.action == "demote"
    assert "suppression_risk_not_acknowledged" in d.guardrails_failed
    assert f.disposition.lifecycle == "open"


# --------------------------------------------------------------------------- #
# the armed path: shadow first, then real suppression with full attribution
# --------------------------------------------------------------------------- #


def test_shadow_mode_records_but_stays_open():
    f = _refuted()
    [d] = policy.apply_policy([f], _armed(), now_iso=NOW, prior_runs=2)   # 2 < 5
    assert d.action == "shadow_suppress" and d.guardrails_failed == []
    assert f.disposition.lifecycle == "open" and f.disposition.shadow is True
    assert f.disposition.sarif_suppression is None
    assert "shadow_run_3_of_5" in d.reasons
    m.assert_invariants(f)


def test_suppression_when_all_gates_pass():
    f = _refuted()
    [d] = policy.apply_policy([f], _armed(), now_iso=NOW, prior_runs=5)
    assert d.action == "suppress" and d.guardrails_failed == []
    dd = f.disposition
    assert dd.lifecycle == "suppressed"
    assert dd.sarif_suppression["status"] == "accepted"
    assert dd.decision_ref == f"decision:root_cause:{f.fingerprints.root_cause}"   # G5
    assert dd.expires_at == "2026-11-20T00:00:00Z"                                 # G6 +90d
    assert dd.vex_status == "not_affected"
    assert dd.vex_justification in m.OPENVEX_JUSTIFICATIONS
    m.assert_invariants(f)          # I6: attribution is complete, structurally


def test_suppression_vex_justification_tracks_reachability():
    f = _refuted()
    f.validation.reachability = m.Reachability(verdict="unreachable")
    policy.apply_policy([f], _armed(), now_iso=NOW, prior_runs=5)
    assert f.disposition.vex_justification == "vulnerable_code_not_in_execute_path"


def test_p_above_threshold_blocks_suppression():
    f = _refuted()
    [d] = policy.apply_policy([f], _armed(suppress_below=0.01), now_iso=NOW, prior_runs=99)
    assert d.action == "demote" and "p_above_suppress_threshold" in d.guardrails_failed
    assert f.disposition.lifecycle == "open"


# --------------------------------------------------------------------------- #
# guardrails G1/G7: crypto and critical are never auto-suppressed
# --------------------------------------------------------------------------- #


def test_G1_crypto_never_suppressed_even_with_absurd_threshold():
    f = _refuted()
    # (a crypto CWE with a non-crypto family is unrepresentable — I4 crypto-sticky —
    # so the guardrail only ever needs to key on the family/CWE set of a valid finding)
    f.taxonomy.cwe = ["CWE-327"]
    f.taxonomy.cwe_family = "crypto"
    [d] = policy.apply_policy([f], _armed(suppress_below=0.99), now_iso=NOW, prior_runs=99)
    assert d.action == "demote"
    assert "G1_crypto_never_auto_suppressed" in d.guardrails_failed
    assert f.disposition.lifecycle == "open"
    assert d.p >= score.CRYPTO_FLOOR          # the score floor backs the guardrail
    m.assert_invariants(f)


def test_G7_critical_never_suppressed():
    f = _refuted(sev="critical")
    [d] = policy.apply_policy([f], _armed(suppress_below=0.99), now_iso=NOW, prior_runs=99)
    assert d.action == "demote"
    assert "G7_critical_never_auto_suppressed" in d.guardrails_failed
    assert f.disposition.lifecycle == "open"


# --------------------------------------------------------------------------- #
# G2: an LLM panel alone cannot refute a deterministic finding
# --------------------------------------------------------------------------- #


def test_G2_unsupported_deterministic_refutation_escalates():
    f = _refuted(agent_only=False, panel=[
        _op("prosecutor", "false_positive"),
        _op("defender", "false_positive", cites=0, status="unevidenced"),
        _op("adjudicator", "false_positive")])
    [d] = policy.apply_policy([f], _armed(), now_iso=NOW, prior_runs=99)
    assert d.action == "escalate_human"
    assert "G2_deterministic_refutation_unsupported" in d.reasons
    assert f.disposition.state == "needs_human" and f.disposition.lifecycle == "open"
    m.assert_invariants(f)


def test_G2_satisfied_by_fully_verified_defender():
    f = _refuted(agent_only=False)    # default panel has a fully-verified defender
    [d] = policy.apply_policy([f], _cfg(), now_iso=NOW)
    assert d.action == "demote" and f.disposition.state == "refuted"


def test_escalated_finding_still_gates_the_build():
    f = _refuted(agent_only=False, panel=[
        _op("prosecutor", "false_positive"),
        _op("defender", "false_positive", cites=0, status="unevidenced"),
        _op("adjudicator", "false_positive")])
    policy.apply_policy([f], _cfg(), now_iso=NOW)
    ok_arm = ArmResult(name="a", kind="scanner", family="x", ok=True, exit_code=0,
                       error="", findings=[])
    code, _ = _exit_code([f], [ok_arm], _cfg())
    assert code == 1          # needs_human at high severity is unresolved -> gate


# --------------------------------------------------------------------------- #
# escalation on score flags; states that policy leaves alone
# --------------------------------------------------------------------------- #


def test_unreliable_panel_escalates_any_state():
    f = _refuted(panel=[_op("prosecutor", "false_positive", verified=False, pass_rate=0.5,
                            status="unreliable"),
                        _op("adjudicator", "false_positive")])
    [d] = policy.apply_policy([f], _armed(), now_iso=NOW, prior_runs=99)
    assert d.action == "escalate_human" and "unreliable_panel_opinion" in d.reasons
    assert f.disposition.state == "needs_human"


def test_validated_finding_gets_score_but_no_action():
    f = _refuted()
    f.disposition.state = "validated"
    f.validation.verdict = "true_positive"
    [d] = policy.apply_policy([f], _armed(), now_iso=NOW, prior_runs=99)
    assert d.action == "none" and d.reasons == ["state_validated"]
    assert f.validation.evidence_check["score"]["log_odds"] == d.score.log_odds
    assert f.disposition.lifecycle == "open"


def test_unvalidated_finding_untouched():
    f = _finding()
    [d] = policy.apply_policy([f], _armed(), now_iso=NOW, prior_runs=99)
    assert d.action == "none" and d.reasons == ["not_validated"]
    assert f.disposition.state == "new" and f.validation is None


def test_suppressed_finding_stops_gating():
    f = _refuted()
    policy.apply_policy([f], _armed(), now_iso=NOW, prior_runs=5)
    assert f.disposition.lifecycle == "suppressed"
    ok_arm = ArmResult(name="a", kind="scanner", family="x", ok=True, exit_code=0,
                       error="", findings=[])
    code, _ = _exit_code([f], [ok_arm], _cfg())
    assert code == 0


# --------------------------------------------------------------------------- #
# history plumbing, run counting, serialization, orchestrator wiring
# --------------------------------------------------------------------------- #


def test_history_reaches_score_by_root_cause():
    f = _refuted()
    hist = {f.fingerprints.root_cause: {"confirmed_fp": 3}}
    [d] = policy.apply_policy([f], _cfg(), now_iso=NOW, history=hist)
    assert d.score.terms["history"] == -score.HISTORY_CAP


def test_count_prior_runs_is_strict(tmp_path):
    for name, manifest in (("20260820_120000", True), ("20260821_130516", True),
                           ("20260822_000000", True),    # the current run
                           ("not-a-run", True), ("20260819_999999", False)):
        d = tmp_path / name
        d.mkdir()
        if manifest:
            (d / "manifest.json").write_text("{}")
    (tmp_path / "stray.txt").write_text("x")
    assert policy.count_prior_runs(tmp_path, "20260822_000000") == 2
    assert policy.count_prior_runs(tmp_path / "missing", "x") == 0


def test_decisions_summary_and_json_roundtrip():
    f1, f2 = _refuted(), _finding()
    ds = policy.apply_policy([f1, f2], _cfg(), now_iso=NOW)
    assert policy.decisions_summary(ds) == {"demote": 1, "none": 1}
    rows = policy.decisions_to_json(ds)
    json.dumps(rows)          # serializable as-is
    assert rows[0]["action"] == "demote" and rows[0]["score"]["calibration"] == "prior"


def test_scan_writes_policy_json_and_manifest_actions(tmp_path):
    from tests.test_orchestrator import _finding as orch_finding
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep")])]
    run = orch_run(arms, tmp_path)
    pj = json.loads((run.out_dir / "policy.json").read_text())
    assert pj[0]["action"] == "none" and pj[0]["reasons"] == ["not_validated"]
    assert run.manifest["disposition_actions"] == {"none": 1}
    assert any(r["path"].endswith("policy.json") for r in run.manifest["reports"])


def test_G11_high_assurance_refutation_needs_a_real_panel():
    """R12 round 8: `demote` removes a finding from the build just as suppression
    does, but G1/G7 only cover suppression and G9 only covers baselines — so a
    crypto/critical `refuted` state with NO panel behind it left the gate and the
    scan exited 0. Not reachable via synthesize_validation (an empty panel yields
    needs_human), so this guards the non-panel paths: a hand-written decision
    record, a replayed validation, a future producer setting state directly."""
    f = _refuted(sev="critical", panel=[])          # state refuted, nothing behind it
    [d] = policy.apply_policy([f], _armed(), now_iso=NOW, prior_runs=99)
    assert d.action == "escalate_human"
    assert "G11_high_assurance_refutation_not_panel_backed" in d.reasons
    assert f.disposition.state == "needs_human"     # gates
    m.assert_invariants(f)


def test_G11_does_not_block_a_properly_backed_crypto_demotion():
    """Deliberately not a blanket ban: the eval corpus's MD5-cache decoy is a
    crypto FALSE POSITIVE, and demoting it on anchored cross-family agreement is
    what this tool is for."""
    f = _refuted(sev="high")
    f.taxonomy.cwe = ["CWE-327"]            # keep I4 consistent with the family
    f.taxonomy.cwe_family = "crypto"
    [d] = policy.apply_policy([f], _armed(suppress_below=0.99), now_iso=NOW, prior_runs=99)
    assert d.action == "demote"
    assert f.disposition.state == "refuted"
