"""M-V4b verify-fix: machine evidence bound to a patch that can NEVER close a
finding (L1: not counted by history; L3: not a panel vote / no auto-close)."""
import hashlib

from security_council import decisions as dec
from security_council.arms import verify_fix as vf
from security_council.arms.verify_fix import VerifyFixArm


def _rc(seed="v"):
    return "rootCause/v1:" + hashlib.sha256(seed.encode()).hexdigest()[:32]


def _finding_row(rc):
    return {"id": "f" + hashlib.sha256(rc.encode()).hexdigest()[:12],
            "taxonomy": {"cwe": ["CWE-89"], "cwe_family": "injection"},
            "locations": [{"uri": "app/x.py", "start_line": 1}],
            "fingerprints": {"root_cause": rc}}


# --------------------------------------------------------------------------- #
# L1: verify evidence never feeds the score history term (anti-poisoning)
# --------------------------------------------------------------------------- #


def test_verify_evidence_recorded_but_not_counted_as_history(tmp_path):
    store = dec.DecisionStore(tmp_path)
    rc = _rc()
    store.record_verify_evidence(root_cause=rc, finding_id="f1", verdict="fixed",
                                 patch_sha256="abc123", base_commit="c0", producer="codex-verify-fix",
                                 now_iso="2026-08-23T00:00:00Z")
    assert store.verify_evidence(rc)[0]["verdict"] == "fixed"
    # it is machine evidence — history_counts (human outcome marks only) ignores it
    assert store.history_counts() == {}


def test_forged_machine_outcome_mark_is_not_counted(tmp_path):
    """Even a hand-forged event with kind=outcome_mark + operator is ignored if
    decided_by=machine (L1 belt-and-braces)."""
    store = dec.DecisionStore(tmp_path)
    rc = _rc("forge")
    rec = {"schema_version": 1, "root_cause": rc, "finding_id": "f", "context_hash": "",
           "history": [{"at": "t", "kind": "outcome_mark", "verdict": "false_positive",
                        "operator": "not-a-human", "decided_by": "machine"}]}
    dec._atomic_write(store._path(rc), rec)
    assert store.history_counts() == {}          # machine event rejected
    # a real human mark IS counted
    store.mark_outcome(root_cause=rc, finding_id="f", verdict="false_positive",
                       operator="clindell", now_iso="t2")
    assert store.history_counts()[rc]["confirmed_fp"] == 1


def test_bad_verdict_rejected(tmp_path):
    store = dec.DecisionStore(tmp_path)
    try:
        store.record_verify_evidence(root_cause=_rc(), finding_id="f", verdict="green",
                                     patch_sha256="x", base_commit=None, producer="p", now_iso="t")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


# --------------------------------------------------------------------------- #
# the arm: applies the patch itself, fails closed, binds the verdict to the sha
# --------------------------------------------------------------------------- #


class _R:
    def __init__(self, ok=True, out="", rc=0):
        self.ok, self.stdout, self.stderr = ok, out, ""
        self.exit_code, self.elapsed_seconds, self.timed_out = rc, 1.0, False


def _seed(tmp_path):
    t = tmp_path / "repo"
    (t / "app").mkdir(parents=True)
    (t / "app" / "x.py").write_text("q = bad\n")
    return t


def test_verify_fails_closed_without_fence(tmp_path, monkeypatch):
    monkeypatch.setattr(vf.proc, "run_command", lambda cmd, **kw: _R(ok=True))  # apply "works"
    monkeypatch.setattr(vf.VerifyFixArm, "_apply_patch", lambda self, work: True)
    monkeypatch.setattr(vf._fence, "certify", lambda **kw: (None, {"refused": "no bwrap"}))
    arm = VerifyFixArm(finding=_finding_row(_rc()), patch_path="/x.patch", patch_sha256="s")
    res = arm.run(_seed(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    assert not res.ok and res.artifacts[0]["verdict"] == "unproven"
    assert "fence_unverified" in res.artifacts[0]["note"]


def test_verify_unproven_when_patch_wont_apply(tmp_path, monkeypatch):
    monkeypatch.setattr(vf.VerifyFixArm, "_apply_patch", lambda self, work: False)
    arm = VerifyFixArm(finding=_finding_row(_rc()), patch_path="/x.patch", patch_sha256="s")
    res = arm.run(_seed(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok and res.artifacts[0]["verdict"] == "unproven"
    assert "did not apply" in res.artifacts[0]["note"]


def _fake_cert(monkeypatch):
    from security_council import fence
    cert = fence.FenceCertificate(config_hash="h", bwrap_version="bwrap 0.11.0", host="t",
                                  minted_at=9e18)
    monkeypatch.setattr(vf._fence, "certify",
                        lambda **kw: (cert, {"bwrap": "x", "breaches": [], "canary_done": True}))


def test_verify_parses_verdict_and_binds_patch_sha(tmp_path, monkeypatch):
    _fake_cert(monkeypatch)
    monkeypatch.setattr(vf.VerifyFixArm, "_apply_patch", lambda self, work: True)
    monkeypatch.setattr(vf.proc, "run_command",
                        lambda cmd, **kw: _R(out="Assessment: the finding is now fixed."))
    arm = VerifyFixArm(finding=_finding_row(_rc()), patch_path="/x.patch",
                       patch_sha256="deadbeef", base_commit="c1")
    res = arm.run(_seed(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    ev = res.artifacts[0]
    assert ev["verdict"] == "fixed" and ev["patch_sha256"] == "deadbeef"
    assert ev["base_commit"] == "c1" and ev["non_closing"] is True and ev["kind"] == "verify-fix"


def test_verdict_parser():
    assert vf._parse_verdict("the code is not fixed", "") == "not_fixed"
    assert vf._parse_verdict("remediated correctly", "") == "fixed"
    assert vf._parse_verdict("could not determine", "") == "unproven"


# --------------------------------------------------------------------------- #
# L3 + end-to-end: verify NEVER changes disposition; renders as human-review
# --------------------------------------------------------------------------- #


def test_scan_verify_flow_leaves_disposition_untouched(tmp_path, monkeypatch):
    from security_council import proc as realproc
    from security_council.orchestrator import run_scan
    from tests.test_entitlements import _cfg
    from tests.test_fix_lane import _fake_cert as fix_fake_cert
    from tests.test_orchestrator import FakeArm, _finding as orch_finding
    fix_fake_cert(monkeypatch)
    _fake_cert(monkeypatch)

    real = realproc.run_command   # fixmod.proc and vf.proc are the SAME module

    def fenced_fake(cmd, **kw):
        from pathlib import Path
        if "bwrap" not in cmd[0]:
            return real(cmd, **kw)               # real git init/diff/git_info
        if any("verify" in str(a) for a in cmd):
            return _R(out="fixed")               # the fenced verify agent
        p = Path(kw["cwd"]) / "app" / "x.py"      # the fenced fix agent edits the work copy
        if p.exists():
            p.write_text("q = db.execute('...', [x])\n")
        return _R()
    monkeypatch.setattr(realproc, "run_command", fenced_fake)
    monkeypatch.setattr(vf.VerifyFixArm, "_apply_patch", lambda self, work: True)

    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 'SELECT '+x\n")
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="vf")])]
    run = run_scan(target, arms, _cfg(), out_dir=tmp_path / "out",
                   fix_spec={"jobs": ["suggest-patches"], "finding_ids": None, "verify": True})
    # a verify-fix evidence artifact exists...
    kinds = {a["kind"] for a in run.manifest["artifacts"]}
    assert "verify-fix" in kinds and "fix" in kinds
    # ...but the finding is still open (evidence never auto-closes — L3/D7)
    f = run.findings[0]
    assert f.disposition.lifecycle == "open" and f.disposition.state != "refuted"
    # ...and it never became a panel vote
    assert f.validation is None or all(op.role != "verifier" for op in f.validation.panel)
    # ...and the summary presents it as human-review evidence, not a green check
    md = (run.out_dir / "summary.md").read_text()
    assert "requires human review" in md
