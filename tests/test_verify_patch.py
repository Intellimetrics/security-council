"""Deterministic verify-fix (R11 Q4): apply the patch to a scratch copy, re-run
the scanners that reported the finding, require it to DISAPPEAR under verified
coverage. Machine evidence only — never a disposition, never history (L1),
never a panel vote (L3). Offline: the scanners are content-sensitive fakes."""
import difflib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from security_council import decisions as dec, model as m, verify_patch as vp
from security_council.arms.base import ArmResult
from security_council.config import DEFAULT_CONFIG
from security_council.orchestrator import run_scan
from tests.test_orchestrator import FakeArm, _finding as orch_finding

RC_MAIN, RC_OTHER, RC_MOVED = "vp-main", "vp-other", "vp-moved"


class ContentArm:
    """A deterministic-scanner stand-in whose findings depend on the TREE it is
    handed: a rule (uri, needle) fires when that file contains the needle. That
    is what makes "re-run it on the patched copy" mean something offline."""
    kind = "scanner"

    def __init__(self, name="semgrep", family="semgrep", rules=(), coverage=None,
                 unavailable_after=None):
        self.name, self.family = name, family
        self.rules = list(rules)          # (uri, needle, rc_seed, rule_id, severity)
        self._cov = dict(coverage or {})
        self.unavailable_after = unavailable_after
        self.calls = 0
        self.roots: list[Path] = []

    def available(self):
        self.calls += 1
        if self.unavailable_after is not None and self.calls > self.unavailable_after:
            return False, "docker went away"
        return True, "fake"

    def run(self, target, out_dir, *, run_id, collected_at):
        self.roots.append(Path(target))
        found = []
        for uri, needle, seed, rule_id, sev in self.rules:
            p = Path(target) / uri
            if p.is_file() and needle in p.read_text():
                f = orch_finding(source_id=self.name, kind="scanner", vendor=self.family,
                                 rc=seed, sev=sev)
                f = replace(f, rule=m.RuleRef(id=rule_id, source=self.name, source_rule_id=rule_id),
                            locations=[replace(f.locations[0], uri=uri)])
                found.append(f)
        return ArmResult(name=self.name, kind="scanner", family=self.family, ok=True,
                         exit_code=0, error="", findings=found, tool_version="9.9",
                         coverage={"raw_results": len(found), "normalized": len(found),
                                   **self._cov})


def _cfg():
    cfg = {**DEFAULT_CONFIG}
    cfg["policy"] = {**DEFAULT_CONFIG["policy"]}
    cfg["decisions"] = {**DEFAULT_CONFIG["decisions"], "require_signatures": "warn"}
    return cfg


def _seed(tmp_path):
    """The target: seeded once per test (idempotent, so a patch helper may
    seed first and the run helper may seed again without clobbering)."""
    t = tmp_path / "repo"
    if t.is_dir():
        return t
    (t / "app").mkdir(parents=True)
    (t / "app" / "x.py").write_text("import db\nq = bad(x)\nprint(q)\n")
    (t / "app" / "y.py").write_text("z = other(y)\n")
    (t / "README.md").write_text("# demo\n")
    return t


def _patch(tmp_path, name, uri, old, new):
    """A -p1 patch replacing the line `old` with `new` in the seeded repo's
    `uri`, shaped like `git diff` output (context lines included — git apply
    rejects a context-free hunk in the middle of a file)."""
    src = _seed(tmp_path) / uri
    before = src.read_text().splitlines(keepends=True) if src.is_file() else [old + "\n"]
    after = [(new + "\n") if ln.rstrip("\n") == old else ln for ln in before]
    body = "".join(difflib.unified_diff(before, after, fromfile=f"a/{uri}", tofile=f"b/{uri}"))
    p = tmp_path / name
    p.write_text(f"diff --git a/{uri} b/{uri}\n{body}")
    return p


def _arm(**kw):
    rules = kw.pop("rules", None) or [("app/x.py", "bad(", RC_MAIN, "py.injection", "high")]
    return ContentArm(rules=rules, **kw)


def _main_id():
    return orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc=RC_MAIN).id


def _run(tmp_path, arms, patch, ids=None, **kw):
    target = kw.pop("target", None) or _seed(tmp_path)
    return run_scan(target, arms, _cfg(), out_dir=tmp_path / "out",
                    verify_patch={"patch": str(patch), "finding_ids": ids}, **kw)


def _results(run):
    return run.manifest["verify_fix"]["patches"][0]["results"]


# --------------------------------------------------------------------------- #
# the three verdicts
# --------------------------------------------------------------------------- #

def test_fixed_when_the_finding_disappears_under_verified_coverage(tmp_path):
    arm = _arm()
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    run = _run(tmp_path, [arm], patch)
    block = run.manifest["verify_fix"]
    assert block["method"] == "deterministic"
    pv = block["patches"][0]
    assert pv["applied"] is True and pv["patch_sha256"] == vp.sha256_of(patch)
    assert pv["files"] == ["app/x.py"]
    (res,) = pv["results"]
    assert res["verdict"] == "fixed" and res["finding_id"] == _main_id()
    (src,) = res["sources"]
    assert src["arm"] == "semgrep" and src["coverage"] == "verified" and src["present"] is False
    # the arm really ran a second time, on a DIFFERENT tree than the scan's copy...
    assert len(arm.roots) == 2 and arm.roots[0] != arm.roots[1]
    # ...and the user's tree was never touched
    assert (tmp_path / "repo" / "app" / "x.py").read_text().startswith("import db\nq = bad(x)")
    # evidence artifact, machine-labelled, independent of any patch producer
    (art,) = [a for a in run.manifest["artifacts"] if a["kind"] == "verify-fix"]
    assert art["method"] == "deterministic" and art["verdict"] == "fixed"
    assert art["decided_by"] == "machine" and art["non_closing"] is True
    assert art["patch_sha256"] == pv["patch_sha256"] and "semgrep 9.9" in art["checked_by"]
    assert art["model_id"] is None


def test_not_fixed_when_the_scanner_still_reports_it(tmp_path):
    patch = _patch(tmp_path, "noop.patch", "README.md", "# demo", "# demo, edited")
    run = _run(tmp_path, [_arm()], patch, ids=[_main_id()])
    (res,) = _results(run)
    assert res["verdict"] == "not_fixed"
    assert res["sources"][0]["present"] is True and res["sources"][0]["match_tier"] == "root_cause"
    assert "still reports it" in res["reasons"][0]


def test_not_fixed_when_the_sink_merely_moves(tmp_path):
    """A 'fix' that rewrites the sink so every fingerprint changes, while the
    same rule fires again in the same file, is not a fix. The finding as
    fingerprinted is gone, but the patched copy carries a NEW same-rule finding
    that the original run never had."""
    rules = [("app/x.py", "bad(", RC_MAIN, "py.injection", "high"),
             ("app/x.py", "bad2(", RC_MOVED, "py.injection", "high")]
    patch = _patch(tmp_path, "move.patch", "app/x.py", "q = bad(x)", "q = bad2(x)")
    run = _run(tmp_path, [_arm(rules=rules)], patch)
    pv = run.manifest["verify_fix"]["patches"][0]
    (res,) = pv["results"]
    assert res["verdict"] == "not_fixed"
    assert res["sources"][0]["present"] is False and res["sources"][0]["moved_to"]
    assert "sink moved" in res["reasons"][0]
    assert pv["new_findings"] == 1


def test_unproven_when_coverage_of_the_patched_copy_is_not_verified(tmp_path):
    """R12 coverage model: an absence is only evidence from a scan that vouches
    for what it examined. Partial (or none) coverage can never yield `fixed`."""
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    for cov in ({"completion": "partial"}, {"ignore_files": [".semgrepignore"]},
                {"coverage_unverified": True}):
        run = _run(tmp_path, [_arm(coverage=cov)], patch, ids=[_main_id()])
        (res,) = _results(run)
        assert res["verdict"] == "unproven", cov
        assert res["sources"][0]["present"] is False       # it WAS absent...
        assert res["sources"][0]["coverage"] != "verified"  # ...but nobody can vouch
        assert any(d["kind"] in ("verify_patch_coverage", "verify_patch_arm_failed")
                   for d in run.degradations)


def test_unproven_when_the_arm_is_unavailable_for_the_patched_copy(tmp_path):
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    run = _run(tmp_path, [_arm(unavailable_after=1)], patch, ids=[_main_id()])
    (res,) = _results(run)
    assert res["verdict"] == "unproven"
    assert "failed on the patched copy" in res["reasons"][0]
    assert any(d["kind"] == "verify_patch_arm_failed" for d in run.degradations)


def test_unproven_when_no_deterministic_source_reported_it(tmp_path):
    """An agent-only finding (the cross-file IDOR shape) has no scanner that
    can vouch for its absence; a human has to look."""
    agent = orch_finding(source_id="house", kind="agent_cli", vendor="claude", rc="idor")
    # its own file, or the T2 location tier of the clusterer folds it into the
    # semgrep finding at app/x.py:1
    agent = replace(agent, locations=[replace(agent.locations[0], uri="app/y.py")])
    arms = [_arm(), FakeArm("house", "agent_cli", "claude", [agent],
                            coverage={"completion": "complete"})]
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    run = _run(tmp_path, arms, patch, ids=[agent.id])
    (res,) = _results(run)
    assert res["verdict"] == "unproven" and res["sources"] == []
    assert "no deterministic scanner" in res["reasons"][0]


def test_unproven_when_the_patch_does_not_apply(tmp_path):
    patch = _patch(tmp_path, "stale.patch", "app/x.py", "q = something_else(x)", "q = safe(x)")
    run = _run(tmp_path, [_arm()], patch, ids=[_main_id()])
    pv = run.manifest["verify_fix"]["patches"][0]
    assert pv["applied"] is False and pv["apply_error"]
    (res,) = pv["results"]
    assert res["verdict"] == "unproven" and "did not apply" in res["reasons"][0]
    assert any(d["kind"] == "verify_patch_not_applied" for d in run.degradations)
    assert pv["arms"] == []                                   # nothing was re-run


def test_refused_patch_is_never_applied(tmp_path):
    patch = tmp_path / "ci.patch"
    patch.write_text("diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n"
                     "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n"
                     "@@ -1 +1 @@\n-a\n+b\n")
    run = _run(tmp_path, [_arm()], patch, ids=[_main_id()])
    pv = run.manifest["verify_fix"]["patches"][0]
    assert pv["refused"] and pv["applied"] is False
    assert pv["results"][0]["verdict"] == "unproven"


# --------------------------------------------------------------------------- #
# the boundaries: evidence, not decision (L1 / L3 / D7)
# --------------------------------------------------------------------------- #

def test_verdict_never_changes_disposition_gate_or_panel(tmp_path):
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    run = _run(tmp_path, [_arm()], patch)
    assert _results(run)[0]["verdict"] == "fixed"
    (f,) = run.findings
    # the finding in THIS run is still detected in the unpatched tree: open, gating
    assert f.disposition.lifecycle == "open" and f.disposition.state == "new"
    assert f.baseline_state != "absent" and f.validation is None
    assert run.exit_code == 1
    # and a second scan of the (still unpatched) tree is not influenced either
    again = run_scan(tmp_path / "repo", [_arm()], _cfg(), out_dir=tmp_path / "out2")
    assert again.findings[0].disposition.lifecycle == "open" and again.exit_code == 1


def test_evidence_is_recorded_as_machine_kind_and_ignored_by_history(tmp_path):
    """L1: `history_counts` feeds the score prior from HUMAN outcome marks only.
    The deterministic verdict is stored, bound to the patch, and never counts."""
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    run = _run(tmp_path, [_arm()], patch)
    store = dec.DecisionStore(tmp_path / "repo" / ".security-council")
    rc = run.findings[0].fingerprints.root_cause
    (ev,) = store.verify_evidence(rc)
    assert ev["kind"] == "deterministic_verify_fix" and ev["decided_by"] == "machine"
    assert ev["verdict"] == "fixed" and ev["patch_sha256"] == vp.sha256_of(patch)
    assert ev["producer"] == "semgrep 9.9" and ev["model"] is None
    assert ev["detail"]["sources"][0]["coverage"] == "verified"
    assert store.history_counts() == {}
    assert store.history_counts(signature_policy="enforce") == {}
    # belt and braces: a forged copy carrying an operator and a TP verdict
    rec = store.load(rc)
    rec["history"].append({**ev, "operator": "someone", "verdict": "true_positive"})
    dec._atomic_write(store._path(rc), rec)
    assert store.history_counts() == {}
    # and the record carries no decision — a later scan reapplies nothing
    assert "suppression" not in rec
    assert store.apply_prior_decisions(run.findings, now_iso="2026-08-26T00:00:00Z") == []


def test_record_verify_evidence_rejects_unknown_kind(tmp_path):
    store = dec.DecisionStore(tmp_path)
    with pytest.raises(ValueError, match="kind"):
        store.record_verify_evidence(root_cause="rootCause/v1:" + "0" * 32, finding_id="f",
                                     verdict="fixed", patch_sha256="x", base_commit=None,
                                     producer="p", now_iso="t", kind="human_verify_fix")


# --------------------------------------------------------------------------- #
# selection, summary, CLI
# --------------------------------------------------------------------------- #

def test_default_selection_is_the_files_the_patch_touches(tmp_path):
    rules = [("app/x.py", "bad(", RC_MAIN, "py.injection", "high"),
             ("app/y.py", "other(", RC_OTHER, "py.other", "medium")]
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    run = _run(tmp_path, [_arm(rules=rules)], patch)
    res = _results(run)
    assert [r["uri"] for r in res] == ["app/x.py"] and res[0]["verdict"] == "fixed"
    # an explicit id outside the patch's files is checked anyway (and is not fixed)
    other_id = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep",
                            rc=RC_OTHER, sev="medium").id
    run2 = _run(tmp_path, [_arm(rules=rules)], patch, ids=[other_id[:8], "ffffffffff"])
    res2 = _results(run2)
    assert [r["verdict"] for r in res2] == ["not_fixed"]
    assert any(d["kind"] == "verify_patch_unknown_ids" and "ffffffffff" in d["detail"]
               for d in run2.degradations)


def test_nothing_to_verify_is_a_degradation_not_a_verdict(tmp_path):
    patch = _patch(tmp_path, "noop.patch", "README.md", "# demo", "# demo, edited")
    run = _run(tmp_path, [_arm()], patch)
    assert _results(run) == []
    assert any(d["kind"] == "verify_patch_nothing_to_verify" for d in run.degradations)


def test_summary_renders_provenance_not_assurance(tmp_path):
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    run = _run(tmp_path, [_arm()], patch)
    md = (run.out_dir / "summary.md").read_text()
    sec = md[md.index("## Patch verification"):]
    assert "requires human review" in sec and "scratch copy" in sec
    assert "never closes a finding" in sec
    assert "`fix.patch`" in sec and "`semgrep` 9.9 (coverage verified)" in sec
    assert "**fixed**" in sec and "absent from a verified scan" in sec
    # the artifact table labels the row as deterministic, still human-review
    assert "deterministic verdict: fixed — requires human review" in md


def test_inplace_is_refused_with_verify_patch(tmp_path):
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    with pytest.raises(ValueError, match="scratch copy"):
        _run(tmp_path, [_arm()], patch, isolate=False)


def test_cli_verify_patch_end_to_end(tmp_path, monkeypatch, capsys):
    from security_council import cli
    target = _seed(tmp_path)
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    monkeypatch.setattr(cli, "_build_arms", lambda names, config, diff=None: [_arm()])
    (target / ".security-council.yaml").write_text("decisions:\n  require_signatures: warn\n")
    rc = cli.main(["scan", str(target), "--arms", "semgrep", "--verify-patch", str(patch),
                   "--for", _main_id(), "--json", "--out", str(tmp_path / "out")])
    out = capsys.readouterr().out
    rec = json.loads(out[out.index("{"):])
    assert rc == rec["exit_code"] == 1                    # the unpatched tree still gates
    pv = rec["verify_fix"]["patches"][0]
    assert pv["counts"] == {"fixed": 1, "not_fixed": 0, "unproven": 0}
    assert pv["results"][0]["verdict"] == "fixed"
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["verify_fix"]["patches"][0]["patch_sha256"] == vp.sha256_of(patch)
    # the human-readable path prints the verdict with the evidence caveat
    rc2 = cli.main(["scan", str(target), "--arms", "semgrep", "--verify-patch", str(patch),
                    "--out", str(tmp_path / "out2")])
    text = capsys.readouterr().out
    assert rc2 == 1 and "patch verification fix.patch: 1 fixed" in text
    assert "requires human review" in text


def test_cli_usage_errors(tmp_path, monkeypatch, capsys):
    from security_council import cli
    target = _seed(tmp_path)
    patch = _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")
    monkeypatch.setattr(cli, "_build_arms", lambda names, config, diff=None: [_arm()])
    assert cli.main(["scan", str(target), "--verify-patch", str(tmp_path / "missing.patch")]) == 2
    assert cli.main(["scan", str(target), "--verify-patch", str(patch), "--inplace"]) == 2
    assert cli.main(["scan", str(target), "--for", "abcdef"]) == 2
    err = capsys.readouterr().err
    assert "not a file" in err and "--inplace" in err and "--for" in err


# --------------------------------------------------------------------------- #
# the fix lane's --verify-fix now takes the deterministic path
# --------------------------------------------------------------------------- #

def test_fix_lane_verify_is_deterministic_not_a_vendor_opinion(tmp_path, monkeypatch):
    from security_council import proc as realproc
    from security_council.arms import fix as fixmod
    from tests.test_fix_lane import _fake_cert
    _fake_cert(monkeypatch)
    real = realproc.run_command

    def fenced_fake(cmd, **kw):
        if "bwrap" not in cmd[0]:
            return real(cmd, **kw)                       # real git init / diff
        p = Path(kw["cwd"]) / "app" / "x.py"             # the fenced fix agent edits the copy
        p.write_text(p.read_text().replace("q = bad(x)", "q = db.safe(x)"))
        class _R:
            ok, exit_code, stdout, stderr, elapsed_seconds, timed_out = True, 0, "", "", 1.0, False
        return _R()
    monkeypatch.setattr(realproc, "run_command", fenced_fake)
    monkeypatch.setattr(fixmod.FixArm, "available", lambda self: (True, "test"))

    target = _seed(tmp_path)
    run = run_scan(target, [_arm()], _cfg(), out_dir=tmp_path / "out",
                   fix_spec={"jobs": ["suggest-patches"], "finding_ids": None, "verify": True})
    kinds = [a["kind"] for a in run.manifest["artifacts"]]
    assert kinds.count("fix") == 1 and kinds.count("verify-fix") == 1
    (ev,) = [a for a in run.manifest["artifacts"] if a["kind"] == "verify-fix"]
    assert ev["method"] == "deterministic" and ev["producer"] == vp.PRODUCER
    assert ev["verdict"] == "fixed" and ev["fix_family"] == "claude"
    pv = run.manifest["verify_fix"]["patches"][0]
    assert pv["applied"] is True and pv["patch"].startswith("claude-fix:suggest-patches:")
    # the vendor verify arm was never consulted
    assert not any("verify-fix" in str(a.get("producer")) and a.get("method") != "deterministic"
                   for a in run.manifest["artifacts"])
    assert run.findings[0].disposition.lifecycle == "open"
    assert (target / "app" / "x.py").read_text().startswith("import db\nq = bad(x)")
