"""A2 (R19): `--verify-patch FILE --against RUN_DIR` — judge a patch against an
OLD run's finding population at the SAME commit, guarded by a control run of the
CURRENT scanners so scanner/ruleset drift cannot masquerade as a fix.

Every precondition fails CLOSED to a graded `unproven (<reason>)` verdict — never
a usage error, a crash, or a `fixed`. Offline: git is real, the scanners are the
content-sensitive fakes from test_verify_patch (a rule fires when a file contains
its needle), so "re-run it on the patched / control copy" means something.

Load-bearing guards are vacuity-checked (R12 discipline): a differential where
the ONLY change is the guarded condition, and the verdict flips off `fixed`; and
a direct neuter of the committed-run-dir guard showing its refusal disappears.
"""
import difflib
import json
import os
import subprocess

from security_council import decisions as dec, verify_patch as vp
from security_council.orchestrator import run_scan, run_verify_against
from tests.test_verify_patch import RC_MAIN, RC_MOVED, ContentArm, _cfg

FILES = {"app/x.py": "import db\nq = bad(x)\nprint(q)\n",
         "app/y.py": "z = other(y)\n",
         "README.md": "# demo\n"}


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


def _repo(tmp_path):
    """A committed git repo (clean tree, one commit)."""
    repo = tmp_path / "gitrepo"
    (repo / "app").mkdir(parents=True)
    for rel, body in FILES.items():
        (repo / rel).write_text(body)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _arm(rules=None, **kw):
    rules = rules or [("app/x.py", "bad(", RC_MAIN, "py.injection", "high")]
    return ContentArm(rules=rules, **kw)


def _against(tmp_path, repo, arm, name="against"):
    """A real prior full-scan run dir, produced OUTSIDE the repo so it neither
    dirties the tree nor counts as a committed run dir."""
    return run_scan(repo, [arm], _cfg(), out_dir=tmp_path / name).out_dir


def _patch(tmp_path, name, rel, old, new):
    """A -p1 patch replacing line `old` with `new` in the repo's `rel`, written
    OUTSIDE the repo (so it never dirties the target tree)."""
    before = FILES[rel].splitlines(keepends=True)
    after = [(new + "\n") if ln.rstrip("\n") == old else ln for ln in before]
    body = "".join(difflib.unified_diff(before, after, fromfile=f"a/{rel}", tofile=f"b/{rel}"))
    p = tmp_path / name
    p.write_text(f"diff --git a/{rel} b/{rel}\n{body}")
    return p


def _fix(tmp_path):
    return _patch(tmp_path, "fix.patch", "app/x.py", "q = bad(x)", "q = safe(x)")


def _main_id(tmp_path, repo):
    (against,) = [json.loads((_against(tmp_path, repo, _arm(), name="idprobe")
                              / "findings.json").read_text())]
    return against[0]["id"]


def _verify(repo, patch, against, arms=None, **kw):
    return run_verify_against(repo, patch, against, arms or [_arm()], **kw)


def _reason0(r):
    return (r["reasons"] or [""])[0]


# --------------------------------------------------------------------------- #
# the happy path and the three verdicts
# --------------------------------------------------------------------------- #

def test_fixed_against_an_old_run_with_a_control_that_reproduces(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    pv = res.pv
    assert pv["mode"] == "against" and pv["applied"] is True
    assert pv["counts"] == {"fixed": 1, "not_fixed": 0, "unproven": 0}
    (r,) = pv["results"]
    assert r["verdict"] == "fixed" and r["uri"] == "app/x.py"
    # the control note is FIRST — the fix is attributable to the patch
    assert "control:" in _reason0(r) and "reproduce" in _reason0(r)
    assert any("absent from a verified scan" in x for x in r["reasons"])
    # the user's tree is untouched and still at the same commit
    assert (repo / "app" / "x.py").read_text() == FILES["app/x.py"]


def test_not_fixed_when_the_patched_scanner_still_reports_it(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    # a patch that touches app/x.py (so the finding is selected) but leaves bad(
    patch = _patch(tmp_path, "noop.patch", "app/x.py", "print(q)", "print(q)  # note")
    res = _verify(repo, patch, against, out_dir=tmp_path / "vout")
    (r,) = res.pv["results"]
    assert r["verdict"] == "not_fixed" and "still reports it" in " ".join(r["reasons"])


def test_not_fixed_when_the_sink_moves_against_the_control_baseline(tmp_path):
    """The moved-sink baseline is the CONTROL population (current scanners on the
    unpatched tree): a new same-rule finding in the same file, absent from the
    control, is a moved sink, not a fix."""
    repo = _repo(tmp_path)
    rules = [("app/x.py", "bad(", RC_MAIN, "py.injection", "high"),
             ("app/x.py", "bad2(", RC_MOVED, "py.injection", "high")]
    against = _against(tmp_path, repo, _arm(rules=rules))
    patch = _patch(tmp_path, "move.patch", "app/x.py", "q = bad(x)", "q = bad2(x)")
    res = _verify(repo, patch, against, arms=[_arm(rules=rules)], out_dir=tmp_path / "vout")
    (r,) = res.pv["results"]
    assert r["verdict"] == "not_fixed" and "sink moved" in " ".join(r["reasons"])
    assert res.pv["new_findings"] == 1


# --------------------------------------------------------------------------- #
# the CONTROL run (load-bearing, R19): a finding that does not reproduce on the
# UNPATCHED current tree cannot be judged fixed — that is scanner/ruleset drift
# --------------------------------------------------------------------------- #

def test_control_not_reproduced_is_unproven_not_fixed(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())            # the old run DID report it
    # the CURRENT scanner no longer detects `bad(` (a ruleset drift). Select the
    # old finding by id, since the patch's file no longer matches a live finding.
    drifted = _arm(rules=[("app/x.py", "NEVER_MATCHES", "z", "py.other", "high")])
    res = _verify(repo, _fix(tmp_path), against, arms=[drifted],
                  finding_ids=[_main_id(tmp_path, repo)], out_dir=tmp_path / "vout")
    (r,) = res.pv["results"]
    assert r["verdict"] == "unproven"
    assert vp.R_CONTROL_NOT_REPRODUCED in _reason0(r)


def test_control_reproduction_is_what_flips_the_verdict(tmp_path):
    """Vacuity of the control gate: the ONLY difference between these two runs is
    whether the current scanner reproduces the finding on the unpatched tree; the
    verdict flips unproven(control_not_reproduced) <-> fixed."""
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    fid = _main_id(tmp_path, repo)
    detects = _verify(repo, _fix(tmp_path), against, arms=[_arm()],
                      finding_ids=[fid], out_dir=tmp_path / "a").pv["results"][0]
    blind = _verify(repo, _fix(tmp_path), against,
                    arms=[_arm(rules=[("app/x.py", "NOPE", "z", "py.o", "high")])],
                    finding_ids=[fid], out_dir=tmp_path / "b").pv["results"][0]
    assert detects["verdict"] == "fixed"
    assert blind["verdict"] == "unproven" and vp.R_CONTROL_NOT_REPRODUCED in _reason0(blind)


def test_control_arm_unavailable_is_its_own_reason(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    # the arm is available once (for the against-run production done above uses a
    # fresh arm), then goes away for BOTH the control and patched passes
    res = _verify(repo, _fix(tmp_path), against, arms=[_arm(unavailable_after=0)],
                  finding_ids=[_main_id(tmp_path, repo)], out_dir=tmp_path / "vout")
    (r,) = res.pv["results"]
    assert r["verdict"] == "unproven"
    assert vp.R_CONTROL_ARM_UNAVAILABLE in _reason0(r)


# --------------------------------------------------------------------------- #
# global preconditions: each fails CLOSED to a graded `unproven (<reason>)`
# --------------------------------------------------------------------------- #

def test_base_mismatch_when_head_moved_since_the_against_run(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    _git(repo, "commit", "-q", "--allow-empty", "-m", "moves HEAD")   # rebase-like drift
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    assert res.pv["precondition"]["reason"] == vp.R_BASE_MISMATCH
    assert all(r["verdict"] == "unproven" for r in res.pv["results"])
    assert all(vp.R_BASE_MISMATCH in _reason0(r) for r in res.pv["results"])


def test_base_match_is_what_permits_a_verdict(tmp_path):
    """Vacuity of the base-commit gate: same inputs, HEAD moved vs not — the
    verdict flips unproven(base_mismatch) <-> fixed."""
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    same = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "a").pv
    _git(repo, "commit", "-q", "--allow-empty", "-m", "drift")
    moved = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "b").pv
    assert same["counts"]["fixed"] == 1
    assert moved["precondition"]["reason"] == vp.R_BASE_MISMATCH


def test_target_dirty_is_unproven(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    (repo / "untracked.py").write_text("x = 1\n")           # an untracked SOURCE file: dirty
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    assert res.pv["precondition"]["reason"] == vp.R_TARGET_DIRTY


def test_the_state_dir_alone_does_not_count_as_dirty(tmp_path):
    """The reused R18 predicate exempts .security-council — a run that just wrote
    its own state there must still be able to verify (the exemption is load-
    bearing: WITHOUT it the against-run's own writes would refuse every verify)."""
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    (repo / ".security-council").mkdir(exist_ok=True)
    (repo / ".security-council" / "state.json").write_text("{}")    # tool state, untracked
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    assert res.pv["precondition"] is None and res.pv["counts"]["fixed"] == 1


def test_against_scope_not_full_is_unproven(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    mf = json.loads((against / "manifest.json").read_text())
    mf["scan_scope"] = {"kind": "diff", "base": "HEAD~1"}            # a partial run
    (against / "manifest.json").write_text(json.dumps(mf))
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    assert res.pv["precondition"]["reason"] == vp.R_AGAINST_SCOPE


def test_against_coverage_not_verified_is_unproven(tmp_path):
    """Per-finding: an old run whose vouching scanner covered only 'partial'
    cannot be the pre-patch baseline."""
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    mf = json.loads((against / "manifest.json").read_text())
    for a in mf["arms"]:
        if a["name"] == "semgrep":
            a["coverage_verdict"] = "partial"
    (against / "manifest.json").write_text(json.dumps(mf))
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    (r,) = res.pv["results"]
    assert r["verdict"] == "unproven" and vp.R_AGAINST_COVERAGE in _reason0(r)


def test_against_coverage_verified_is_what_permits_fixed(tmp_path):
    """Vacuity of the against-coverage gate: verified -> fixed, partial ->
    unproven, all else equal."""
    repo = _repo(tmp_path)
    ok = _verify(repo, _fix(tmp_path), _against(tmp_path, repo, _arm()),
                 out_dir=tmp_path / "a").pv
    against = _against(tmp_path, repo, _arm(), name="partial")
    mf = json.loads((against / "manifest.json").read_text())
    for a in mf["arms"]:
        a["coverage_verdict"] = "partial"
    (against / "manifest.json").write_text(json.dumps(mf))
    partial = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "b").pv
    assert ok["counts"]["fixed"] == 1
    assert partial["results"][0]["verdict"] == "unproven"
    assert vp.R_AGAINST_COVERAGE in _reason0(partial["results"][0])


def test_inconsistent_manifest_counts_are_unproven(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    mf = json.loads((against / "manifest.json").read_text())
    mf["counts"]["total"] = mf["counts"]["total"] + 7        # tamper: does not match findings.json
    (against / "manifest.json").write_text(json.dumps(mf))
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    assert res.pv["precondition"]["reason"] == vp.R_AGAINST_INCONSISTENT
    assert "tampered" in res.pv["precondition"]["detail"]


def test_missing_manifest_is_unproven_with_no_verdicts(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    (against / "manifest.json").unlink()
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    assert res.pv["precondition"]["reason"] == vp.R_AGAINST_INCONSISTENT
    assert res.pv["results"] == []                           # nothing to attach verdicts to


def test_patch_refused_is_unproven_and_never_applied(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    patch = tmp_path / "store.patch"
    patch.write_text("diff --git a/.security-council/decisions/x.json "
                     "b/.security-council/decisions/x.json\n"
                     "--- a/.security-council/decisions/x.json\n"
                     "+++ b/.security-council/decisions/x.json\n@@ -1 +1 @@\n-a\n+b\n")
    res = _verify(repo, patch, against, finding_ids=[_main_id(tmp_path, repo)],
                  out_dir=tmp_path / "vout")
    assert res.pv["precondition"]["reason"] == vp.R_PATCH_REFUSED
    assert res.pv["applied"] is False
    assert all(r["verdict"] == "unproven" for r in res.pv["results"])


def test_patch_that_does_not_apply_is_unproven(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    stale = _patch(tmp_path, "stale.patch", "app/x.py", "q = does_not_exist(x)", "q = safe(x)")
    res = _verify(repo, stale, against, finding_ids=[_main_id(tmp_path, repo)],
                  out_dir=tmp_path / "vout")
    (r,) = res.pv["results"]
    assert r["verdict"] == "unproven" and vp.R_PATCH_NOT_APPLIED in _reason0(r)
    assert res.pv["applied"] is False


def test_nothing_to_verify_is_a_degradation_not_a_precondition(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    patch = _patch(tmp_path, "readme.patch", "README.md", "# demo", "# demo, edited")
    res = _verify(repo, patch, against, out_dir=tmp_path / "vout")
    assert res.pv["results"] == [] and res.pv["precondition"] is None
    assert any(d["kind"] == "verify_patch_nothing_to_verify" for d in res.degradations)


# --------------------------------------------------------------------------- #
# the committable-run-dir refusal (R14a-S3/R17), on the SYMLINK-RESOLVED path
# --------------------------------------------------------------------------- #

def test_committed_run_dir_is_refused(tmp_path):
    """A hostile repo commits a fake run dir to be trusted as evidence."""
    repo = _repo(tmp_path)
    good = _against(tmp_path, repo, _arm())
    fake = repo / "runs" / "planted"
    fake.mkdir(parents=True)
    for name in ("manifest.json", "findings.json"):
        (fake / name).write_text((good / name).read_text())
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "plant a fake run dir")
    res = _verify(repo, _fix(tmp_path), fake, out_dir=tmp_path / "vout")
    assert res.pv["precondition"]["reason"] == vp.R_AGAINST_TRACKED


def test_committed_run_dir_reached_through_a_symlink_is_refused(tmp_path):
    """The check is on the symlink-RESOLVED path, so a symlink from an untracked
    location to the committed run dir cannot launder it."""
    repo = _repo(tmp_path)
    good = _against(tmp_path, repo, _arm())
    fake = repo / "runs" / "planted"
    fake.mkdir(parents=True)
    for name in ("manifest.json", "findings.json"):
        (fake / name).write_text((good / name).read_text())
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "plant")
    link = tmp_path / "laundered"       # untracked, points INTO the committed dir
    link.symlink_to(fake)
    res = _verify(repo, _fix(tmp_path), link, out_dir=tmp_path / "vout")
    assert res.pv["precondition"]["reason"] == vp.R_AGAINST_TRACKED


def test_legit_run_dir_under_state_dir_is_not_refused(tmp_path):
    """The default location (`.security-council/runs`, gitignored/untracked) must
    NOT trip the committed-run-dir refusal."""
    repo = _repo(tmp_path)
    against = run_scan(repo, [_arm()], _cfg()).out_dir   # default: repo/.security-council/runs/<id>
    assert str(repo / ".security-council") in str(against)
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    assert res.pv["precondition"] is None and res.pv["counts"]["fixed"] == 1


def test_tracked_run_dir_guard_is_load_bearing(tmp_path, monkeypatch):
    """Vacuity: neuter `_run_dir_has_tracked_files` and the committed-run-dir
    refusal disappears (the reason is no longer against_run_dir_tracked)."""
    repo = _repo(tmp_path)
    good = _against(tmp_path, repo, _arm())
    fake = repo / "runs" / "planted"
    fake.mkdir(parents=True)
    for name in ("manifest.json", "findings.json"):
        (fake / name).write_text((good / name).read_text())
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "plant")
    with_guard = _verify(repo, _fix(tmp_path), fake, out_dir=tmp_path / "a").pv
    assert with_guard["precondition"]["reason"] == vp.R_AGAINST_TRACKED
    monkeypatch.setattr(vp, "_run_dir_has_tracked_files", lambda p: False)
    neutered = _verify(repo, _fix(tmp_path), fake, out_dir=tmp_path / "b").pv
    assert (neutered["precondition"] or {}).get("reason") != vp.R_AGAINST_TRACKED


def test_run_dir_has_tracked_files_unit(tmp_path):
    repo = _repo(tmp_path)
    # an untracked dir under the repo -> not tracked
    live = run_scan(repo, [_arm()], _cfg()).out_dir
    assert vp._run_dir_has_tracked_files(live) is False
    # a committed dir -> tracked
    d = repo / "committed"
    d.mkdir()
    (d / "manifest.json").write_text("{}")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "c")
    assert vp._run_dir_has_tracked_files(d) is True
    # a dir outside any git repo -> not tracked (the legit non-repo case)
    outside = tmp_path / "loose"
    outside.mkdir()
    assert vp._run_dir_has_tracked_files(outside) is False


# --------------------------------------------------------------------------- #
# evidence binds to the mutable artifact, and never becomes a decision
# --------------------------------------------------------------------------- #

def test_evidence_binds_both_sides_and_the_against_manifest_sha(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    pv = res.pv
    ag = pv["against"]
    assert ag["run_id"] and ag["base_commit"] and ag["manifest_sha256"]
    assert ag["manifest_sha256"] == vp.sha256_of(against / "manifest.json")
    assert ag["scan_scope"]["kind"] == "full" and ag["coverage"]["semgrep"] == "verified"
    # both the control and patched scanner passes are recorded with versions
    assert [a["name"] for a in pv["control_arms"]] == ["semgrep"]
    assert [a["name"] for a in pv["arms"]] == ["semgrep"]
    assert pv["control_arms"][0]["tool_version"] == "9.9" and pv["arms"][0]["tool_version"] == "9.9"
    assert pv["control_arms"][0]["coverage_verdict"] == "verified"
    # the evidence artifact carries the against binding and stays machine/non-closing
    (art,) = res.artifacts
    assert art["mode"] == "against" and art["decided_by"] == "machine"
    assert art["non_closing"] is True and art["against"]["manifest_sha256"] == ag["manifest_sha256"]
    assert art["control_arms"] and art["patched_arms"]
    # the evidence file is written outside the scan run tree
    assert (res.out_dir / "verify-against.json").is_file()


def test_manifest_sha_is_recorded_even_when_a_precondition_fails(tmp_path):
    """Trust is being extended to a MUTABLE local artifact, so its sha256 is
    bound even on a rejected run — tampering stays visible."""
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    _git(repo, "commit", "-q", "--allow-empty", "-m", "drift")     # force base_mismatch
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    assert res.pv["precondition"]["reason"] == vp.R_BASE_MISMATCH
    assert res.pv["against"]["manifest_sha256"] == vp.sha256_of(against / "manifest.json")


def test_verdict_is_recorded_as_machine_evidence_and_ignored_by_history(tmp_path):
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    store = dec.DecisionStore(repo / ".security-council")
    rc = res.pv["results"][0]["root_cause"]
    (ev,) = store.verify_evidence(rc)
    assert ev["kind"] == "deterministic_verify_fix" and ev["decided_by"] == "machine"
    assert ev["verdict"] == "fixed" and ev["patch_sha256"] == res.pv["patch_sha256"]
    assert ev["detail"]["mode"] == "against"
    assert ev["detail"]["against"]["manifest_sha256"] == res.pv["against"]["manifest_sha256"]
    assert store.history_counts() == {}                    # L1: never feeds the score prior
    assert store.has_decisions() is False                  # never a decision


def test_precondition_failure_records_no_store_evidence(tmp_path):
    """A global precondition failure is noise in the store — it is NOT recorded."""
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    (repo / "dirty.py").write_text("x = 1\n")               # -> target_dirty
    res = _verify(repo, _fix(tmp_path), against, out_dir=tmp_path / "vout")
    assert res.pv["precondition"]["reason"] == vp.R_TARGET_DIRTY
    store = dec.DecisionStore(repo / ".security-council")
    rc = res.pv["results"][0]["root_cause"]
    assert store.verify_evidence(rc) == []


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #

def test_cli_verify_against_end_to_end(tmp_path, monkeypatch, capsys):
    from security_council import cli
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    monkeypatch.setattr(cli, "_build_arms", lambda names, config, diff=None: [_arm()])
    (repo / ".security-council.yaml").write_text("decisions:\n  require_signatures: warn\n")
    # NOTE the config file above is untracked -> would dirty the tree, so stage
    # it as tool state? No: it is NOT .security-council/, so commit it clean.
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "config")
    # re-produce the against run at the NEW head so base matches
    against = _against(tmp_path, repo, _arm(), name="against2")
    rc = cli.main(["scan", str(repo), "--arms", "semgrep", "--verify-patch", str(_fix(tmp_path)),
                   "--against", str(against), "--json", "--out", str(tmp_path / "cliout")])
    out = capsys.readouterr().out
    rec = json.loads(out[out.index("{"):])
    assert rc == 0                                          # evidence-only: never gates
    assert rec["mode"] == "against"
    assert rec["verify_patch"]["counts"] == {"fixed": 1, "not_fixed": 0, "unproven": 0}
    # human-readable path
    rc2 = cli.main(["scan", str(repo), "--arms", "semgrep", "--verify-patch", str(_fix(tmp_path)),
                    "--against", str(against), "--out", str(tmp_path / "cliout2")])
    text = capsys.readouterr().out
    assert rc2 == 0 and "verify-patch --against" in text
    assert "1 fixed" in text and "never closes a finding" in text


def test_cli_against_requires_verify_patch(tmp_path, capsys):
    from security_council import cli
    repo = _repo(tmp_path)
    against = _against(tmp_path, repo, _arm())
    assert cli.main(["scan", str(repo), "--against", str(against)]) == 2
    assert "pass --verify-patch too" in capsys.readouterr().err


def test_cli_against_not_a_directory_is_usage_error(tmp_path, monkeypatch, capsys):
    from security_council import cli
    repo = _repo(tmp_path)
    monkeypatch.setattr(cli, "_build_arms", lambda names, config, diff=None: [_arm()])
    rc = cli.main(["scan", str(repo), "--verify-patch", str(_fix(tmp_path)),
                   "--against", str(tmp_path / "nope")])
    assert rc == 2 and "is not a directory" in capsys.readouterr().err
