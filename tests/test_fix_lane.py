"""M-V4a fix arm: fail-closed on an uncertified fence; produces a validated
`.patch` artifact (never applied); refuses in-place; secrets patch export-excluded."""
import hashlib

import pytest

from security_council.arms import fix as fixmod
from security_council.arms.fix import FixArm
from security_council.orchestrator import run_scan
from tests.test_entitlements import _cfg
from tests.test_orchestrator import FakeArm, _finding as orch_finding


def _finding_row(cwe="CWE-89", fam="injection", uri="app/x.py"):
    return {"id": "f" + hashlib.sha256(uri.encode()).hexdigest()[:12],
            "taxonomy": {"cwe": [cwe], "cwe_family": fam},
            "locations": [{"uri": uri, "start_line": 1}]}


def _seed_target(tmp_path):
    t = tmp_path / "repo"
    (t / "app").mkdir(parents=True)
    (t / "app" / "x.py").write_text("q = 'SELECT ' + name\n")
    return t


def test_unknown_fix_job_rejected():
    with pytest.raises(ValueError, match="unknown fix job"):
        FixArm(job="nope", finding=_finding_row())


def test_fix_fails_closed_without_fence(tmp_path, monkeypatch):
    monkeypatch.setattr(fixmod._fence, "certify",
                        lambda **kw: (None, {"refused": "bwrap unavailable", "bwrap": "x"}))
    arm = FixArm(job="suggest-patches", finding=_finding_row())
    res = arm.run(_seed_target(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    assert not res.ok and "fence_unverified" in res.error and res.artifacts == []


def _fake_cert(monkeypatch):
    from security_council import fence
    # the fake mints a certificate for the fence it is ASKED about, so
    # `verify_certificate` (hash + liveness) is still genuinely exercised
    def _certify(**kw):
        h = fence.config_hash_for(work_dir=kw["work_dir"], home=kw["home"],
                                  allow_network=kw.get("allow_network", False))
        cert = fence.FenceCertificate(config_hash=h, bwrap_version="bwrap 0.11.0", host="t",
                                      minted_at=9e18)
        return cert, {"bwrap": "bwrap 0.11.0", "breaches": [], "controls_missing": [],
                      "canary_done": True}
    monkeypatch.setattr(fixmod._fence, "certify", _certify)


def test_fix_produces_validated_patch_artifact(tmp_path, monkeypatch):
    _fake_cert(monkeypatch)
    target = _seed_target(tmp_path)

    def fake_run(cmd, **kw):
        # emulate the fenced vendor editing the work copy (cwd)
        from pathlib import Path
        wt = Path(kw["cwd"]) / "app" / "x.py"
        wt.write_text("q = db.execute('SELECT ...', [name])\n")
        class _R:
            ok, exit_code, stdout, stderr, elapsed_seconds, timed_out = True, 0, "", "", 1.0, False
        return _R()
    monkeypatch.setattr(fixmod.proc, "run_command", fake_run)

    arm = FixArm(job="suggest-patches", finding=_finding_row())
    res = arm.run(target, tmp_path / "out", run_id="r1", collected_at="2026-08-23T00:00:00Z")
    assert res.ok and len(res.artifacts) == 1
    a = res.artifacts[0]
    assert a["kind"] == "fix" and a["format"] == "patch" and a["export_excluded"] is False
    # the .patch was written under raw/, and the REAL target is untouched
    patch = (tmp_path / "out" / "raw" / a["path"].split("raw/", 1)[1]).read_text()
    assert "db.execute" in patch and "SELECT" in patch
    assert (target / "app" / "x.py").read_text() == "q = 'SELECT ' + name\n"   # never applied


def test_secrets_fix_patch_is_export_excluded_and_redacted(tmp_path, monkeypatch):
    _fake_cert(monkeypatch)
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "settings.py").write_text("KEY = 'AKIAIOSFODNN7EXAMPLEKEY99'\n")

    def fake_run(cmd, **kw):
        from pathlib import Path
        (Path(kw["cwd"]) / "app" / "settings.py").write_text("KEY = os.environ['KEY']\n")
        class _R:
            ok, exit_code, stdout, stderr, elapsed_seconds, timed_out = True, 0, "", "", 1.0, False
        return _R()
    monkeypatch.setattr(fixmod.proc, "run_command", fake_run)

    arm = FixArm(job="suggest-patches", finding=_finding_row("CWE-798", "secrets", "app/settings.py"))
    res = arm.run(target, tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok
    a = res.artifacts[0]
    assert a["export_excluded"] is True and a["patch"]["secret_in_patch"] is True
    patch = (tmp_path / "out" / "raw" / a["path"].split("raw/", 1)[1]).read_text()
    assert "AKIAIOSFODNN7EXAMPLEKEY99" not in patch


def test_no_change_degrades_not_crashes(tmp_path, monkeypatch):
    _fake_cert(monkeypatch)

    def fake_run(cmd, **kw):
        class _R:
            ok, exit_code, stdout, stderr, elapsed_seconds, timed_out = True, 0, "", "", 1.0, False
        return _R()   # edits nothing
    monkeypatch.setattr(fixmod.proc, "run_command", fake_run)
    arm = FixArm(job="fix-finding", finding=_finding_row())
    res = arm.run(_seed_target(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok and "no_patch" in res.error and res.artifacts == []


def test_orchestrator_refuses_inplace_with_fix(tmp_path):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="a")])]
    with pytest.raises(ValueError, match="requires isolation"):
        run_scan(_seed_target(tmp_path), arms, _cfg(), out_dir=tmp_path / "out",
                 isolate=False, fix_spec={"jobs": ["suggest-patches"], "finding_ids": None})


def test_orchestrator_fix_only_open_findings(tmp_path, monkeypatch):
    _fake_cert(monkeypatch)
    monkeypatch.setattr(fixmod.proc, "run_command",
                        lambda cmd, **kw: type("R", (), {"ok": True, "exit_code": 0, "stdout": "",
                                                         "stderr": "", "elapsed_seconds": 1.0,
                                                         "timed_out": False})())
    # a refuted finding must be skipped by the fix phase
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="z")])]
    run = run_scan(_seed_target(tmp_path), arms, _cfg(), out_dir=tmp_path / "out",
                   fix_spec={"jobs": ["suggest-patches"], "finding_ids": ["nonexistent"]})
    # no finding matched the id filter → no fix artifacts, no crash
    assert [a for a in run.manifest["artifacts"] if a.get("kind") == "fix"] == []


# --------------------------------------------------------------------- #
# B1: relaxed posture (open network, neutral-path runtime, structured stamps)
# --------------------------------------------------------------------- #

def _fake_plan(monkeypatch, command="codex", kind="node"):
    from security_council.fence import RuntimePlan
    plan = RuntimePlan(command=command,
                       binds=((f"/real/{command}", "/opt/sc-node"),),
                       path_dirs=("/opt/sc-node/bin",),
                       provenance={"command": command, "kind": kind, "host_path": f"/real/{command}"})
    monkeypatch.setattr(fixmod._fence, "resolve_runtime", lambda c: plan)
    return plan


def _fake_relaxed_cert(monkeypatch):
    from security_council import fence

    def _certify(**kw):
        h = fence.config_hash_for(
            work_dir=kw["work_dir"], home=kw["home"], allow_network=kw.get("allow_network", False),
            runtime_binds=kw.get("runtime_binds", ()), writable_binds=kw.get("writable_binds", ()))
        cert = fence.FenceCertificate(config_hash=h, bwrap_version="bwrap 0.11.0", host="t",
                                      minted_at=9e18)
        return cert, {"bwrap": "bwrap 0.11.0", "breaches": [], "controls_missing": [],
                      "canary_done": True, "network": "open:waived_by_posture"}
    monkeypatch.setattr(fixmod._fence, "certify", _certify)


def test_relaxed_available_refuses_without_acknowledgement(monkeypatch):
    _fake_plan(monkeypatch)
    monkeypatch.setattr(fixmod.shutil, "which", lambda c: "/x/" + c)
    monkeypatch.setattr(fixmod._fence, "bwrap_available", lambda: (True, "bwrap 0.11.0"))
    arm = FixArm(job="fix-finding", finding=_finding_row(), allow_network=True)
    ok, why = arm.available()
    assert not ok and "acknowledgement" in why
    arm2 = FixArm(job="fix-finding", finding=_finding_row(), allow_network=True,
                  egress_acknowledged=True)
    assert arm2.available()[0] is True


def test_relaxed_run_stamps_structured_posture(tmp_path, monkeypatch):
    _fake_plan(monkeypatch, "codex", "node")
    _fake_relaxed_cert(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")           # api-key path: no credential copy

    def fake_run(cmd, **kw):
        from pathlib import Path
        (Path(kw["cwd"]) / "app" / "x.py").write_text("q = db.execute('SELECT ...', [name])\n")
        return type("R", (), {"ok": True, "exit_code": 0, "stdout": "", "stderr": "",
                              "elapsed_seconds": 1.0, "timed_out": False})()
    monkeypatch.setattr(fixmod.proc, "run_command", fake_run)

    arm = FixArm(job="fix-finding", finding=_finding_row(), allow_network=True,
                 egress_acknowledged=True)
    res = arm.run(_seed_target(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok
    p = res.coverage["posture"]
    assert p["network_access"] == "unrestricted"
    assert p["execution_boundary"] == "orchestrator_bwrap"
    assert p["operator_acknowledged_unrestricted_egress"] is True
    assert p["real_home_visible"] is False
    assert p["vendor_home"] == "api-key"                       # env key present -> no copy
    assert p["code_disclosed_to"] == "openai"
    assert p["vendor_sandbox"] == "workspace-write"
    assert p["tests_ran"] is False and p["runtime"]["kind"] == "node"
    assert p["cert_hash"]
    assert res.artifacts[0]["patch"]["posture"]["network_access"] == "unrestricted"


def test_relaxed_run_copies_credential_when_no_api_key(tmp_path, monkeypatch):
    _fake_plan(monkeypatch, "codex", "node")
    _fake_relaxed_cert(monkeypatch)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CODEX_API_KEY", raising=False)
    fake_home = tmp_path / "fakehome"
    (fake_home / ".codex").mkdir(parents=True)
    (fake_home / ".codex" / "auth.json").write_text('{"token":"SENSITIVE"}')
    monkeypatch.setattr(fixmod.Path, "home", classmethod(lambda cls: fake_home))
    captured = {}

    def fake_run(cmd, **kw):
        from pathlib import Path
        # the credential COPY is reachable at the neutral CODEX_HOME, not the real one
        captured["env"] = kw.get("env", {})
        (Path(kw["cwd"]) / "app" / "x.py").write_text("fixed = 1\n")
        return type("R", (), {"ok": True, "exit_code": 0, "stdout": "", "stderr": "",
                              "elapsed_seconds": 1.0, "timed_out": False})()
    monkeypatch.setattr(fixmod.proc, "run_command", fake_run)

    arm = FixArm(job="fix-finding", finding=_finding_row(), allow_network=True,
                 egress_acknowledged=True)
    res = arm.run(_seed_target(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    assert res.ok
    assert res.coverage["posture"]["vendor_home"] == "oauth-file-copy"
    assert captured["env"]["CODEX_HOME"] == "/sc-codex"        # neutral, not the real ~/.codex
    # the real credential file is untouched (we copied, never moved/bound the dir)
    assert (fake_home / ".codex" / "auth.json").read_text() == '{"token":"SENSITIVE"}'


def test_strict_posture_stamps_unshared_network(tmp_path, monkeypatch):
    _fake_cert(monkeypatch)
    monkeypatch.setattr(fixmod.proc, "run_command",
                        lambda cmd, **kw: type("R", (), {"ok": True, "exit_code": 0, "stdout": "",
                                                         "stderr": "", "elapsed_seconds": 1.0,
                                                         "timed_out": False})())
    arm = FixArm(job="suggest-patches", finding=_finding_row())   # allow_network defaults False
    res = arm.run(_seed_target(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    # no change -> degrades, but the posture stamp still records the strict shape
    p = res.coverage["posture"]
    assert p["network_access"] == "unshared" and p["code_disclosed_to"] is None
    assert p["operator_acknowledged_unrestricted_egress"] is None


# --------------------------------------------------------------------- #
# B1c: CLI double opt-in for the relaxed posture (repo config can't enable it)
# --------------------------------------------------------------------- #

def _cli_scan(monkeypatch, tmp_path, extra_args, config_text=None):
    """Run `cli.main(scan ...)` with run_scan faked; return (rc, captured fix_spec)."""
    from types import SimpleNamespace

    from security_council import cli
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("x = 1\n")
    if config_text is not None:
        (target / ".security-council.yaml").write_text(config_text)
    seen = {}

    def fake_run_scan(target, arms, config, **kw):
        seen["fix_spec"] = kw.get("fix_spec")
        return SimpleNamespace(run_id="r", out_dir=tmp_path, exit_code=0,
                               manifest={"counts": {}}, degradations=[])
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_build_arms", lambda names, config=None, diff=None: [])
    rc = cli.main(["scan", str(target), "--arms", "semgrep", "--json", *extra_args])
    return rc, seen.get("fix_spec")


def test_cli_ack_without_config_key_is_refused(monkeypatch, tmp_path):
    rc, spec = _cli_scan(monkeypatch, tmp_path,
                         ["--fix", "gating", "--fix-job", "fix-finding",
                          "--allow-unrestricted-fix-egress"])
    assert rc == 2 and spec is None                        # both halves required


def test_cli_repo_config_cannot_enable_network(monkeypatch, tmp_path):
    rc, spec = _cli_scan(monkeypatch, tmp_path,
                         ["--fix", "gating", "--fix-job", "fix-finding",
                          "--allow-unrestricted-fix-egress"],
                         config_text="fix:\n  allow_network: true\n")
    assert rc == 2 and spec is None                        # repo-sourced key refused


def test_cli_gov_profile_refuses_the_lane(monkeypatch, tmp_path):
    rc, spec = _cli_scan(monkeypatch, tmp_path,
                         ["--fix", "gating", "--fix-job", "fix-finding",
                          "--allow-unrestricted-fix-egress", "--profile", "gov",
                          "--config", str(_operator_cfg(tmp_path))])
    assert rc == 4 and spec is None                        # gov refuses like Red


def test_cli_both_halves_via_operator_config_enables_relaxed(monkeypatch, tmp_path):
    rc, spec = _cli_scan(monkeypatch, tmp_path,
                         ["--fix", "gating", "--fix-job", "fix-finding",
                          "--allow-unrestricted-fix-egress",
                          "--config", str(_operator_cfg(tmp_path))])
    assert rc == 0
    assert spec["allow_network"] is True and spec["egress_acknowledged"] is True


def test_cli_strict_when_neither_half_present(monkeypatch, tmp_path):
    rc, spec = _cli_scan(monkeypatch, tmp_path, ["--fix", "gating", "--fix-job", "fix-finding"])
    assert rc == 0
    assert spec["allow_network"] is False and spec["egress_acknowledged"] is False


def _operator_cfg(tmp_path):
    p = tmp_path / "operator.yaml"
    p.write_text("fix:\n  allow_network: true\n")
    return p


def test_prompt_has_no_bogus_skill_trigger_and_names_cwe():
    # B1 live-found: `$fix-finding`/`/claude-security ...` are NOT reachable in
    # -p/exec mode; a literal `$fix-finding` prefix is confusing text (R10).
    arm = FixArm(job="fix-finding", finding=_finding_row("CWE-89", "injection", "app/r.py"))
    p = arm._prompt()
    assert "$fix-finding" not in p and "/claude-security" not in p
    assert "CWE-89" in p and "app/r.py" in p


def test_relaxed_run_passes_devnull_stdin(tmp_path, monkeypatch):
    # B1 live-found: `codex exec` reads stdin and blocks on no EOF; the fenced
    # run must pass stdin=DEVNULL.
    import subprocess
    _fake_plan(monkeypatch, "codex", "node")
    _fake_relaxed_cert(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    seen = {}

    def fake_run(cmd, **kw):
        seen["stdin"] = kw.get("stdin")
        from pathlib import Path
        (Path(kw["cwd"]) / "app" / "x.py").write_text("fixed = 1\n")
        return type("R", (), {"ok": True, "exit_code": 0, "stdout": "", "stderr": "",
                              "elapsed_seconds": 1.0, "timed_out": False})()
    monkeypatch.setattr(fixmod.proc, "run_command", fake_run)
    arm = FixArm(job="fix-finding", finding=_finding_row(), allow_network=True,
                 egress_acknowledged=True)
    arm.run(_seed_target(tmp_path), tmp_path / "out", run_id="r", collected_at="t")
    assert seen["stdin"] is subprocess.DEVNULL
