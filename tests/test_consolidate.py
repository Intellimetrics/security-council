"""The consolidate verb: import-only by construction, revision-bound, gated."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from security_council import mcp_server as srv
from security_council.cli import main as cli_main
from tests.test_import_bundle import PRIOR_COMMIT, _write_prior_run

HERE = Path(__file__).parent
SEED = HERE / "fixtures" / "seedrepo"


def _git_target(tmp_path: Path) -> tuple[Path, str]:
    target = tmp_path / "target"
    shutil.copytree(SEED, target)
    subprocess.run(["git", "init", "-q", "."], cwd=target, check=True)
    subprocess.run(["git", "add", "-A"], cwd=target, check=True)
    subprocess.run(["git", "-c", "user.email=t@x", "-c", "user.name=t",
                    "commit", "-qm", "seed"], cwd=target, check=True)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=target, check=True,
                         capture_output=True, text=True).stdout.strip()
    return target, sha


def test_consolidate_cli_produces_a_gated_report_without_rerunning_producers(tmp_path, capsys):
    target, sha = _git_target(tmp_path)
    prior = _write_prior_run(tmp_path, git_commit=sha)
    rc = cli_main(["consolidate", str(target), "--import-run", str(prior),
                   "--out", str(tmp_path / "out"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1 and payload["exit_code"] == 1          # high findings still gate
    assert payload["counts"]["total"] == 2
    assert payload["degradations"] == []
    manifest = json.loads((Path(payload["out_dir"]) / "manifest.json").read_text())
    [row] = [a for a in manifest["arms"] if a["kind"] == "import"]
    assert row["ok"] and row["imported_run_id"] == "20260829_123340"
    assert row["imported_sources"] == ["semgrep"]


def test_consolidate_cli_fails_closed_on_revision_mismatch(tmp_path, capsys):
    target, _ = _git_target(tmp_path)                     # HEAD != PRIOR_COMMIT
    prior = _write_prior_run(tmp_path, git_commit=PRIOR_COMMIT)
    rc = cli_main(["consolidate", str(target), "--import-run", str(prior),
                   "--out", str(tmp_path / "out"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 3                                        # degraded, never silently clean
    assert any("revision mismatch" in json.dumps(d) for d in payload["degradations"])


def test_consolidate_cli_requires_at_least_one_source(tmp_path, capsys):
    target, _ = _git_target(tmp_path)
    rc = cli_main(["consolidate", str(target)])
    assert rc == 2
    assert "--import-run" in capsys.readouterr().err


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv(srv.ROOT_ENV, str(tmp_path))
    monkeypatch.delenv(srv.NESTED_ENV, raising=False)
    return tmp_path


def test_sc_consolidate_confines_import_paths_to_the_mcp_root(root):
    outside = Path("/tmp")
    with pytest.raises(ValueError, match="ProjectRootMismatch"):
        srv.sc_consolidate({"import_runs": str(outside)})
    with pytest.raises(ValueError, match="PathMustBeAbsolute"):
        srv.sc_consolidate({"import_runs": "relative/run"})
    with pytest.raises(ValueError, match="at least one source"):
        srv.sc_consolidate({})


def test_sc_consolidate_runs_the_import_end_to_end(root, tmp_path, monkeypatch):
    target, sha = _git_target(root)
    prior = _write_prior_run(root / "artifacts", git_commit=sha)
    out = srv.sc_consolidate({"target": str(target), "import_runs": str(prior),
                              "reports_root": str(root / "reports")})
    assert out["exit_code"] == 1 and out["counts"]["total"] == 2
    assert out["validation"] == {"requested": False} or out["validation"]["requested"] is False


def test_scanners_own_artifacts_do_not_dirty_the_consolidate_precondition(tmp_path):
    # 0.3.0 release rehearsal: a default-layout scan writes runs under
    # .security-council/, and consolidate then refused to import the very runs
    # the scanner had just produced ("target checkout is dirty"). The tool's
    # state dir never counts; any OTHER change still does.
    from security_council.workspace import prepare_workspace
    target, _ = _git_target(tmp_path)
    ws = prepare_workspace(target, mode="inplace")
    assert ws.git_info()["dirty"] is False
    (target / ".security-council" / "runs" / "r1").mkdir(parents=True)
    (target / ".security-council" / "runs" / "r1" / "findings.json").write_text("[]")
    assert ws.git_info()["dirty"] is False               # tool artifacts: clean
    (target / "app" / "settings.py").write_text("changed = True\n")
    assert ws.git_info()["dirty"] is True                # source change: dirty
    subprocess.run(["git", "checkout", "--", "app/settings.py"], cwd=target, check=True)
    (target / "evil.py").write_text("x = 1\n")
    assert ws.git_info()["dirty"] is True                # untracked source: dirty
    (target / "evil.py").unlink()
    (target / ".security-council.yaml").write_text("policy: {}\n")
    assert ws.git_info()["dirty"] is True                # config file: dirty


def test_consolidate_works_on_default_layout_runs(tmp_path, capsys):
    # end-to-end shape of the rehearsal failure: default-out scan, then
    # consolidate the run the scanner itself wrote into the target
    target, sha = _git_target(tmp_path)
    prior = target / ".security-council" / "runs" / "20260829_123340"
    prior.parent.mkdir(parents=True, exist_ok=True)
    import shutil as _sh
    _sh.move(str(_write_prior_run(tmp_path, git_commit=sha)), str(prior))
    rc = cli_main(["consolidate", str(target), "--import-run", str(prior),
                   "--out", str(tmp_path / "out"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1 and payload["degradations"] == []
    assert payload["counts"]["total"] == 2


def test_whitespace_adjacent_dirs_cannot_impersonate_the_state_dir(tmp_path):
    # R18 (council): a dir named " .security-council" or ".security-council "
    # is SOURCE, not tool state — whitespace-normalizing the porcelain path
    # would have let a planted leading-space dir read as clean
    from security_council.workspace import prepare_workspace
    target, _ = _git_target(tmp_path)
    ws = prepare_workspace(target, mode="inplace")
    (target / " .security-council").mkdir()
    (target / " .security-council" / "backdoor.py").write_text("evil = 1\n")
    assert ws.git_info()["dirty"] is True
    subprocess.run(["rm", "-rf", str(target / " .security-council")], check=True)
    (target / ".security-council ").mkdir()
    (target / ".security-council " / "b.py").write_text("evil = 2\n")
    assert ws.git_info()["dirty"] is True


def test_subdirectory_target_state_dir_still_counts_dirty_fail_closed(tmp_path):
    # a target that is a SUBDIR of a larger repo: porcelain paths are
    # repo-root-relative, so its state dir does not match the prefix and the
    # tree reads dirty — the residual is fail-closed (consolidate refuses),
    # never fail-open. Documented limitation, not a bypass.
    from security_council.workspace import prepare_workspace
    repo = tmp_path / "mono"
    (repo / "svc" / "api").mkdir(parents=True)
    (repo / "svc" / "api" / "app.py").write_text("x = 1\n")
    subprocess.run(["git", "init", "-q", "."], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@x", "-c", "user.name=t",
                    "commit", "-qm", "seed"], cwd=repo, check=True)
    ws = prepare_workspace(repo / "svc" / "api", mode="inplace")
    (repo / "svc" / "api" / ".security-council" / "runs").mkdir(parents=True)
    (repo / "svc" / "api" / ".security-council" / "runs" / "x.json").write_text("[]")
    assert ws.git_info()["dirty"] is True


def test_failed_git_status_reads_unknown_never_clean(tmp_path, monkeypatch):
    # R18 parting nit: st.ok was unchecked, so a failed `git status` read as
    # dirty=False (clean) — the one fail-open path in the predicate
    from security_council import proc as _proc
    from security_council import workspace as _ws
    target, _ = _git_target(tmp_path)
    ws = _ws.prepare_workspace(target, mode="inplace")
    real = _proc.run_command

    def flaky(cmd, **kw):
        if "status" in cmd:
            return _proc.ProcResult(False, 128, "", "fatal: boom", 0.0, False)
        return real(cmd, **kw)
    monkeypatch.setattr(_ws.proc, "run_command", flaky)
    assert ws.git_info()["dirty"] is None      # unknown -> import gate refuses
