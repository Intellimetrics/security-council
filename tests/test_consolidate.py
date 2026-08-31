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
