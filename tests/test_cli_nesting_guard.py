"""R6/MV4-4: decision-store CLI writes are human actions and must be refused
when running nested inside a security-council arm (a nested/prompt-injected
agent must not be able to forge a suppression, outcome mark, or baseline)."""
import json

from security_council.cli import main as cli_main
from tests.test_decisions import _finding  # noqa: F401 - ensures import graph
from tests.test_orchestrator import FakeArm, _finding as orch_finding, _run as orch_run


def _run_with_finding(tmp_path):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="n")])]
    run = orch_run(arms, tmp_path)
    [row] = json.loads((run.out_dir / "findings.json").read_text())
    return run, row["id"]


def test_outcome_mark_refused_when_nested(tmp_path, capsys, monkeypatch):
    run, fid = _run_with_finding(tmp_path)
    monkeypatch.setenv("SECURITY_COUNCIL_NESTED", "1")
    rc = cli_main(["outcome", "mark", fid, "--verdict", "fp", "--operator", "x",
                   "--run", str(run.out_dir), "--target", str(tmp_path)])
    assert rc == 2 and "refused inside a security-council arm" in capsys.readouterr().err
    # and nothing was written to the decision store
    assert not (tmp_path / ".security-council" / "decisions").exists()


def test_suppress_and_baseline_refused_when_nested(tmp_path, capsys, monkeypatch):
    run, fid = _run_with_finding(tmp_path)
    monkeypatch.setenv("SECURITY_COUNCIL_NESTED", "1")
    assert cli_main(["suppress", fid, "--operator", "x", "--justification", "j",
                     "--run", str(run.out_dir), "--target", str(tmp_path)]) == 2
    assert cli_main(["baseline", "set", "--run", str(run.out_dir),
                     "--target", str(tmp_path), "--operator", "x"]) == 2
    err = capsys.readouterr().err
    assert err.count("refused inside a security-council arm") == 2


def test_writes_allowed_when_not_nested(tmp_path, monkeypatch):
    run, fid = _run_with_finding(tmp_path)
    monkeypatch.delenv("SECURITY_COUNCIL_NESTED", raising=False)
    assert cli_main(["outcome", "mark", fid, "--verdict", "fp", "--operator", "clindell",
                     "--run", str(run.out_dir), "--target", str(tmp_path)]) == 0
    assert (tmp_path / ".security-council" / "decisions").exists()


def test_mcp_decision_handlers_refuse_when_nested(tmp_path, monkeypatch):
    """R6/MV4-12: the MCP decision-write handlers guard too, symmetric w/ CLI."""
    import pytest

    from security_council import mcp_server as srv
    monkeypatch.setenv(srv.ROOT_ENV, str(tmp_path))
    monkeypatch.setenv(srv.NESTED_ENV, "1")
    for fn, args in ((srv.sc_suppress, {"finding_id": "x", "operator": "o", "justification": "j"}),
                     (srv.sc_outcome_mark, {"finding_id": "x", "verdict": "fp", "operator": "o"}),
                     (srv.sc_baseline, {"action": "set", "operator": "o"})):
        with pytest.raises(ValueError, match="refused inside a security-council arm"):
            fn(args)
    # read-only baseline show still works when nested
    assert srv.sc_baseline({"action": "show"})["set"] is False
