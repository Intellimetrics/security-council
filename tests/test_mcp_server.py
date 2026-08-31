"""MCP server handlers (transport-independent): root scoping, nesting guard,
and the sc_* tool surface over a real orchestrated run — no `mcp` SDK needed."""
import json
from types import SimpleNamespace

import pytest

from security_council import mcp_server as srv
from tests.test_orchestrator import FakeArm, _allow_unsigned
from tests.test_orchestrator import _finding as orch_finding

NOW = "2026-08-22T00:00:00Z"


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv(srv.ROOT_ENV, str(tmp_path))
    monkeypatch.delenv(srv.NESTED_ENV, raising=False)
    return tmp_path


def _fake_arms(monkeypatch, rc="mcp"):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner",
                                  vendor="semgrep", rc=rc)])]
    monkeypatch.setattr(srv, "_arms", lambda names, config: arms)


# --------------------------------------------------------------------------- #
# guards
# --------------------------------------------------------------------------- #


def test_relative_and_escaping_paths_refused(root):
    with pytest.raises(ValueError, match="PathMustBeAbsolute"):
        srv.sc_config({"target": "subdir"})
    with pytest.raises(ValueError, match="ProjectRootMismatch"):
        srv.sc_config({"target": "/tmp"})


def test_nesting_guard_refuses_sc_scan(root, monkeypatch):
    monkeypatch.setenv(srv.NESTED_ENV, "1")
    with pytest.raises(ValueError, match="NestedScanRefused"):
        srv.sc_scan({})
    # read-only tools still work when nested
    assert srv.sc_config({})["config"]["policy"]["auto_suppress"] is False


def test_unknown_tool_and_unknown_arm(root):
    with pytest.raises(ValueError, match="Unknown tool"):
        srv.call_tool("sc_nope", {})
    with pytest.raises(ValueError, match="unknown arms"):
        srv.sc_scan({"arms": "not-an-arm"})


def test_operator_config_profile_and_deep_controls(root, monkeypatch):
    cfg = root / "operator.yaml"
    cfg.write_text("arms:\n  options:\n    claude:\n      max_budget_usd: 9\n")
    reports = root / "portfolio-runs"
    captured = {}

    def fake_arms(names, config):
        captured["names"] = names
        captured["config"] = config
        return [FakeArm("claude", "agent_cli", "claude", [])]

    def fake_run_scan(target, arms, config, **kwargs):
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            run_id="r1", out_dir=reports / "r1", exit_code=0, degradations=[],
            manifest={"counts": {"total": 0, "by_severity": {}, "by_state": {}},
                      "disposition_actions": {}, "baseline_delta": None, "reports": []})

    monkeypatch.setattr(srv, "_arms", fake_arms)
    import security_council.orchestrator as orch
    monkeypatch.setattr(orch, "run_scan", fake_run_scan)

    out = srv.sc_scan({"target": str(root), "config_path": str(cfg), "profile": "deep",
                       "arms": "claude,agy", "deep": True, "reports_root": str(reports),
                       "min_arms": 2, "validate_budget": 4, "sbom": True,
                       "validator_current": "codex",
                       "validator_participants": "claude,antigravity",
                       "validator_timeout": 300})
    assert out["exit_code"] == 0
    assert captured["names"] == ["claude", "agy"]
    assert captured["config"]["_source"]["kind"] == "explicit"
    assert captured["config"]["policy"]["min_arms_ok"] == 2
    assert captured["config"]["reports"]["outdir"] == str(reports)
    assert captured["config"]["arms"]["options"]["claude"] == {
        "max_budget_usd": 9, "effort": "high"}
    assert captured["config"]["arms"]["options"]["agy"]["effort"] == "high"
    assert captured["kwargs"]["validate"] is True
    assert captured["kwargs"]["validate_budget_usd"] == 4
    assert captured["kwargs"]["validator_timeout"] == 300
    runner = captured["kwargs"]["validator_runner"]
    assert runner.keywords["current"] == "codex"
    assert runner.keywords["participants"] == ("claude", "antigravity")
    assert captured["kwargs"]["analysis_arms"][0].name == "sbom"

    with pytest.raises(ValueError, match="mutually exclusive"):
        srv.sc_scan({"config_path": str(cfg), "ignore_repo_config": True})
    with pytest.raises(ValueError, match="exclude validator_current"):
        srv.sc_scan({"validator_current": "codex",
                     "validator_participants": "claude,codex"})


# --------------------------------------------------------------------------- #
# the tool surface over one real scan
# --------------------------------------------------------------------------- #


def test_scan_report_lastrun_baseline_suppress_flow(root, monkeypatch):
    _fake_arms(monkeypatch)
    _allow_unsigned(root)          # this flow records UNSIGNED decisions
    out = srv.call_tool("sc_scan", {"arms": "semgrep"})
    assert out["exit_code"] == 1 and out["counts"]["total"] == 1

    last = srv.sc_last_run({})
    assert last["found"] and last["run_id"] == out["run_id"]

    rep = srv.sc_report({"run_dir": out["out_dir"], "format": "md"})
    assert "# security-council report" in rep["markdown"]
    em = srv.sc_report({"run_dir": out["out_dir"], "format": "emass",
                        "app_name": "app", "app_version": "1"})
    assert em["body"][0]["applicationFindings"][0]["cweId"] == "89"
    with pytest.raises(ValueError, match="app_name"):
        srv.sc_report({"run_dir": out["out_dir"], "format": "emass"})

    assert srv.sc_baseline({})["set"] is False
    assert srv.sc_baseline({"action": "set", "operator": "clindell"})["findings"] == 1
    assert srv.sc_baseline({})["set"] is True

    [row] = json.loads((root / ".security-council" / "runs" / out["run_id"]
                        / "findings.json").read_text())
    sup = srv.sc_suppress({"finding_id": row["id"], "operator": "clindell",
                           "justification": "fixture"})
    assert sup["recorded"] == "suppressed"
    mark = srv.sc_outcome_mark({"finding_id": row["id"], "verdict": "fp",
                                "operator": "clindell"})
    assert mark["marked"] == "false_positive"

    # rescan: the stored suppression reapplies and the gate clears
    out2 = srv.sc_scan({"arms": "semgrep", "gate_baseline": "new"})
    assert out2["exit_code"] == 0
    assert srv.sc_report({"run_dir": out2["out_dir"]})["counts"]["by_severity"] == {"high": 1}


def test_sc_scan_requires_operator_fields(root, monkeypatch):
    _fake_arms(monkeypatch)
    out = srv.sc_scan({"arms": "semgrep"})
    [row] = json.loads((root / ".security-council" / "runs" / out["run_id"]
                        / "findings.json").read_text())
    with pytest.raises(ValueError, match="operator and justification"):
        srv.sc_suppress({"finding_id": row["id"]})
    with pytest.raises(ValueError, match="operator is required"):
        srv.sc_outcome_mark({"finding_id": row["id"], "verdict": "fp"})


def test_sc_doctor_reports_every_arm_without_raising(root, monkeypatch):
    import security_council.arms.registry as reg
    monkeypatch.setattr(reg, "known_arms", lambda: ["good", "bad"])

    class _Probe:
        def __init__(self, ok):
            self._ok = ok

        def available(self):
            if not self._ok:
                raise RuntimeError("boom")
            return True, "ready"
    monkeypatch.setattr(reg, "build_arm", lambda n, options=None: _Probe(n == "good"))
    rows = srv.sc_doctor({})["arms"]
    assert {r["arm"]: r["ready"] for r in rows} == {"good": True, "bad": False}
    assert "boom" in next(r for r in rows if r["arm"] == "bad")["detail"]


def test_tool_registry_schemas_are_complete(root):
    names = [t[0] for t in srv.TOOLS]
    assert names == ["sc_scan", "sc_consolidate", "sc_doctor", "sc_report", "sc_last_run",
                     "sc_baseline", "sc_suppress", "sc_outcome_mark", "sc_decisions_verify",
                     "sc_serve", "sc_config"]
    for name, desc, schema, fn in srv.TOOLS:
        assert desc and schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert callable(fn) and srv.HANDLERS[name] is fn


def test_sc_report_parity_system_name_csv_and_bundle(root, monkeypatch):
    _fake_arms(monkeypatch)
    out = srv.sc_scan({"arms": "semgrep"})
    run_dir = out["out_dir"]
    # csv format
    csv_out = srv.sc_report({"run_dir": run_dir, "format": "csv"})
    assert csv_out["csv"].splitlines()[0].startswith('"finding_id"')
    # system identity flows into the HTML exactly like `report --system-name`
    page = srv.sc_report({"run_dir": run_dir, "format": "html",
                          "system_name": "Investigative Management System"})
    assert "Investigative Management System" in page["html"]
    # bundle writes the audience set into <run_dir>/exports and lists it
    bundle = srv.sc_report({"run_dir": run_dir, "bundle": "triage"})
    assert sorted(bundle["written"]) == ["findings.csv", "summary.html", "summary.md"]
    assert bundle["out_dir"].endswith("exports")
    with pytest.raises(ValueError, match="unknown bundle"):
        srv.sc_report({"run_dir": run_dir, "bundle": "everything"})
