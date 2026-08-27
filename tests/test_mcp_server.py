"""MCP server handlers (transport-independent): root scoping, nesting guard,
and the sc_* tool surface over a real orchestrated run — no `mcp` SDK needed."""
import json

import pytest

from security_council import mcp_server as srv
from tests.test_orchestrator import FakeArm, _allow_unsigned, _finding as orch_finding

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
    assert "boom" in [r for r in rows if r["arm"] == "bad"][0]["detail"]


def test_tool_registry_schemas_are_complete(root):
    names = [t[0] for t in srv.TOOLS]
    assert names == ["sc_scan", "sc_doctor", "sc_report", "sc_last_run", "sc_baseline",
                     "sc_suppress", "sc_outcome_mark", "sc_decisions_verify", "sc_serve",
                     "sc_config"]
    for name, desc, schema, fn in srv.TOOLS:
        assert desc and schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert callable(fn) and srv.HANDLERS[name] is fn