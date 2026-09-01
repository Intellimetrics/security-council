"""R19 A4 (IMS follow-up #2): the PRE-run validation-selection preview.

The 0.3.0 merge landed representative sampling and post-run histograms, but
the operator still learned what `--validate` attempted only AFTER paying for
it. The preview surfaces eligible/selected/cap/strategy and the budget
ceiling BEFORE any panel convenes, from the same `select_for_validation` the
loop and the manifest read (parallel accounting drifts — the boolean-coverage
lesson). The ceiling is the per-finding `--max-cost-usd` fuse × selected: an
upper bound, never a spend prediction.
"""
import json

from security_council.config import DEFAULT_CONFIG
from security_council.orchestrator import run_scan
from security_council.validate import panel
from security_council.validate.council_client import CouncilResult
from tests.test_orchestrator import FakeArm, _finding


# --------------------------------------------------------------------- #
# validation_preview (pure)
# --------------------------------------------------------------------- #

def _findings(n):
    # distinct families, or the same-file CWE-gated overlap tier clusters
    # them into one finding and the counts under test collapse
    fams = ["injection", "xss", "path_traversal", "authz", "deserialization"]
    return [_finding(source_id="semgrep", kind="scanner", vendor="semgrep",
                     rc=f"rc{i}", family=fams[i % len(fams)])
            for i in range(n)]


def test_preview_counts_cap_and_ceiling():
    p = panel.validation_preview(_findings(3), max_findings=2, budget_usd=0.5)
    assert p == {"eligible": 3, "selected": 2, "max_findings": 2,
                 "strategy": panel.SELECTION_STRATEGY,
                 "per_finding_budget_usd": 0.5, "budget_ceiling_usd": 1.0}


def test_preview_without_budget_has_no_ceiling():
    p = panel.validation_preview(_findings(2), max_findings=None, budget_usd=None)
    assert p["selected"] == 2 and p["budget_ceiling_usd"] is None
    # bool is not a price (True == 1 would render "$1.00")
    assert panel.validation_preview(_findings(1), budget_usd=True)["budget_ceiling_usd"] is None


def test_preview_reads_the_same_selection_as_the_loop():
    fs = _findings(5)
    _, selected = panel.select_for_validation(fs, max_findings=3)
    p = panel.validation_preview(fs, max_findings=3, budget_usd=0.5)
    assert p["selected"] == len(selected) and p["eligible"] == 5


# --------------------------------------------------------------------- #
# end-to-end: fires before panels, matches the manifest, prints one line
# --------------------------------------------------------------------- #

def _cfg():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg["decisions"]["require_signatures"] = "warn"
    return cfg


def _scan(tmp_path, findings, *, validate=True, preview=None, runner=None, **kw):
    return run_scan(tmp_path, [FakeArm("semgrep", "scanner", "semgrep", findings)],
                    _cfg(), out_dir=tmp_path / "out", validate=validate,
                    validator_runner=runner, on_validation_preview=preview, **kw)


def test_preview_fires_before_any_panel_convenes(tmp_path):
    events = []

    def runner(prompt, *, cwd, mode="consensus", max_cost_usd=None, timeout=600):
        events.append(("panel", max_cost_usd))
        return CouncilResult(ok=False, degraded=True, results=[], error="fake backend")

    run = _scan(tmp_path, _findings(2), preview=lambda p: events.append(("preview", p)),
                runner=runner, validate_max_findings=1)
    kinds = [k for k, _ in events]
    assert kinds[0] == "preview" and kinds.count("panel") == 1
    p = events[0][1]
    assert p["eligible"] == 2 and p["selected"] == 1
    assert p["budget_ceiling_usd"] == 0.5                # 1 × default $0.50 fuse
    # the record agrees with what was announced (single-sourced arithmetic)
    vm = run.manifest["validation"]
    assert vm["eligible"] == 2 and vm["external_selected"] == 1
    assert vm["budget_ceiling_usd"] == p["budget_ceiling_usd"]


def test_no_validate_means_no_preview_and_no_ceiling(tmp_path):
    fired = []
    run = _scan(tmp_path, _findings(1), validate=False, preview=fired.append)
    assert fired == []
    assert run.manifest["validation"]["budget_ceiling_usd"] is None


def test_preview_fires_even_when_nothing_is_selected(tmp_path):
    fired = []
    run = _scan(tmp_path, [], preview=fired.append)
    assert len(fired) == 1
    assert fired[0]["eligible"] == 0 and fired[0]["budget_ceiling_usd"] == 0.0
    assert run.exit_code == 0                            # visibility, never a gate


def test_summary_renders_the_budget_ceiling(tmp_path):
    def runner(prompt, *, cwd, mode="consensus", max_cost_usd=None, timeout=600):
        return CouncilResult(ok=False, degraded=True, results=[], error="fake backend")
    _scan(tmp_path, _findings(2), runner=runner, validate_max_findings=2)
    md = (tmp_path / "out" / "summary.md").read_text()
    assert "budget ceiling $1.00" in md and "$0.50/finding fuse" in md


def test_cli_prints_one_stderr_line_and_wires_the_callback(tmp_path, capsys, monkeypatch):
    from types import SimpleNamespace

    from security_council import cli

    cli._print_validation_preview({"eligible": 54, "selected": 12, "max_findings": 12,
                                   "strategy": panel.SELECTION_STRATEGY,
                                   "per_finding_budget_usd": 0.5,
                                   "budget_ceiling_usd": 6.0})
    err = capsys.readouterr().err
    assert "12 of 54 eligible" in err and "cap 12" in err
    assert "budget ceiling $6.00" in err and "not a spend prediction" in err
    # no budget -> no dollar claim at all
    cli._print_validation_preview({"eligible": 1, "selected": 1, "max_findings": None,
                                   "strategy": panel.SELECTION_STRATEGY,
                                   "per_finding_budget_usd": None,
                                   "budget_ceiling_usd": None})
    assert "$" not in capsys.readouterr().err

    seen = {}

    def fake_run_scan(target, arms, config, **kw):
        seen.update(kw)
        return SimpleNamespace(run_id="r", out_dir=tmp_path, exit_code=0,
                               manifest={"counts": {}}, degradations=[])
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_build_arms", lambda names, config=None, diff=None: [])
    assert cli.main(["scan", str(tmp_path), "--arms", "semgrep", "--json"]) == 0
    assert seen["on_validation_preview"] is cli._print_validation_preview
