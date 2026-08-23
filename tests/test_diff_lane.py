"""M-V1 diff lane: change-scoped scanning stays scope-coherent, is marked
partial end to end, and cannot corrupt a baseline."""
import pathlib

from security_council.arms.base import DiffSpec
from security_council.arms.claude_security import build_prompt
from security_council.arms.codex_security import CodexSecurityArm
from security_council.arms.registry import build_arm
from security_council.cli import main as cli_main
from security_council.decisions import DecisionStore, annotate_baseline
from security_council.jsonio import to_dict
from security_council.orchestrator import run_scan
from tests.test_orchestrator import DEFAULT_CONFIG, FakeArm, _finding as orch_finding


# --------------------------------------------------------------------------- #
# arm command / prompt shaping
# --------------------------------------------------------------------------- #


def test_codex_cmd_committed_diff():
    arm = CodexSecurityArm(diff=DiffSpec(kind="diff", base="origin/main", head="HEAD"))
    cmd = arm._cmd(["codex-security"], pathlib.Path("/t"), "/out")
    assert cmd[cmd.index("--diff") + 1] == "origin/main"
    assert cmd[cmd.index("--head") + 1] == "HEAD"
    assert "--working-tree" not in cmd


def test_codex_cmd_working_tree():
    arm = CodexSecurityArm(diff=DiffSpec(kind="working_tree", base="HEAD"))
    cmd = arm._cmd(["codex-security"], pathlib.Path("/t"), "/out")
    assert "--working-tree" in cmd and cmd[cmd.index("--base") + 1] == "HEAD"
    assert "--diff" not in cmd


def test_codex_full_scan_has_no_diff_flags():
    cmd = CodexSecurityArm()._cmd(["codex-security"], pathlib.Path("/t"), "/out")
    assert "--diff" not in cmd and "--working-tree" not in cmd


def test_claude_prompt_scan_changes():
    p = build_prompt(effort="medium", scope=None, diff=DiffSpec(kind="diff", base="origin/main"))
    assert "/claude-security scan-changes --base origin/main" in p
    assert "significant number of tokens" in p          # gate-collapse acknowledgement kept
    # full scan prompt is unchanged
    assert "scan-codebase" in build_prompt(effort="low", scope=None)


def test_registry_threads_diff_to_dedicated_arms():
    spec = DiffSpec(kind="diff", base="b")
    assert build_arm("codex-security", diff=spec).diff is spec
    assert build_arm("claude-security", diff=spec).diff is spec
    # scanner arms have no diff support and must not choke on the kwarg
    assert getattr(build_arm("semgrep", diff=spec), "supports_diff", False) is False


# --------------------------------------------------------------------------- #
# orchestrator: scope coherence + partial marking
# --------------------------------------------------------------------------- #


class FakeDiffArm(FakeArm):
    supports_diff = True

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.diff = None

    def run(self, target, out_dir, *, run_id, collected_at):
        r = super().run(target, out_dir, run_id=run_id, collected_at=collected_at)
        r.coverage["scan_scope"] = self.diff.as_dict() if self.diff else {"kind": "full"}
        return r


def _run(arms, tmp_path, diff=None, **policy):
    cfg = {**DEFAULT_CONFIG, "policy": {**DEFAULT_CONFIG["policy"], **policy}}
    return run_scan(tmp_path, arms, cfg, out_dir=tmp_path / "out", diff=diff)


def test_diff_run_skips_non_diff_arms_and_marks_partial(tmp_path):
    diff_arm = FakeDiffArm("codex-security", "agent_cli", "codex",
                           [orch_finding(source_id="codex-security", kind="agent_cli",
                                         vendor="codex", rc="d")])
    diff_arm.diff = DiffSpec(kind="diff", base="origin/main")
    plain = FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="x")])
    run = _run([diff_arm, plain], tmp_path, diff=DiffSpec(kind="diff", base="origin/main"))
    # only the diff-capable arm ran; the scanner is an informational skip, not a failure
    assert [a["name"] for a in run.manifest["arms"]] == ["codex-security"]
    skips = [d for d in run.manifest["degradations"] if d["kind"] == "diff_skipped"]
    assert len(skips) == 1 and skips[0]["arm"] == "semgrep"
    assert run.manifest["scan_scope"] == {"kind": "diff", "base": "origin/main", "head": None}
    assert run.exit_code in (0, 1)          # a skipped-by-design arm does not degrade the run
    assert "⚠ partial — change-scoped scan" in (run.out_dir / "summary.md").read_text()


def test_full_run_is_not_partial(tmp_path):
    arm = FakeArm("semgrep", "scanner", "semgrep",
                  [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc="f")])
    run = _run([arm], tmp_path)
    assert run.manifest["scan_scope"] == {"kind": "full"}
    assert "change-scoped scan" not in (run.out_dir / "summary.md").read_text()


# --------------------------------------------------------------------------- #
# baseline safety under partial scans
# --------------------------------------------------------------------------- #


def _bl_row(rc):
    f = orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep", rc=rc)
    return to_dict(f), f


def test_annotate_baseline_partial_never_marks_absent(tmp_path):
    store = DecisionStore(tmp_path)
    old_rows = [_bl_row("a")[0], _bl_row("gone")[0]]
    store.set_baseline(old_rows, run_id="r0", now_iso="2026-08-23T00:00:00Z")
    present = _bl_row("a")[1]                            # only "a" is in the diff scope
    full = annotate_baseline([present], store.load_baseline(), partial=False)
    partial = annotate_baseline([present], store.load_baseline(), partial=True)
    assert full["absent"] == 1 and full["partial"] is False           # full scan: "gone" resolved
    assert partial["absent"] == 0 and partial["out_of_scope"] == 1    # diff scan: cannot conclude


def test_baseline_set_refuses_partial_run(tmp_path, capsys):
    diff_arm = FakeDiffArm("codex-security", "agent_cli", "codex",
                           [orch_finding(source_id="codex-security", kind="agent_cli",
                                         vendor="codex", rc="p")])
    diff_arm.diff = DiffSpec(kind="diff", base="origin/main")
    run = _run([diff_arm], tmp_path, diff=DiffSpec(kind="diff", base="origin/main"))
    assert run.manifest["scan_scope"]["kind"] == "diff"
    rc = cli_main(["baseline", "set", "--run", str(run.out_dir), "--target", str(tmp_path),
                   "--operator", "clindell"])
    assert rc == 2 and "partial" in capsys.readouterr().err
    assert DecisionStore(tmp_path / ".security-council").load_baseline() is None


# --------------------------------------------------------------------------- #
# CLI guard
# --------------------------------------------------------------------------- #


def test_cli_diff_requires_diff_capable_arm(tmp_path, capsys):
    (tmp_path / "f.py").write_text("x = 1\n")
    rc = cli_main(["scan", str(tmp_path), "--arms", "semgrep", "--diff", "origin/main"])
    assert rc == 2 and "diff-capable arm" in capsys.readouterr().err
