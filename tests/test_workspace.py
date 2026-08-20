"""Workspace isolation tests."""
from security_council.workspace import prepare_workspace


def _make_repo(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("print('hi')\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")
    (tmp_path / ".llm-council" / "runs").mkdir(parents=True)
    (tmp_path / ".llm-council" / "runs" / "t.md").write_text("secret AKIA...\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("x\n")
    return tmp_path


def test_copy_excludes_runtime_and_vcs_dirs(tmp_path):
    repo = _make_repo(tmp_path)
    ws = prepare_workspace(repo, mode="copy")
    try:
        assert ws.mode == "copy"
        assert (ws.root / "app" / "x.py").is_file()          # real code copied
        assert not (ws.root / ".git").exists()               # vcs excluded
        assert not (ws.root / ".llm-council").exists()       # runtime excluded (no re-ingest)
        assert not (ws.root / "node_modules").exists()
        assert ws.root != repo                               # a separate copy
    finally:
        ws.cleanup()
    assert not ws.root.exists()                              # cleanup removed the copy


def test_inplace_uses_original(tmp_path):
    repo = _make_repo(tmp_path)
    ws = prepare_workspace(repo, mode="inplace")
    assert ws.root == repo and ws.mode == "inplace"
    ws.cleanup()                                             # no-op, original preserved
    assert repo.exists()


def test_context_manager_cleans_up(tmp_path):
    repo = _make_repo(tmp_path)
    with prepare_workspace(repo, mode="copy") as ws:
        root = ws.root
        assert root.exists()
    assert not root.exists()


def test_writes_into_copy_do_not_touch_original(tmp_path):
    repo = _make_repo(tmp_path)
    ws = prepare_workspace(repo, mode="copy")
    (ws.root / ".llm-council").mkdir()                       # simulate a validator transcript write
    (ws.root / ".llm-council" / "run.md").write_text("stuff\n")
    ws.cleanup()
    assert not (repo / ".llm-council" / "run.md").exists()   # original untouched
