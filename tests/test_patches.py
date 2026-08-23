"""M-V4a patch validation + redaction: refuse agent/VCS-meta files, symlink/mode
entries, binary hunks; redact secrets on both hunk sides; safe git extraction."""

from security_council import patches


def _diff(*files: str) -> str:
    out = []
    for f in files:
        out += [f"diff --git a/{f} b/{f}", "index 000..111 100644",
                "--- a/" + f, "+++ b/" + f, "@@ -1 +1 @@", "-old", "+new"]
    return "\n".join(out) + "\n"


def test_accepts_ordinary_code_patch():
    rep = patches.validate_patch(_diff("app/routes.py"))
    assert rep.ok and rep.files == ["app/routes.py"] and rep.refused == []
    assert rep.sha256


def test_refuses_agent_and_vcs_meta_files():
    for f in (".claude/settings.json", "CLAUDE.md", ".mcp.json", ".git/config",
              ".gitmodules", ".gitattributes", ".github/workflows/ci.yml",
              ".security-council/decisions/x.json", ".codex/config.toml"):
        rep = patches.validate_patch(_diff(f))
        assert not rep.ok and rep.refused, f"{f} should be refused"


def test_flags_review_paths():
    rep = patches.validate_patch(_diff("tests/test_app.py"))
    assert rep.ok and any("test" in r for r in rep.review_required)
    rep2 = patches.validate_patch(_diff("poetry.lock"))
    assert rep2.ok and rep2.review_required


def test_refuses_symlink_and_binary():
    sym = ("diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n"
           "@@ -0,0 +1 @@\n+/etc/passwd\n")
    assert not patches.validate_patch(sym).ok
    binp = "diff --git a/x.png b/x.png\nBinary files a/x.png and b/x.png differ\n"
    assert not patches.validate_patch(binp).ok


def test_mode_change_is_review_required():
    m = ("diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n"
         "--- a/run.sh\n+++ b/run.sh\n@@ -1 +1 @@\n-x\n+y\n")
    rep = patches.validate_patch(m)
    assert rep.ok and any("mode" in r for r in rep.review_required)


def test_redacts_secret_on_both_sides_for_secrets_family():
    d = ("diff --git a/app/settings.py b/app/settings.py\n--- a/app/settings.py\n"
         "+++ b/app/settings.py\n@@ -1,2 +1,2 @@\n"
         "-AWS_KEY = 'AKIAIOSFODNN7EXAMPLEKEY123'\n"
         "+AWS_KEY = os.environ['AWS_KEY']\n")
    rep = patches.validate_patch(d, secret_family=True)
    assert rep.redacted and rep.secret_in_patch
    assert "AKIAIOSFODNN7EXAMPLEKEY123" not in rep.diff
    assert "<redacted secret sha256:" in rep.diff


def test_redacts_by_path_heuristic_even_without_family_flag():
    d = ("diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n"
         "-TOKEN=deadbeefdeadbeefdeadbeef0000\n+TOKEN=${TOKEN}\n")
    rep = patches.validate_patch(d, secret_family=False)
    assert rep.redacted and "deadbeefdeadbeefdeadbeef0000" not in rep.diff


def test_ordinary_patch_not_redacted():
    rep = patches.validate_patch(_diff("app/routes.py"))
    assert not rep.redacted and not rep.secret_in_patch


def test_extract_patch_neutralizes_git_config(tmp_path):
    # a planted malicious .git/config must not execute during extraction (MV4-10)
    pristine = tmp_path / "pristine"
    work = tmp_path / "work"
    for d in (pristine, work):
        (d / "app").mkdir(parents=True)
        (d / "app" / "x.py").write_text("old\n")
    (work / "app" / "x.py").write_text("new\n")
    canary = tmp_path / "sc-escape"
    gitdir = work / ".git"
    gitdir.mkdir()
    (gitdir / "config").write_text(f"[core]\n\tfsmonitor = touch {canary}\n")
    diff = patches.extract_patch(pristine, work, ceiling=tmp_path)
    assert "new" in diff and "old" in diff       # the real change is captured
    assert not canary.exists()                    # fsmonitor command did NOT run


def test_out_of_scope_hunk_flagged():
    rep = patches.validate_patch(_diff("app/a.py", "app/b.py"),
                                 target_files={"app/a.py"})
    assert rep.ok and any("out_of_scope" in r for r in rep.review_required)
