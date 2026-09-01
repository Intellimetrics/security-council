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


def test_extracted_patch_applies_to_a_fresh_copy(tmp_path):
    """The fix lane's `.patch` carried the ABSOLUTE scratch paths git printed
    for `diff --no-index /tmp/.../pristine /tmp/.../work`, so `git apply` and
    `patch -p1` both failed on it ("No such file or directory") — the artifact
    could never be applied, and the vendor verify arm only survived because
    its test monkeypatched `_apply_patch`. The deterministic verify lane is the
    first real consumer, so the patch must be an ordinary -p1 patch."""
    pristine, work, fresh = tmp_path / "pristine", tmp_path / "work", tmp_path / "fresh"
    for d in (pristine, work, fresh):
        (d / "app").mkdir(parents=True)
        (d / "app" / "x.py").write_text("q = bad\n")
    (work / "app" / "x.py").write_text("q = good\n")
    (work / "app" / "new.py").write_text("n = 1\n")           # an added file...
    for d in (pristine, fresh):                                 # ...and a deleted one
        (d / "app" / "gone.py").write_text("g = 0\n")
    diff = patches.extract_patch(pristine, work, ceiling=tmp_path)
    assert "diff --git a/app/x.py b/app/x.py" in diff
    assert "--- a/app/x.py" in diff and "+++ b/app/x.py" in diff
    assert "diff --git a/app/new.py b/app/new.py" in diff and "+++ b/app/new.py" in diff
    assert "diff --git a/app/gone.py b/app/gone.py" in diff and "--- a/app/gone.py" in diff
    assert "pristine" not in diff and "work/" not in diff
    assert patches.validate_patch(diff).files == ["app/gone.py", "app/new.py", "app/x.py"]
    patch_file = tmp_path / "fix.patch"
    patch_file.write_text(diff)
    ok, err = patches.apply_patch(fresh, patch_file)
    assert ok, err
    assert (fresh / "app" / "x.py").read_text() == "q = good\n"
    assert (fresh / "app" / "new.py").read_text() == "n = 1\n"
    assert not (fresh / "app" / "gone.py").exists()


def test_apply_patch_fails_closed_and_touches_nothing_on_a_bad_hunk(tmp_path):
    fresh = tmp_path / "fresh"
    (fresh / "app").mkdir(parents=True)
    (fresh / "app" / "x.py").write_text("q = something_else\n")
    patch_file = tmp_path / "fix.patch"
    patch_file.write_text("diff --git a/app/x.py b/app/x.py\n--- a/app/x.py\n+++ b/app/x.py\n"
                          "@@ -1 +1 @@\n-q = bad\n+q = good\n")
    ok, err = patch_file and patches.apply_patch(fresh, patch_file)
    assert not ok and err
    assert (fresh / "app" / "x.py").read_text() == "q = something_else\n"


def test_apply_patch_refuses_paths_that_escape_the_tree(tmp_path):
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    (tmp_path / "victim.txt").write_text("keep\n")
    patch_file = tmp_path / "escape.patch"
    patch_file.write_text("diff --git a/../victim.txt b/../victim.txt\n"
                          "--- a/../victim.txt\n+++ b/../victim.txt\n"
                          "@@ -1 +1 @@\n-keep\n+owned\n")
    ok, _ = patches.apply_patch(fresh, patch_file)
    assert not ok
    assert (tmp_path / "victim.txt").read_text() == "keep\n"


def test_rel_keeps_a_genuine_work_directory_in_the_path():
    assert patches._rel("src/work/x.py") == "src/work/x.py"
    assert patches._rel("/pristine/x.py") == "pristine/x.py"



# --------------------------------------------------------------------------- #
# R14 follow-ups (council, non-blocking): traditional headers, deletions, -p
# --------------------------------------------------------------------------- #

def test_traditional_patch_headers_reach_the_refuse_list():
    """VP-1: a `---/+++`-only patch used to yield no files, so the REFUSE list
    never saw `.security-council/…`."""
    from security_council.patches import validate_patch
    trad = "--- .security-council/x\n+++ .security-council/x\n@@ -0,0 +1 @@\n+z\n"
    r = validate_patch(trad)
    assert r.files == [".security-council/x"] and r.refused and r.ok is False
    plain = "--- app/x.py\t2026\n+++ app/x.py\t2026\n@@ -1 +1 @@\n-a\n+b\n"
    r = validate_patch(plain)
    assert r.files == ["app/x.py"] and r.ok
    new = "--- /dev/null\n+++ b/app/new.py\n@@ -0,0 +1 @@\n+x\n"
    assert validate_patch(new).files == ["app/new.py"]


def test_deletion_is_flagged_for_review():
    from security_council.patches import validate_patch
    d = ("diff --git a/app/x.py b/app/x.py\ndeleted file mode 100644\n--- a/app/x.py\n"
         "+++ /dev/null\n@@ -1 +0,0 @@\n-x\n")
    r = validate_patch(d)
    assert r.ok and "deletes app/x.py" in r.review_required


def test_strip_level_follows_the_headers(tmp_path):
    """A git-format new-file patch must never be applied with -p0 (it would
    create `b/X`); a plain patch must never be applied with -p1."""
    import shutil
    from security_council.patches import apply_patch
    if not shutil.which("git"):
        import pytest
        pytest.skip("git required")
    work = tmp_path / "w"
    (work / "sub").mkdir(parents=True)
    (work / "sub" / "x.py").write_text("a\n")
    (work / "x.py").write_text("a\n")                    # same-named file at the root
    gitfmt = tmp_path / "g.patch"
    gitfmt.write_text("diff --git a/nope/new.py b/nope/new.py\nnew file mode 100644\n"
                      "--- /dev/null\n+++ b/nope/new.py\n@@ -0,0 +1 @@\n+x\n")
    ok, err = apply_patch(work, gitfmt)
    assert ok and (work / "nope" / "new.py").is_file() and not (work / "b").exists()
    plain = tmp_path / "p.patch"
    plain.write_text("--- sub/x.py\n+++ sub/x.py\n@@ -1 +1 @@\n-a\n+b\n")
    ok, err = apply_patch(work, plain)
    assert ok and (work / "sub" / "x.py").read_text() == "b\n"
    assert (work / "x.py").read_text() == "a\n"           # -p1 was never tried


def test_extract_patch_excludes_agent_created_cache_junk(tmp_path):
    # B1 live-found: codex under workspace-write ran the code and left
    # __pycache__/*.pyc, which git diff reports as a binary hunk and the
    # validator then refuses. The diff must exclude generated junk.
    from security_council import patches
    pris = tmp_path / "pristine"
    work = tmp_path / "work"
    for d in (pris, work):
        (d / "app").mkdir(parents=True)
        (d / "app" / "x.py").write_text("q = 'SELECT ' + name\n")
    # the agent edits the source AND leaves a compiled cache file behind
    (work / "app" / "x.py").write_text("q = db.execute('SELECT ...', [name])\n")
    (work / "app" / "__pycache__").mkdir()
    (work / "app" / "__pycache__" / "x.cpython-311.pyc").write_bytes(b"\x00\x01\x02BINARY\x00")
    diff = patches.extract_patch(pris, work, ceiling=tmp_path)
    assert "db.execute" in diff                     # the real edit is present
    assert "Binary files" not in diff and "__pycache__" not in diff   # junk excluded
    rep = patches.validate_patch(diff, target_files={"app/x.py"})
    assert rep.ok and not rep.refused               # no longer refused for a binary hunk
