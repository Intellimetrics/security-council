"""Patch extraction, validation, and redaction for the fix lane (M-V4a, R6).

The orchestrator — never the vendor agent — produces the `.patch`: it diffs a
PRISTINE copy against the agent's WORK copy with git config fully neutralized,
from a non-repo cwd, so a malicious `.git/config` the agent planted
(`core.fsmonitor`, `diff.*.textconv`) cannot execute during extraction (MV4-10).

The validator then treats the diff as hostile: it REFUSES patches that touch
agent/VCS-meta config (a fix laundering into the reviewer's tooling), symlink
or mode-change entries, or paths outside the repo; and it REDACTS secret
material on both `+` and `-` sides (a "fix" can move a key onto a `+` line).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# A fix for a code finding never legitimately edits these — refuse, don't flag.
REFUSE_PATH_RES = [re.compile(p) for p in (
    r"(^|/)\.git($|/)", r"(^|/)\.security-council($|/)",
    r"(^|/)\.claude($|/)", r"(^|/)CLAUDE\.md$", r"(^|/)AGENTS\.md$", r"(^|/)GEMINI\.md$",
    r"(^|/)\.mcp\.json$", r"(^|/)\.codex($|/)", r"(^|/)\.cursor($|/)",
    r"(^|/)\.vscode($|/)", r"(^|/)\.envrc$", r"(^|/)\.pre-commit-config\.yaml$",
    r"(^|/)conftest\.py$", r"(^|/)\.gitmodules$", r"(^|/)\.gitattributes$",
    r"(^|/)\.github($|/)",
)]
# these get a review_required flag (legitimate sometimes, high-leverage always)
REVIEW_PATH_RES = [re.compile(p) for p in (
    r"(^|/)\.gitlab-ci\.yml$", r"(^|/).*\.lock$", r"(^|/)(package-lock\.json|poetry\.lock|"
    r"Cargo\.lock|go\.sum|yarn\.lock)$", r"(^|/)Makefile$", r"(^|/).*\.(sh|bash)$",
    r"(^|/)tests?/", r"(^|/)test_.*\.py$", r"(^|/).*_test\.(py|js|ts|go)$",
)]
SECRET_PATH_RES = [re.compile(p, re.IGNORECASE) for p in (
    r"\.env", r"\.pem$", r"\.key$", r"\.p12$", r"\.jks$", r"\.pfx$",
    r"secret", r"credential", r"\.netrc$", r"id_rsa", r"id_ed25519",
)]
# secrets-family CWEs — patches for these redact both hunk sides regardless
SECRET_CWES = frozenset({"CWE-798", "CWE-259", "CWE-321", "CWE-312", "CWE-540"})

_GIT_NEUTRAL_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false",
    "GIT_ALLOW_PROTOCOL": "none", "HOME": "/dev/null",
}
_HIGH_ENTROPY = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


@dataclass
class PatchReport:
    ok: bool
    diff: str                       # possibly redacted
    files: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)       # -> reject the whole patch
    review_required: list[str] = field(default_factory=list)
    redacted: bool = False
    secret_in_patch: bool = False
    sha256: str = ""


_DIFF_EXCLUDE_DIRS = (".git", ".hg", ".svn", ".security-council", ".llm-council")


def extract_patch(pristine: Path, work: Path, *, ceiling: Path) -> str:
    """`git diff --no-index` between CONTENT snapshots of the two trees (VCS
    metadata dirs stripped), run from a non-repo cwd with git config neutralized.
    Snapshotting excludes `.git` etc. so a repo the fix agent created/planted can
    never appear in the patch or execute config during extraction (MV4-10).

    The diff is taken with RELATIVE arguments and the snapshot prefixes are
    stripped, so the result is an ordinary `-p1` patch (`a/app/x.py`) that
    `git apply` / `patch -p1` accept against a copy of the repository. It used
    to carry the absolute scratch paths, which nothing could apply — the
    deterministic verify lane is the first consumer that actually applies it.
    """
    import tempfile
    snap = Path(tempfile.mkdtemp(prefix="sc-diff-", dir=str(ceiling)))
    try:
        ign = shutil.ignore_patterns(*_DIFF_EXCLUDE_DIRS)
        shutil.copytree(pristine, snap / "pristine", ignore=ign, symlinks=True,
                        ignore_dangling_symlinks=True)
        shutil.copytree(work, snap / "work", ignore=ign, symlinks=True,
                        ignore_dangling_symlinks=True)
        env = {**os.environ, **_GIT_NEUTRAL_ENV, "GIT_CEILING_DIRECTORIES": str(ceiling)}
        git = shutil.which("git") or "git"
        r = subprocess.run([git, "-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null",
                            "diff", "--no-index", "--no-ext-diff", "--no-color",
                            "pristine", "work"],
                           capture_output=True, text=True, cwd=str(snap), env=env,
                           timeout=120, check=False)
        # git diff --no-index exits 1 when there are differences — that's success here
        return _strip_snapshot_prefixes(r.stdout)
    finally:
        shutil.rmtree(snap, ignore_errors=True)


# `git diff --no-index pristine work` names paths a/pristine/X and b/work/X
# (for an added or deleted file BOTH sides carry the surviving tree's prefix);
# these turn the header lines into the plain a/X b/X form of a -p1 patch.
_SNAP = r"(?:pristine|work)/"
_SNAPSHOT_HEADER_RES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r'^(diff --git "?a/)' + _SNAP), r"\1"),
    (re.compile(r'^(diff --git "?a/[^\n]*? "?b/)' + _SNAP), r"\1"),
    (re.compile(r'^(--- "?a/)' + _SNAP), r"\1"),
    (re.compile(r'^(\+\+\+ "?b/)' + _SNAP), r"\1"),
    (re.compile(r"^((?:rename|copy) (?:from|to) )" + _SNAP), r"\1"),
    (re.compile(r"^(Binary files )" + _SNAP + r"(.*) and " + _SNAP + r"(.*)( differ)$"),
     r"\1\2 and \3\4"),
)


def _strip_snapshot_prefixes(diff: str) -> str:
    out = []
    for line in diff.splitlines(keepends=True):
        for rx, repl in _SNAPSHOT_HEADER_RES:
            line = rx.sub(repl, line, count=1)
        out.append(line)
    return "".join(out)


def apply_patch(work: Path, patch_path: Path, *, timeout: int = 120) -> tuple[bool, str]:
    """Apply a unified diff to a SCRATCH tree — never the user's — with git
    config neutralized. `git apply` is atomic (no file is touched unless every
    hunk applies) and refuses paths that escape the tree (no `--unsafe-paths`).
    `-p1` (the `a/ b/` form every git-produced patch has) is tried first, then
    `-p0` for a plain `diff -u` without prefixes. Returns (applied, error)."""
    git = shutil.which("git") or "git"
    work = Path(work)
    env = {**os.environ, **_GIT_NEUTRAL_ENV, "GIT_CEILING_DIRECTORIES": str(work.parent)}
    err = ""
    # R14 follow-up: pick the strip level from the patch's own headers instead
    # of trying both — `-p0` on a git-format new-file patch would create `b/X`
    # and report "applied"; `-p1` on a plain `--- app/x.py` patch would strip a
    # real directory and could hit a same-named file at the root.
    try:
        text = Path(patch_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    strips = ("-p1",) if _GIT_PREFIX_RE.search(text) else ("-p0",)
    for strip in strips:
        r = subprocess.run([git, "-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null",
                            "apply", strip, "--recount", "--whitespace=nowarn", str(patch_path)],
                           capture_output=True, text=True, cwd=str(work), env=env,
                           timeout=timeout, check=False)
        if r.returncode == 0:
            return True, ""
        err = err or (r.stderr or r.stdout or f"git apply exited {r.returncode}").strip()
    return False, err[:500]


_DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_PLUS_HEADER_RE = re.compile(r"^\+\+\+ (?:b/)?([^\t\n]+)")
_GIT_PREFIX_RE = re.compile(r"^(?:diff --git a/|--- a/|\+\+\+ b/)", re.M)
_MODE_RE = re.compile(r"^(new mode|old mode|new file mode|deleted file mode) (\d+)")
_SYMLINK_MODE = "120000"


def _rel(path: str) -> str:
    """Repo-relative POSIX path from a diff header path (the `a/ b/` prefix is
    already removed by the header regex). `extract_patch` emits plain
    repo-relative paths now, so this only normalizes separators and a stray
    leading slash; it used to search for `/work/` markers, which mangled a
    genuine `src/work/x.py` into `x.py`."""
    from .normalize.paths import normalize_separators
    return normalize_separators(path).lstrip("/")


def validate_patch(diff: str, *, target_files: set[str] | None = None,
                   secret_family: bool = False) -> PatchReport:
    files: list[str] = []
    refused: list[str] = []
    review: list[str] = []
    cur: str | None = None

    def _seen(f: str) -> None:
        if f in files:
            return
        files.append(f)
        if any(rx.search(f) for rx in REFUSE_PATH_RES):
            refused.append(f)
        elif any(rx.search(f) for rx in REVIEW_PATH_RES):
            review.append(f"modifies {f}")
        if target_files and f not in target_files and f not in refused:
            review.append(f"out_of_scope: {f}")

    for line in diff.splitlines():
        m = _DIFF_GIT_RE.match(line)
        if m:
            cur = _rel(m.group(2))
            _seen(cur)
            continue
        # R14 (VP-1): a traditional `---/+++`-only patch used to yield no files at
        # all, so the REFUSE list never saw it. The `+++` header names the file.
        m = _PLUS_HEADER_RE.match(line)
        if m and m.group(1).strip() != "/dev/null":
            cur = _rel(m.group(1).strip())
            _seen(cur)
            continue
        if line.startswith(("new mode", "old mode", "new file mode", "deleted file mode")):
            mm = _MODE_RE.match(line)
            if mm and mm.group(2) == _SYMLINK_MODE:
                refused.append("symlink entry (120000)")
            elif mm and ("new mode" in line):
                review.append("file mode change")
            elif line.startswith("deleted file mode"):
                # R14 (VP-2): a deletion can read as `fixed`; a reviewer must see it
                review.append(f"deletes {cur or 'a file'}")
        if line.startswith("rename from") or line.startswith("copy from"):
            review.append("rename/copy header")
        if line.startswith("Binary files") or "GIT binary patch" in line:
            refused.append("binary hunk")
    diff2, redacted, secret = _redact(diff, force=secret_family)
    ok = not refused
    return PatchReport(ok=ok, diff=diff2, files=sorted(set(files)),
                       refused=sorted(set(refused)), review_required=sorted(set(review)),
                       redacted=redacted, secret_in_patch=secret,
                       sha256=hashlib.sha256(diff2.encode()).hexdigest())


def _redact(diff: str, *, force: bool) -> tuple[str, bool, bool]:
    """Redact secret material on BOTH +/- content lines (a fix can move a key to
    a + line). `force` (secrets-family finding, or a secret-hinted path) redacts
    every high-entropy token on content lines; otherwise leave non-secret diffs
    intact. Returns (diff, redacted, secret_seen)."""
    out: list[str] = []
    redacted = secret = False
    in_secret_file = force
    for line in diff.splitlines():
        m = _DIFF_GIT_RE.match(line)
        if m:
            in_secret_file = force or any(rx.search(_rel(m.group(2))) for rx in SECRET_PATH_RES)
        if in_secret_file and line[:1] in ("+", "-") and not line.startswith(("+++", "---")):
            body = line[1:]
            if _HIGH_ENTROPY.search(body):
                sha = hashlib.sha256(body.strip().encode()).hexdigest()[:12]
                out.append(f"{line[0]}<redacted secret sha256:{sha}>")
                redacted = secret = True
                continue
        out.append(line)
    return "\n".join(out) + ("\n" if diff.endswith("\n") else ""), redacted, secret
