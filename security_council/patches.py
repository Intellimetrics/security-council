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


def extract_patch(pristine: Path, work: Path, *, ceiling: Path) -> str:
    """`git diff --no-index pristine work` with git config neutralized, run from
    a non-repo cwd. --no-index makes git ignore both trees' `.git`, so a planted
    repo config cannot run code (MV4-10). Returns the unified diff (paths made
    relative to the work tree)."""
    env = {**os.environ, **_GIT_NEUTRAL_ENV,
           "GIT_CEILING_DIRECTORIES": str(ceiling)}
    git = shutil.which("git") or "git"
    r = subprocess.run([git, "-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null",
                        "diff", "--no-index", "--no-ext-diff", "--no-color",
                        str(pristine), str(work)],
                       capture_output=True, text=True, cwd=str(ceiling), env=env,
                       timeout=120, check=False)
    # git diff --no-index exits 1 when there are differences — that's success here
    return r.stdout


_DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_MODE_RE = re.compile(r"^(new mode|old mode|new file mode|deleted file mode) (\d+)")
_SYMLINK_MODE = "120000"


def _rel(path: str) -> str:
    # git --no-index emits absolute-ish a//tmp/.../pristine/app/x paths; keep the
    # tail after the copy root so refuse/target matching works on repo-relative paths
    p = path.replace("\\", "/")
    for marker in ("/pristine/", "/work/", "/sc-ws-"):
        i = p.find(marker)
        if i >= 0:
            return p[i + len(marker):].split("/", 1)[-1] if marker == "/sc-ws-" else p[i + len(marker):]
    return p.lstrip("/")


def validate_patch(diff: str, *, target_files: set[str] | None = None,
                   secret_family: bool = False) -> PatchReport:
    files: list[str] = []
    refused: list[str] = []
    review: list[str] = []
    for line in diff.splitlines():
        m = _DIFF_GIT_RE.match(line)
        if m:
            f = _rel(m.group(2))
            files.append(f)
            if any(rx.search(f) for rx in REFUSE_PATH_RES):
                refused.append(f)
            elif any(rx.search(f) for rx in REVIEW_PATH_RES):
                review.append(f"modifies {f}")
            if target_files and f not in target_files and not refused[-1:] == [f]:
                review.append(f"out_of_scope: {f}")
            continue
        if line.startswith(("new mode", "old mode", "new file mode", "deleted file mode")):
            mm = _MODE_RE.match(line)
            if mm and mm.group(2) == _SYMLINK_MODE:
                refused.append("symlink entry (120000)")
            elif mm and ("new mode" in line):
                review.append("file mode change")
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
