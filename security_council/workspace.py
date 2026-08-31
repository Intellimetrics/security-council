"""Scan workspace isolation.

Arms and the validator both WRITE into the directory they operate on (scanner
output, claude-security's report dir, llm-council transcripts). Scanning the real
target therefore pollutes it and, worse, the next scan re-ingests those artifacts.
The default `copy` mode gives arms a throwaway copy (runtime/vcs dirs excluded);
reports are written to an out_dir outside the copy, and the copy is discarded.
Findings carry repo-relative paths, so they remain valid against the original.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import proc

DEFAULT_EXCLUDES = frozenset({
    ".git", ".hg", ".svn", ".llm-council", ".security-council", ".spikes",
    "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", ".venv",
    "node_modules", ".tox",
})


@dataclass
class Workspace:
    root: Path              # where arms scan (copy, or the original for inplace)
    original: Path          # the real target (source of git provenance)
    mode: str               # copy | inplace
    _tmp: Path | None = None
    # R12: what the scratch copy LEFT OUT. Excludes are deliberate (runtime dirs,
    # VCS internals) but a scan that never saw `.git/hooks` or a vendored tree
    # must say so in its scope, not present itself as "the whole repository".
    excluded: list[str] = field(default_factory=list)

    def git_info(self) -> dict:
        r = proc.run_command(["git", "-C", str(self.original), "rev-parse", "HEAD"], timeout=15)
        if not r.ok:
            return {"git_commit": None, "dirty": None, "branch": None}
        st = proc.run_command(["git", "-C", str(self.original), "status", "--porcelain"], timeout=15)
        br = proc.run_command(["git", "-C", str(self.original), "rev-parse", "--abbrev-ref", "HEAD"],
                              timeout=15)

        # The tool's own state dir must not dirty the tool's own precondition:
        # a default-layout scan writes runs under .security-council/ and a
        # signed decision modifies the store there, and `consolidate` would
        # then refuse to import the very runs this scanner just produced.
        # Everything else — tracked modifications, untracked SOURCE files, and
        # the .security-council.yaml config file — still counts as dirty.
        def _tool_state_only(line: str) -> bool:
            paths = [p.strip().strip('"') for p in line[3:].split(" -> ")]
            return all(p == ".security-council" or p.startswith(".security-council/")
                       for p in paths)

        dirty = any(ln.strip() and not _tool_state_only(ln)
                    for ln in st.stdout.splitlines())
        return {"git_commit": r.stdout.strip(), "dirty": dirty,
                "branch": br.stdout.strip() if br.ok else None}

    def cleanup(self) -> None:
        if self._tmp is not None and self._tmp.exists():
            shutil.rmtree(self._tmp, ignore_errors=True)

    def __enter__(self) -> "Workspace":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()


def prepare_workspace(target: str | Path, *, mode: str = "copy",
                      extra_excludes: frozenset[str] = frozenset()) -> Workspace:
    target = Path(target).resolve()
    if mode == "inplace":
        return Workspace(root=target, original=target, mode="inplace")
    excludes = DEFAULT_EXCLUDES | set(extra_excludes)
    tmp = Path(tempfile.mkdtemp(prefix="sc-ws-"))
    dst = tmp / target.name
    skipped: set[str] = set()
    base_ignore = shutil.ignore_patterns(*excludes)

    def _ignore(d, names):
        hit = base_ignore(d, names)
        for n in hit:
            try:
                skipped.add(str((Path(d) / n).relative_to(target)))
            except ValueError:
                skipped.add(n)
        return hit

    shutil.copytree(target, dst, ignore=_ignore, symlinks=False, ignore_dangling_symlinks=True)
    return Workspace(root=dst, original=target, mode="copy", _tmp=tmp, excluded=sorted(skipped))
