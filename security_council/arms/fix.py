"""Fix arm (M-V4a): produce a reviewed `.patch` ARTIFACT for a finding — never
applied to the user's tree (R6, go-with-conditions).

Flow, all orchestrator-owned:
1. make two fresh copies of the target — a WORK copy the vendor agent edits and
   a PRISTINE copy to diff against (symlinks preserved, not dereferenced);
   `git init` the work copy with one baseline commit, no remotes, credentials
   disabled (M4).
2. `fence.certify()` the work copy — a bwrap canary must prove no escape, or the
   job is refused (fail-closed; no `FenceCertificate`, no run).
3. run the vendor fix skill INSIDE the fence with an allowlisted env + ephemeral
   HOME (M1/M3/MV4-11). The agent may edit files and run tests — untrusted, but
   fenced with no network and no reach outside the work copy.
4. the ORCHESTRATOR extracts the diff with the neutralized `git diff --no-index`
   (never runs git in the agent's tree — MV4-10), validates + redacts it
   (`patches.py`), and returns it as a `.patch` artifact with provenance +
   review flags. `--apply`/commit/push are never available.

Built offline (fake-proc), like the other agentic arms; the live vendor run
needs spend and degrades safely to `no_patch` / `tests_ran: false`.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .. import entitlements as _entitlements
from .. import fence as _fence
from .. import patches as _patches
from .. import proc
from ..artifacts import Artifact, artifact_id
from .base import ArmResult

FIX_JOBS = {
    "suggest-patches": ("claude", "/claude-security suggest-patches"),
    "fix-finding": ("codex", "$fix-finding"),
}


def prepare_fix_copies(target: Path, tmp_root: Path) -> tuple[Path, Path]:
    """(work, pristine) fresh copies; work is a git repo with a baseline commit
    and no remotes. Symlinks preserved (not dereferenced) so an out-of-tree
    symlink target can't be pulled in and embedded in a patch (MV4-7)."""
    from ..workspace import DEFAULT_EXCLUDES
    ign = shutil.ignore_patterns(*DEFAULT_EXCLUDES)
    work, pristine = tmp_root / "work", tmp_root / "pristine"
    shutil.copytree(target, work, ignore=ign, symlinks=True, ignore_dangling_symlinks=True)
    shutil.copytree(target, pristine, ignore=ign, symlinks=True, ignore_dangling_symlinks=True)
    env = _git_env()
    git = shutil.which("git") or "git"
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=fix@sc", "-c", "user.name=sc",
                  "commit", "-q", "-m", "baseline", "--no-verify"]):
        proc.run_command([git, *args], cwd=str(work), env=env, timeout=120,
                         success_exit_codes=tuple(range(0, 2)))
    return work, pristine


def _git_env() -> dict:
    import os
    env = dict(os.environ)
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false",
                "GIT_SSH_COMMAND": "/bin/false", "GIT_ALLOW_PROTOCOL": "none"})
    return env


class FixArm:
    kind = "fix"
    supports_diff = False

    def __init__(self, *, job: str, finding: dict, model: str | None = None,
                 max_cost_usd: float = 5.0, timeout: int = 3600) -> None:
        if job not in FIX_JOBS:
            raise ValueError(f"unknown fix job {job!r}; known: {sorted(FIX_JOBS)}")
        self.job = job
        self.family, self.skill = FIX_JOBS[job]
        self.finding = finding
        self.model = model
        self.max_cost_usd = float(max_cost_usd)
        self.timeout = int(timeout)
        self.name = f"{self.family}-fix:{job}"
        self.command = "claude" if self.family == "claude" else "codex"

    def available(self) -> tuple[bool, str]:
        ok, detail = _fence.bwrap_available()
        if not ok:
            return False, f"fix lane needs bwrap: {detail}"
        if not shutil.which(self.command):
            return False, f"{self.command} not on PATH"
        return True, f"fenced: bwrap {detail}; {self.command} {self.skill}"

    def _cmd(self, home: Path) -> list[str]:
        prompt = (f"{self.skill} for finding at "
                  f"{(self.finding.get('locations') or [{}])[0].get('uri','?')}. "
                  "Produce a minimal fix and write the changed files. "
                  "I understand it may take a while and use tokens; proceed without asking.")
        if self.family == "codex":
            base = ["codex", "exec", "--sandbox", "workspace-write", "-C", str(home),
                    "--skip-git-repo-check", prompt]
            if self.model:
                base[2:2] = ["--model", self.model]
            return base
        cmd = ["claude", "-p", prompt, "--output-format", "json",
               "--dangerously-skip-permissions", "--no-session-persistence", "--strict-mcp-config"]
        if self.model:
            cmd += ["--model", self.model]
        return cmd

    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        import tempfile
        target = Path(target).resolve()
        tmp_root = Path(tempfile.mkdtemp(prefix="sc-fix-"))
        raw_dir = Path(out_dir) / "raw" / self.name.replace(":", "_")
        raw_dir.mkdir(parents=True, exist_ok=True)
        posture = _entitlements.safeguard_posture_for(self.model)
        tier = _entitlements.classify_model(self.model)
        cov = {"job": self.job, "safeguard_posture": posture, "fenced": True}
        try:
            work, pristine = prepare_fix_copies(target, tmp_root)
            home = tmp_root / "home"
            home.mkdir()
            # M1: fail closed unless the fence canary certifies against THIS work dir
            cert, report = _fence.certify(work_dir=work, original=target)
            cov["fence"] = {k: report.get(k) for k in ("bwrap", "breaches", "canary_done")}
            if cert is None:
                return self._fail("fence_unverified: " + str(report.get("refused")), cov)
            env = _fence.allowlisted_env(home=str(home))
            cmd = self._cmd(home)
            fcmd = _fence.bwrap_argv(work_dir=work, home=home, allow_network=False) + ["--", *cmd]
            r = proc.run_command(fcmd, timeout=self.timeout, cwd=str(work), env=env,
                                 success_exit_codes=tuple(range(0, 256)))
            diff = _patches.extract_patch(pristine, work, ceiling=tmp_root)
            if not diff.strip():
                return self._fail("no_patch: the fix produced no change", cov, ok_degrade=True)
            secret_family = bool(set(_norm_cwes(self.finding)) & _patches.SECRET_CWES)
            loc = (self.finding.get("locations") or [{}])[0]
            report_p = _patches.validate_patch(
                diff, target_files={loc.get("uri")} if loc.get("uri") else None,
                secret_family=secret_family)
            if not report_p.ok:
                return self._fail(f"patch_refused: {report_p.refused}", cov)
            patch_path = raw_dir / "fix.patch"
            patch_path.write_text(report_p.diff)
            rel = f"raw/{self.name.replace(':', '_')}/fix.patch"
            excluded = report_p.secret_in_patch
            art = Artifact(
                id=artifact_id(kind="fix", producer=self.name, path=rel, run_id=run_id),
                kind="fix", title=f"Patch for {loc.get('uri','?')}", path=rel,
                producer=self.name, family=self.family, dual_use=False,
                export_excluded=excluded, created_at=collected_at, model_id=self.model,
                entitlement=tier.name if tier else None, safeguard_posture=posture,
                format="patch", related_finding_ids=[self.finding.get("id")] if self.finding.get("id") else [])
            meta = {"sha256": report_p.sha256, "secret_in_patch": report_p.secret_in_patch,
                    "review_required": report_p.review_required, "files": report_p.files,
                    "base_commit": (report or {}).get("base_commit"), "exit_code": r.exit_code}
            cov.update({"patch": meta, "elapsed": r.elapsed_seconds})
            return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=True,
                             exit_code=r.exit_code, error="", findings=[],
                             elapsed_seconds=r.elapsed_seconds, command=["<fenced>", self.command],
                             raw_path=str(patch_path), coverage=cov,
                             artifacts=[{**art.to_dict(), "patch": meta}])
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def _fail(self, error: str, cov: dict, *, ok_degrade: bool = False) -> ArmResult:
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=ok_degrade,
                         exit_code=None, error=error, findings=[], coverage=cov,
                         command=["<fenced>", self.command])


def _norm_cwes(finding: dict) -> list[str]:
    tax = finding.get("taxonomy") or {}
    return [str(c).upper() for c in (tax.get("cwe") or [])]
