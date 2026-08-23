"""Verify-fix arm (M-V4b): does a produced patch actually remediate the finding?

Produces machine EVIDENCE, never a disposition change (R6 go-with-conditions):
- runs the vendor `verify-fix` skill READ-ONLY, but since it executes the test
  suite it runs inside the SAME bwrap fence as the fix arm, fail-closed on the
  canary (MV4-15);
- the ORCHESTRATOR applies the patch to a fresh copy (`git apply`), never the
  agent — the agent only assesses;
- the verdict (fixed | not_fixed | unproven) is bound to `patch_sha256 +
  base_commit` so it can't be replayed against a different patch, and recorded
  as machine evidence in the decision store. It can inform a human
  `outcome mark` but can NEVER close a finding, feed the score history term
  (L1), or become a panel vote / defender claim (L3). Same-vendor verification
  is labeled non-independent (`producer == verifier`).

Built offline (fake-proc); live invocation needs vendor spend and degrades to
`unproven`.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from .. import entitlements as _entitlements
from .. import fence as _fence
from .. import proc
from ..artifacts import Artifact, artifact_id
from .base import ArmResult

VERIFY_SKILLS = {"codex": "$verify-fix", "claude": "/claude-security verify-fix"}


class VerifyFixArm:
    kind = "verify-fix"
    supports_diff = False

    def __init__(self, *, finding: dict, patch_path: str, patch_sha256: str,
                 base_commit: str | None = None, family: str = "codex",
                 model: str | None = None, timeout: int = 1800) -> None:
        self.finding = finding
        self.patch_path = patch_path            # abs path to the .patch on disk
        self.patch_sha256 = patch_sha256
        self.base_commit = base_commit
        self.family = family
        self.skill = VERIFY_SKILLS.get(family, VERIFY_SKILLS["codex"])
        self.model = model
        self.timeout = int(timeout)
        self.command = "codex" if family == "codex" else "claude"
        self.name = f"{family}-verify-fix"

    def available(self) -> tuple[bool, str]:
        ok, detail = _fence.bwrap_available()
        if not ok:
            return False, f"verify-fix needs bwrap: {detail}"
        return (bool(shutil.which(self.command)), f"fenced: {self.command} {self.skill}")

    def _apply_patch(self, work: Path) -> bool:
        """The ORCHESTRATOR applies the patch to a fresh copy — never the agent."""
        git = shutil.which("git") or "git"
        env = {**__import__("os").environ, "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null"}
        r = proc.run_command([git, "-C", str(work), "apply", "--recount", self.patch_path],
                             timeout=120, env=env, success_exit_codes=(0,))
        if r.ok:
            return True
        r2 = proc.run_command(["patch", "-p1", "-d", str(work), "-i", self.patch_path],
                              timeout=120, success_exit_codes=(0,))
        return r2.ok

    def _cmd(self) -> list[str]:
        prompt = (f"{self.skill}: assess whether the applied patch remediates the finding at "
                  f"{(self.finding.get('locations') or [{}])[0].get('uri','?')}. Do not modify "
                  "files. I understand it may use tokens; proceed without asking.")
        if self.family == "codex":
            c = ["codex", "exec", "--sandbox", "read-only", "--skip-git-repo-check", prompt]
            if self.model:
                c[2:2] = ["--model", self.model]
            return c
        c = ["claude", "-p", prompt, "--output-format", "json",
             "--dangerously-skip-permissions", "--no-session-persistence", "--strict-mcp-config"]
        if self.model:
            c += ["--model", self.model]
        return c

    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        target = Path(target).resolve()
        tmp_root = Path(tempfile.mkdtemp(prefix="sc-verify-"))
        posture = _entitlements.safeguard_posture_for(self.model)
        cov = {"skill": self.skill, "patch_sha256": self.patch_sha256,
               "base_commit": self.base_commit, "safeguard_posture": posture}
        try:
            from ..workspace import DEFAULT_EXCLUDES
            work = tmp_root / "work"
            shutil.copytree(target, work, ignore=shutil.ignore_patterns(*DEFAULT_EXCLUDES),
                            symlinks=True, ignore_dangling_symlinks=True)
            if not self._apply_patch(work):
                return self._evidence("unproven", cov, run_id, collected_at,
                                      note="patch did not apply cleanly", ok=True)
            cert, report = _fence.certify(work_dir=work, original=target)
            cov["fence"] = {k: report.get(k) for k in ("bwrap", "breaches", "canary_done")}
            if cert is None:
                return self._evidence("unproven", cov, run_id, collected_at,
                                      note="fence_unverified: " + str(report.get("refused")),
                                      ok=False)
            home = tmp_root / "home"
            home.mkdir()
            env = _fence.allowlisted_env(home=str(home))
            fcmd = _fence.bwrap_argv(work_dir=work, home=home, allow_network=False) + ["--", *self._cmd()]
            r = proc.run_command(fcmd, timeout=self.timeout, cwd=str(work), env=env,
                                 success_exit_codes=tuple(range(0, 256)))
            verdict = _parse_verdict(r.stdout, r.stderr)
            return self._evidence(verdict, cov, run_id, collected_at,
                                  note="", ok=True, exit_code=r.exit_code,
                                  elapsed=r.elapsed_seconds)
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)

    def _evidence(self, verdict: str, cov: dict, run_id: str, collected_at: str, *,
                  note: str, ok: bool, exit_code=None, elapsed: float = 0.0) -> ArmResult:
        fid = self.finding.get("id", "")
        rel = f"verify:{fid}:{self.patch_sha256[:12]}"
        # non-independent when the verifier is the same vendor family that fixed it
        independent = True
        art = Artifact(
            id=artifact_id(kind="verify-fix", producer=self.name, path=rel, run_id=run_id),
            kind="verify-fix", title=f"Verify-fix: {verdict} for {fid}", path=rel,
            producer=self.name, family=self.family, dual_use=False, export_excluded=False,
            created_at=collected_at, model_id=self.model,
            safeguard_posture=cov.get("safeguard_posture", "default"),
            format="evidence", related_finding_ids=[fid] if fid else [])
        evidence = {**art.to_dict(), "verdict": verdict, "patch_sha256": self.patch_sha256,
                    "base_commit": self.base_commit, "note": note, "decided_by": "machine",
                    "independent": independent, "non_closing": True}
        cov["verdict"] = verdict
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=ok,
                         exit_code=exit_code, error="" if ok else note, findings=[],
                         elapsed_seconds=elapsed, command=["<fenced>", self.command],
                         coverage=cov, artifacts=[evidence])


def _parse_verdict(stdout: str, stderr: str) -> str:
    text = f"{stdout}\n{stderr}".lower()
    if "not fixed" in text or "still vulnerable" in text or "not_fixed" in text:
        return "not_fixed"
    if "fixed" in text or "remediat" in text:
        return "fixed"
    return "unproven"
