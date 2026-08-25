"""Artifact runner (M-V3): drives a vendor ANALYSIS skill and attaches its
output as a run artifact (never a finding).

Codex-security's analysis skills (threat-model, attack-path-analysis,
propose-security-hardening, define-security-policy, vulnerability-writeup) are
plugin skills triggered as ``$skill`` inside a codex session — no standalone
CLI subcommand — so this runner drives ``codex`` headlessly with the plugin's
gate-collapse acknowledgement, captures the produced markdown into
``raw/<runner>/<job>.md``, and returns an `Artifact` (dual-use ones marked
export-excluded).

Status: built offline (fake-proc tested), like the dedicated scan arms were
before their live run. Live invocation costs vendor tokens and, for gated
tiers, needs entitlement — not runnable on the dev machine. The `_cmd` encodes
the verified ``$skill`` trigger contract; live-verify in a session with spend.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .. import entitlements as _entitlements
from .. import proc
from ..artifacts import ANALYSIS_JOBS, make_artifact
from .base import ArmResult

ACKNOWLEDGEMENT = ("I understand it may take a while and use a significant number of tokens; "
                   "proceed without asking.")


class ArtifactRunnerArm:
    """One vendor analysis job → one artifact. Selected as `<family>-analysis`
    with `job` set (e.g. codex-analysis job=threat-model)."""
    kind = "artifact"
    supports_diff = False

    def __init__(self, *, job: str, family: str = "codex", model: str | None = None,
                 command: str | None = None, max_cost_usd: float = 5.0,
                 timeout: int = 3600) -> None:
        if job not in ANALYSIS_JOBS:
            raise ValueError(f"unknown analysis job {job!r}; known: {sorted(ANALYSIS_JOBS)}")
        self.spec = ANALYSIS_JOBS[job]
        self.family = family
        self.name = f"{family}-analysis:{job}"
        self.model = model
        self.command = command or ("codex" if family == "codex" else "claude")
        self.max_cost_usd = float(max_cost_usd)
        self.timeout = int(timeout)

    def available(self) -> tuple[bool, str]:
        p = shutil.which(self.command)
        if not p:
            return False, f"{self.command} not on PATH"
        if self.family == "codex":
            # R10, verified live 2026-08-25: these analysis skills are NOT
            # reachable through any supported surface, so the lane cannot
            # honestly claim vendor-skill provenance.
            #  - `codex plugin add` installs from a marketplace snapshot only,
            #    so the bundled plugin cannot be registered; `codex plugin list`
            #    shows only gmail/github.
            #  - the reference producer runs `codex exec ... --disable plugins`
            #    and INLINES the skill instructions; it never triggers `$skill`.
            #  - `codex-security` has no threat-model/attack-path/hardening
            #    subcommand, and `skills list` exposes only wrappers for its own
            #    subcommands.
            #  - skills/threat-model/SKILL.md is not self-contained (it reads
            #    ../../references/*.md) and says standard scans build their
            #    threat models in the ordinary workflow, never via this skill.
            # They are internal phases of `codex-security scan`. Refuse rather
            # than emit an artifact stamped with a provenance we cannot support.
            return False, (f"analysis skill {self.spec.skill} is not independently "
                           "invocable: it is an internal phase of `codex-security "
                           "scan`, not a public surface (see docs/reviews/"
                           "R10-live-vendor-runs.md §4)")
        return True, f"local: {p} (analysis skill {self.spec.skill})"

    def _env(self) -> dict:
        env = dict(os.environ)
        env["SECURITY_COUNCIL_NESTED"] = "1"
        env["LLM_COUNCIL_NESTED"] = "1"
        return env

    def _prompt(self) -> str:
        return (f"{self.spec.skill}\n\nRun the {self.spec.skill} analysis now against this "
                f"repository and write the result to a markdown file. {ACKNOWLEDGEMENT}")

    def _cmd(self, prompt: str) -> list[str]:
        """R10: this previously passed CLAUDE CODE flags to codex, where `-p` is
        `--profile`, not the prompt — so the lane could never have run. Shapes
        below follow each CLI's real contract (`codex exec --help`, and the
        reference producer's own spawn in @openai/codex-security)."""
        if self.command == "codex":
            cmd = ["codex", "exec", "--ignore-user-config", "--ephemeral",
                   "--color", "never", "--skip-git-repo-check",
                   "-c", "mcp_servers={}", "-s", "workspace-write"]
            if self.model:
                cmd += ["-m", self.model]
            return [*cmd, prompt]
        cmd = [self.command, "-p", prompt, "--output-format", "json",
               "--dangerously-skip-permissions", "--no-session-persistence",
               "--strict-mcp-config"]
        if self.model:
            cmd += ["--model", self.model]
        return cmd

    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        target = Path(target).resolve()
        raw_dir = Path(out_dir) / "raw" / self.name.replace(":", "_")
        raw_dir.mkdir(parents=True, exist_ok=True)
        prompt = self._prompt()
        cmd = self._cmd(prompt)
        r = proc.run_command(cmd, timeout=self.timeout, cwd=str(target), env=self._env())
        # the skill writes markdown into the repo; capture the newest .md it produced
        produced = _newest_markdown(target, raw_dir)
        posture = _entitlements.safeguard_posture_for(self.model)
        tier = _entitlements.classify_model(self.model)
        cov = {"skill": self.spec.skill, "dual_use": self.spec.dual_use,
               "exit_code": r.exit_code, "safeguard_posture": posture}
        if r.timed_out or not r.ok or produced is None:
            return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=False,
                             exit_code=r.exit_code,
                             error=(f"timed out after {self.timeout}s" if r.timed_out
                                    else f"no artifact produced (exit {r.exit_code})"),
                             findings=[], elapsed_seconds=r.elapsed_seconds,
                             command=_redact(cmd), coverage=cov)
        rel = f"raw/{self.name.replace(':', '_')}/{produced.name}"
        art = make_artifact(job=self.spec, path=rel, producer=self.name, run_id=run_id,
                            created_at=collected_at, model_id=self.model,
                            entitlement=tier.name if tier else None, safeguard_posture=posture)
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=True,
                         exit_code=r.exit_code, error="", findings=[],
                         elapsed_seconds=r.elapsed_seconds, command=_redact(cmd),
                         raw_path=str(produced), coverage=cov, artifacts=[art.to_dict()])


def _newest_markdown(target: Path, raw_dir: Path) -> Path | None:
    """The skill writes markdown into the scanned tree; move the newest one into
    raw/. (Offline tests plant the file directly in raw_dir.)"""
    planted = sorted(raw_dir.glob("*.md"))
    if planted:
        return planted[-1]
    cands = sorted(target.glob("*.md"), key=lambda p: p.stat().st_mtime)
    if not cands:
        return None
    dest = raw_dir / cands[-1].name
    shutil.move(str(cands[-1]), dest)
    return dest


def _redact(cmd: list[str]) -> list[str]:
    return [("<prompt>" if len(a) > 200 else a) for a in cmd]
