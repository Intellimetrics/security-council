"""Arm builder: name -> Arm instance (scanner or LLM-CLI)."""

from __future__ import annotations

from ..artifacts import ANALYSIS_JOBS
from .artifact_runner import ArtifactRunnerArm
from .base import Arm
from .claude_security import ClaudeSecurityArm
from .codex_security import CodexSecurityArm
from .llm_cli import LLM_CLI_SPECS, LlmCliArm
from .scanner import SCANNER_SPECS, ScannerArm

# Dedicated agentic scanners: name -> class. Constructed with model= + the per-arm
# options block from config (`arms.options.<name>`), e.g. effort / max_budget_usd.
DEDICATED_ARMS: dict[str, type] = {
    ClaudeSecurityArm.name: ClaudeSecurityArm,
    CodexSecurityArm.name: CodexSecurityArm,
}


def known_arms() -> list[str]:
    return list(SCANNER_SPECS) + list(LLM_CLI_SPECS) + list(DEDICATED_ARMS)


def build_analysis_arm(job: str, *, model: str | None = None, options: dict | None = None):
    """An artifact-lane runner for one vendor analysis job (M-V3)."""
    opts = dict(options or {})
    model = model or opts.pop("model", None)
    fam = ANALYSIS_JOBS[job].family
    return ArtifactRunnerArm(job=job, family=fam, model=model, **opts)


def build_arm(name: str, *, model: str | None = None, options: dict | None = None,
              diff=None) -> Arm:
    opts = dict(options or {})
    model = model or opts.pop("model", None)
    if name in SCANNER_SPECS:
        return ScannerArm(name)
    if name in LLM_CLI_SPECS:
        return LlmCliArm(name, model=model)
    if name in DEDICATED_ARMS:
        # diff is only meaningful for diff-capable dedicated arms; pass it and
        # let the arm ignore it if unsupported (all current dedicated arms support it)
        if diff is not None:
            opts.setdefault("diff", diff)
        return DEDICATED_ARMS[name](model=model, **opts)
    raise ValueError(f"unknown arm {name!r}; known: {known_arms()}")
