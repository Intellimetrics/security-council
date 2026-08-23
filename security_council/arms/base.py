"""Arm interface and result."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional, Protocol

from ..model import Finding


@dataclass(frozen=True)
class DiffSpec:
    """A change-scoped scan directive (M-V1 diff lane).

    kind "diff": committed range base..head (head defaults to HEAD).
    kind "working_tree": staged+unstaged changes vs base (codex only; claude's
    scan-changes scans committed changes only, so it is skipped in this mode).
    A run carrying a DiffSpec is PARTIAL: it must never be used to set a
    baseline, and delta must not mark out-of-scope findings absent.
    """
    kind: Literal["diff", "working_tree"] = "diff"
    base: Optional[str] = None
    head: Optional[str] = None

    def as_dict(self) -> dict:
        return {"kind": self.kind, "base": self.base, "head": self.head}

    def label(self) -> str:
        if self.kind == "working_tree":
            return f"working-tree vs {self.base or 'HEAD'}"
        return f"{self.base or 'auto'}..{self.head or 'HEAD'}"


@dataclass
class ArmResult:
    name: str
    kind: str                 # scanner | agent_cli | mcp_tool
    family: str
    ok: bool
    exit_code: int | None
    error: str
    findings: list[Finding]
    tool_version: str | None = None
    elapsed_seconds: float = 0.0
    command: list[str] = field(default_factory=list)
    raw_path: str | None = None
    coverage: dict = field(default_factory=dict)
    artifacts: list[dict] = field(default_factory=list)   # M-V3 analysis-lane products


class Arm(Protocol):
    name: str
    kind: str
    family: str

    def available(self) -> tuple[bool, str]: ...

    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult: ...
