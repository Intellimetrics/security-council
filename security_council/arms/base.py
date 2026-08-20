"""Arm interface and result."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..model import Finding


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


class Arm(Protocol):
    name: str
    kind: str
    family: str

    def available(self) -> tuple[bool, str]: ...

    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult: ...
