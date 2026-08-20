"""Arm builder: name -> Arm instance (scanner or LLM-CLI)."""

from __future__ import annotations

from .base import Arm
from .llm_cli import LLM_CLI_SPECS, LlmCliArm
from .scanner import SCANNER_SPECS, ScannerArm


def known_arms() -> list[str]:
    return list(SCANNER_SPECS) + list(LLM_CLI_SPECS)


def build_arm(name: str, *, model: str | None = None) -> Arm:
    if name in SCANNER_SPECS:
        return ScannerArm(name)
    if name in LLM_CLI_SPECS:
        return LlmCliArm(name, model=model)
    raise ValueError(f"unknown arm {name!r}; known: {known_arms()}")
