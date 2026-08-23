"""Analysis-artifact lane (M-V3).

The vendors' analysis workflows (threat model, attack-path analysis, security
hardening proposals, policy proposals, vulnerability write-ups) produce
*documents*, not gate-able findings. Per R5 they attach to a run as
manifest-indexed artifacts and NEVER enter `findings.json` or the finding
model's invariant surface.

Trust-boundary rules this module encodes:
- **Artifacts are not findings.** They live under `raw/<producer>/` and are
  listed in the manifest's `artifacts` index; the SARIF/eMASS/GitLab exporters
  (which render findings) never touch them.
- **Dual-use artifacts are export-excluded by default.** attack-path analysis
  and vulnerability write-ups are attacker-facing narratives; they stay
  `raw/`-resident, are flagged in the summary, and their content is never
  inlined into a shareable report unless an operator opts in.
- Every artifact carries provenance: producer, model id, entitlement,
  safeguard posture (so a Mythos/Daybreak-produced write-up is labeled).

Invocation contract (verified against the installed plugin): these are Codex
plugin skills triggered as ``$threat-model`` etc. inside a codex session — no
standalone CLI subcommand — analogous to claude-security's ``/claude-security``.
The runner (`arms/artifact_runner.py`) drives that headlessly; like the
dedicated scan arms it is built offline first, live-run pending real spend.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

_RAW_PATH_RE = re.compile(r"^raw/[^/].*[^/]$")


@dataclass(frozen=True)
class AnalysisJob:
    key: str                 # short selector, e.g. "threat-model"
    skill: str               # the plugin trigger, e.g. "$threat-model"
    family: str              # vendor family that provides it
    title: str
    dual_use: bool           # attacker-facing → export-excluded by default
    needs_findings: bool     # operates on prior findings (vs repo-level)


# Codex-security analysis skills (no CLI subcommand — session `$skill` triggers).
ANALYSIS_JOBS: dict[str, AnalysisJob] = {
    "threat-model": AnalysisJob("threat-model", "$threat-model", "codex",
                                "Repository threat model", False, False),
    "attack-path": AnalysisJob("attack-path", "$attack-path-analysis", "codex",
                               "Attack-path analysis", True, True),
    "hardening": AnalysisJob("hardening", "$propose-security-hardening", "codex",
                             "Security hardening proposals", False, False),
    "policy": AnalysisJob("policy", "$define-security-policy", "codex",
                          "Security policy proposal", False, False),
    "writeup": AnalysisJob("writeup", "$vulnerability-writeup", "codex",
                           "Vulnerability write-up", True, True),
}


@dataclass
class Artifact:
    id: str
    kind: str                        # the job key
    title: str
    path: str                        # repo-relative, under raw/<producer>/
    producer: str                    # runner/arm id
    family: str
    dual_use: bool
    export_excluded: bool
    created_at: str
    model_id: Optional[str] = None
    entitlement: Optional[str] = None
    safeguard_posture: str = "default"
    format: str = "markdown"
    related_finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "title": self.title, "path": self.path,
                "producer": self.producer, "family": self.family, "dual_use": self.dual_use,
                "export_excluded": self.export_excluded, "created_at": self.created_at,
                "model_id": self.model_id, "entitlement": self.entitlement,
                "safeguard_posture": self.safeguard_posture, "format": self.format,
                "related_finding_ids": list(self.related_finding_ids)}


def artifact_id(*, kind: str, producer: str, path: str, run_id: str) -> str:
    key = f"{run_id}\x00{producer}\x00{kind}\x00{path}"
    return "A" + hashlib.sha256(key.encode()).hexdigest()[:15]


def make_artifact(*, job: AnalysisJob, path: str, producer: str, run_id: str, created_at: str,
                  model_id: str | None = None, entitlement: str | None = None,
                  safeguard_posture: str = "default",
                  related_finding_ids: list[str] | None = None,
                  export_excluded: bool | None = None) -> Artifact:
    if not _RAW_PATH_RE.match(path):
        raise ValueError(f"artifact path must be repo-relative under raw/: {path!r}")
    excl = job.dual_use if export_excluded is None else export_excluded
    return Artifact(
        id=artifact_id(kind=job.key, producer=producer, path=path, run_id=run_id),
        kind=job.key, title=job.title, path=path, producer=producer, family=job.family,
        dual_use=job.dual_use, export_excluded=excl, created_at=created_at,
        model_id=model_id, entitlement=entitlement, safeguard_posture=safeguard_posture,
        related_finding_ids=list(related_finding_ids or []))


def export_eligible(artifacts: list[dict]) -> list[dict]:
    """Artifacts safe to include in a shareable bundle — dual-use/export-excluded
    ones are held back (raw/-only)."""
    return [a for a in artifacts if not a.get("export_excluded")]
