"""Read-only import arms for already-produced canonical security artifacts.

These arms let the normal Security Council clustering, policy, gate, and report
pipeline combine results without paying to rerun their original producers.
Imports are snapshot-bound: the source artifact revision must match the current
clean target checkout or the arm fails closed.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..jsonio import finding_from_dict
from ..model import (
    CWE_FAMILIES,
    EvidenceCitation,
    PanelOpinion,
    Reachability,
    Validation,
)
from ..normalize import registry
from ..normalize.base import ParseContext
from ..normalize.coverage import NONE, PARTIAL, VERIFIED, SourceRun
from .base import ArmResult
from .codex_security import BUNDLE_FILES, _bundle_prompt_sha


def _load_object(path: Path) -> dict:
    with path.open() as fh:
        value = json.load(fh)
    if not isinstance(value, dict):
        raise TypeError(f"expected JSON object: {path}")
    return value


def _load_array(path: Path) -> list:
    with path.open() as fh:
        value = json.load(fh)
    if not isinstance(value, list):
        raise TypeError(f"expected JSON array: {path}")
    return value


def _copy_files(source: Path, destination: Path, names: tuple[str, ...]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        src = source / name
        if src.is_file():
            shutil.copy2(src, destination / name)


def _native_validation(raw: dict, *, target: Path, prompt_sha: str,
                       model: str) -> Validation | None:
    """Translate a sealed Codex Security validation into Council semantics.

    The bundle is already revision-bound by the import arm.  We additionally
    recheck every carried code citation against that exact checkout before it
    can be marked verified.
    """
    source = raw.get("validation")
    if not isinstance(source, dict) or not source:
        return None
    status_text = " ".join(str(source.get(k) or "").lower()
                           for k in ("status", "result", "disposition"))
    if any(mark in status_text for mark in ("false_positive", "refuted", "rejected")):
        verdict = "false_positive"
    elif (any(mark in status_text for mark in ("validated", "confirmed", "reported",
                                                "retained", "accepted"))
          or source.get("summary")):
        verdict = "true_positive"
    else:
        verdict = "uncertain"

    refs = {str(x) for x in (source.get("evidenceRefs") or [])}
    evidence = [item for item in (raw.get("codeEvidence") or []) if isinstance(item, dict)]
    if refs:
        selected = [item for item in evidence if str(item.get("id")) in refs]
    else:
        location_paths = {str(item.get("path")) for item in (raw.get("locations") or [])
                          if isinstance(item, dict) and item.get("path")}
        selected = [item for item in evidence if str(item.get("path")) in location_paths]
    selected = (selected or evidence)[:12]

    citations: list[EvidenceCitation] = []
    root = target.resolve()
    for item in selected:
        path = item.get("path")
        start = item.get("startLine")
        if not isinstance(path, str) or not path or not isinstance(start, int) or start < 1:
            continue
        end = item.get("endLine") if isinstance(item.get("endLine"), int) else start
        if end < start:
            continue
        verified = False
        try:
            candidate = (root / path).resolve()
            candidate.relative_to(root)
            if candidate.is_file():
                line_count = len(candidate.read_text(errors="replace").splitlines())
                verified = end <= line_count
        except (OSError, ValueError):
            verified = False
        claim = item.get("explanation") or item.get("label") or item.get("id") or ""
        citations.append(EvidenceCitation(
            path=path, start_line=start, end_line=end, claim=str(claim)[:300],
            verified=verified,
        ))

    verified_count = sum(c.verified is True for c in citations)
    pass_rate = verified_count / len(citations) if citations else None
    opinion_status = ("unevidenced" if not citations else
                      "ok" if pass_rate == 1.0 else "unreliable")
    confidence_raw = raw.get("confidence") or {}
    level = str(confidence_raw.get("level") or "").lower() \
        if isinstance(confidence_raw, dict) else ""
    confidence = {"high": 0.8, "medium": 0.6, "low": 0.4}.get(level, 0.5)
    rationale_parts = [source.get("summary"), source.get("method")]
    rationale = " — ".join(str(x) for x in rationale_parts if x)[:2000]
    opinion = PanelOpinion(
        role="prosecutor", participant="codex-current", family="codex",
        prompt_sha256=prompt_sha, verdict=verdict, rationale=rationale,
        model_id=model, citations=citations, citation_pass_rate=pass_rate,
        status=opinion_status, independent=True,
    )

    attack_path = raw.get("attackPath") or {}
    reachability = None
    impact = None
    if isinstance(attack_path, dict):
        raw_reach = attack_path.get("reachability")
        if isinstance(raw_reach, dict):
            entrypoint = raw_reach.get("entrypoint")
            attacker = str(raw_reach.get("attacker") or "").lower()
            reachability = Reachability(
                verdict="external" if attacker else "unknown",
                entrypoints=[str(entrypoint)] if entrypoint else [],
                trust_boundary=str(raw_reach.get("attacker")) if raw_reach.get("attacker") else None,
                path_summary=raw_reach.get("summary"),
            )
        raw_impact = attack_path.get("impact")
        if isinstance(raw_impact, dict):
            impact = raw_impact.get("rationale") or raw_impact.get("summary")
        elif raw_impact:
            impact = str(raw_impact)

    return Validation(
        verdict=verdict, confidence=confidence, panel=[opinion],
        evidence_check={
            "citations_total": len(citations),
            "citations_verified": verified_count,
            "hallucinated": len(citations) - verified_count,
            "imported_codex_security": True,
        },
        calibration="prior", reachability=reachability, impact=impact,
    )


class _SnapshotBoundImport:
    _target_commit: str | None = None
    _target_dirty: bool | None = None

    def bind_target(self, *, target: Path, git_info: dict) -> None:
        """Called by the orchestrator before it creates/runs scan workers."""
        self._target_commit = git_info.get("git_commit")
        self._target_dirty = git_info.get("dirty")

    def _revision_error(self, artifact_revision: object) -> str | None:
        if self._target_commit is None:
            return "target Git revision could not be established"
        if self._target_dirty is not False:
            return "target checkout is dirty or its status is unknown"
        if not isinstance(artifact_revision, str) or not artifact_revision:
            return "imported artifact does not attest a target revision"
        if artifact_revision != self._target_commit:
            return ("artifact revision mismatch: imported "
                    f"{artifact_revision} != target {self._target_commit}")
        return None


class SecurityCouncilRunImportArm(_SnapshotBoundImport):
    """Import the canonical findings from one prior Security Council run."""

    name = "security-council-import"
    kind = "import"
    family = "security-council"

    def __init__(self, *, run_dir: str | Path) -> None:
        self.run_dir = Path(run_dir).resolve()

    def available(self) -> tuple[bool, str]:
        missing = [name for name in ("manifest.json", "findings.json")
                   if not (self.run_dir / name).is_file()]
        if missing:
            return False, f"prior Security Council run missing {', '.join(missing)}: {self.run_dir}"
        return True, f"canonical Security Council run: {self.run_dir}"

    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        manifest = _load_object(self.run_dir / "manifest.json")
        revision_error = self._revision_error((manifest.get("target") or {}).get("git_commit"))
        if revision_error:
            return self._fail(revision_error)

        raw = _load_array(self.run_dir / "findings.json")
        findings = [finding_from_dict(item) for item in raw if isinstance(item, dict)]
        if len(findings) != len(raw):
            return self._fail(f"{len(raw) - len(findings)} imported findings were not objects")

        source_runs: list[SourceRun] = []
        verdicts: list[str] = []
        for arm in manifest.get("arms") or []:
            if not isinstance(arm, dict) or arm.get("kind") == "artifact":
                continue
            verdict = arm.get("coverage_verdict")
            if verdict not in (VERIFIED, PARTIAL, NONE):
                return self._fail(f"prior arm {arm.get('name')!r} has invalid coverage verdict")
            declined = frozenset(str(x) for x in (arm.get("declined_families") or []))
            source_runs.append(SourceRun(
                source_id=str(arm.get("name") or ""),
                kind=str(arm.get("kind") or "import"),
                family=str(arm.get("family") or "unknown"),
                ran=verdict != NONE,
                supported_families=None if not declined else frozenset(CWE_FAMILIES) - declined,
                may_decline=verdict == VERIFIED,
            ))
            verdicts.append(verdict)
        if not source_runs:
            return self._fail("prior manifest contains no finding-producing arms")

        raw_dir = Path(out_dir) / "raw" / self.name
        _copy_files(self.run_dir, raw_dir,
                    ("manifest.json", "findings.json", "summary.md", "summary.html"))
        completion = "complete" if all(v == VERIFIED for v in verdicts) else "partial"
        return ArmResult(
            name=self.name, kind=self.kind, family=self.family, ok=True, exit_code=0, error="",
            findings=findings,
            tool_version=str((manifest.get("tool") or {}).get("security_council") or "unknown"),
            raw_path=str(raw_dir / "findings.json"),
            coverage={"raw_results": len(raw), "normalized": len(findings),
                      "completion": completion, "imported_run_id": manifest.get("run_id"),
                      "_source_runs": source_runs},
        )

    def _fail(self, error: str) -> ArmResult:
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=False,
                         exit_code=None, error=error, findings=[])


class CodexSecurityBundleImportArm(_SnapshotBoundImport):
    """Import a sealed native Codex Security canonical bundle."""

    name = "codex-security-import"
    kind = "import"
    family = "codex"

    def __init__(self, *, bundle_dir: str | Path, model_hint: str | None = None) -> None:
        self.bundle_dir = Path(bundle_dir).resolve()
        self.model_hint = model_hint

    def available(self) -> tuple[bool, str]:
        missing = [name for name in ("scan-manifest.json", "findings.json", "coverage.json")
                   if not (self.bundle_dir / name).is_file()]
        if missing:
            return False, f"Codex Security bundle missing {', '.join(missing)}: {self.bundle_dir}"
        return True, f"sealed Codex Security bundle: {self.bundle_dir}"

    def run(self, target: Path, out_dir: Path, *, run_id: str, collected_at: str) -> ArmResult:
        manifest = _load_object(self.bundle_dir / "scan-manifest.json")
        coverage = _load_object(self.bundle_dir / "coverage.json")
        doc = _load_object(self.bundle_dir / "findings.json")
        scan = manifest.get("scan") or {}
        if scan.get("status") != "completed" or not scan.get("sealedAt"):
            return self._fail("Codex Security bundle is not completed and sealed")
        revision_error = self._revision_error((scan.get("target") or {}).get("revision"))
        if revision_error:
            return self._fail(revision_error)

        raw_dir = Path(out_dir) / "raw" / self.name
        _copy_files(self.bundle_dir, raw_dir, BUNDLE_FILES)
        prompt_sha = _bundle_prompt_sha(manifest)
        model = self.model_hint or "codex-security-model-unattested"
        ctx = ParseContext(
            repo_root=Path(target), source_id="codex-security", source_kind="agent_cli",
            family="codex", run_id=run_id, collected_at=collected_at, model_id=model,
            prompt_sha256=prompt_sha,
            tool_version=(scan.get("producer") or {}).get("version"),
        )
        findings, meta = registry.normalize_codex_security(
            doc, ctx, manifest=manifest, coverage=coverage)
        native_by_id = {str(item.get("findingId")): item
                        for item in (doc.get("findings") or [])
                        if isinstance(item, dict) and item.get("findingId")}
        for finding in findings:
            native_id = finding.fingerprints.source_fingerprints.get(
                "codex-security:codexSecurity/findingId")
            native = native_by_id.get(str(native_id))
            if native is not None:
                finding.validation = _native_validation(
                    native, target=target, prompt_sha=prompt_sha, model=model)
        raw_count = len(doc.get("findings") or [])
        completeness = meta.get("completeness")
        completion = "complete" if completeness == "complete" else "partial"
        return ArmResult(
            name=self.name, kind=self.kind, family=self.family, ok=True, exit_code=0, error="",
            findings=findings, tool_version=str((scan.get("producer") or {}).get("version") or "unknown"),
            raw_path=str(raw_dir / "findings.json"),
            coverage={"raw_results": raw_count, "normalized": len(findings),
                      "completion": completion, "scan_id": meta.get("scan_id"),
                      "completeness": completeness, "model_unattested": True,
                      "skipped": dict(ctx.skipped),
                      "_source_runs": [SourceRun("codex-security", "agent_cli", "codex",
                                                 ran=True, may_decline=completion == "complete")]},
        )

    def _fail(self, error: str) -> ArmResult:
        return ArmResult(name=self.name, kind=self.kind, family=self.family, ok=False,
                         exit_code=None, error=error, findings=[])
