"""Canonical artifact import arms used by consolidated reports."""

import json
import shutil
from pathlib import Path

from security_council.arms.import_bundle import (
    CodexSecurityBundleImportArm,
    SecurityCouncilRunImportArm,
)
from security_council.manifest import build_manifest
from security_council.normalize import coverage

HERE = Path(__file__).parent
SEED = HERE / "fixtures" / "seedrepo"
CX_DIR = HERE / "fixtures" / "raw" / "codex-security"
PRIOR = SEED / ".security-council" / "runs" / "20260829_123340"


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    shutil.copytree(SEED, target)
    return target


def test_prior_security_council_run_import_preserves_sources(tmp_path):
    target = _target(tmp_path)
    arm = SecurityCouncilRunImportArm(run_dir=PRIOR)
    arm.bind_target(target=target, git_info={
        "git_commit": "d918a4e148e7ff3ae3c49725cbc497bb1a7f7c36", "dirty": False})

    result = arm.run(target, tmp_path / "out", run_id="r", collected_at="2026-08-29T00:00:00Z")

    assert result.ok and len(result.findings) == 2
    assert result.coverage["imported_run_id"] == "20260829_123340"
    [source] = coverage.source_runs_for(result)
    assert source.source_id == "semgrep" and source.kind == "scanner" and source.may_decline
    assert (tmp_path / "out" / "raw" / arm.name / "manifest.json").is_file()


def test_prior_run_import_rejects_revision_mismatch(tmp_path):
    target = _target(tmp_path)
    arm = SecurityCouncilRunImportArm(run_dir=PRIOR)
    arm.bind_target(target=target, git_info={"git_commit": "wrong", "dirty": False})

    result = arm.run(target, tmp_path / "out", run_id="r", collected_at="now")

    assert not result.ok and "revision mismatch" in result.error


def test_sealed_codex_bundle_import_normalizes_and_attests_snapshot(tmp_path):
    target = _target(tmp_path)
    bundle = tmp_path / "bundle"
    shutil.copytree(CX_DIR, bundle)
    manifest_path = bundle / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["target"]["revision"] = "abc123"
    manifest_path.write_text(json.dumps(manifest))
    arm = CodexSecurityBundleImportArm(bundle_dir=bundle, model_hint="gpt-daybreak-blue-latest")
    arm.bind_target(target=target, git_info={"git_commit": "abc123", "dirty": False})

    result = arm.run(target, tmp_path / "out", run_id="r", collected_at="2026-08-29T00:00:00Z")

    assert result.ok and len(result.findings) == 4
    assert result.coverage["completion"] == "complete"
    assert result.coverage["model_unattested"] is True
    validated = [finding for finding in result.findings if finding.validation is not None]
    assert len(validated) == 1
    [opinion] = validated[0].validation.panel
    assert opinion.participant == "codex-current"
    assert opinion.verdict == "true_positive"
    assert opinion.citations and all(citation.verified for citation in opinion.citations)
    [source] = coverage.source_runs_for(result)
    assert source.source_id == "codex-security" and source.family == "codex"


def test_codex_bundle_import_rejects_dirty_target(tmp_path):
    target = _target(tmp_path)
    arm = CodexSecurityBundleImportArm(bundle_dir=CX_DIR)
    arm.bind_target(target=target, git_info={"git_commit": "abc", "dirty": True})

    result = arm.run(target, tmp_path / "out", run_id="r", collected_at="now")

    assert not result.ok and "dirty" in result.error


def test_manifest_records_import_identity(tmp_path):
    target = _target(tmp_path)
    arm = SecurityCouncilRunImportArm(run_dir=PRIOR)
    arm.bind_target(target=target, git_info={
        "git_commit": "d918a4e148e7ff3ae3c49725cbc497bb1a7f7c36", "dirty": False})
    result = arm.run(target, tmp_path / "out", run_id="r", collected_at="2026-08-29T00:00:00Z")

    manifest = build_manifest(
        run_id="r", target=str(target), arm_results=[result], merged=result.findings,
        config={}, started_at="2026-08-29T00:00:00Z", finished_at="2026-08-29T00:00:01Z",
        git={}, degradations=[], reports=[])

    [row] = manifest["arms"]
    assert row["imported_run_id"] == "20260829_123340"
    assert row["imported_sources"] == ["semgrep"]
