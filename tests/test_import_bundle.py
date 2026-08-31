"""Canonical artifact import arms used by consolidated reports."""

import hashlib
import json
import shutil
from pathlib import Path

from security_council import fingerprint as fpr
from security_council import model as m
from security_council.arms.import_bundle import (
    CodexSecurityBundleImportArm,
    SecurityCouncilRunImportArm,
)
from security_council.jsonio import dumps, to_dict
from security_council.manifest import build_manifest
from security_council.normalize import coverage

HERE = Path(__file__).parent
SEED = HERE / "fixtures" / "seedrepo"
CX_DIR = HERE / "fixtures" / "raw" / "codex-security"
PRIOR_COMMIT = "d918a4e148e7ff3ae3c49725cbc497bb1a7f7c36"


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _scanner_finding(*, path="app/x.py", cwe="CWE-89", family="injection") -> m.Finding:
    sym = f"{path}:q"
    fps = m.Fingerprints(
        path_cwe_sink=fpr.path_cwe_sink(path=path, cwe=cwe, sink_token=sym),
        context_hash=fpr.context_hash(["stmt_q(x)"]),
        root_cause=fpr.root_cause(cwe_family=family, root_symbol=sym, sink_expr="q",
                                  package=None),
    )
    prov = m.ProvenanceEntry(
        source_id="semgrep", source_kind="scanner", family="semgrep",
        prompt_sha256="", collected_at="2026-08-29T00:00:00Z", tool_version="1.0")
    return m.Finding(
        id=m.finding_id(fps), schema_version=m.SCHEMA_VERSION, cluster_id=None,
        rule=m.RuleRef(id="sc/x", source="semgrep"),
        taxonomy=m.Taxonomy(cwe=[cwe], cwe_family=family),
        severity=m.SeverityBlock(label="high", sarif_level=m.SEVERITY_TO_SARIF_LEVEL["high"],
                                 security_severity=m.SEVERITY_TO_SECURITY_SEVERITY["high"]),
        locations=[m.CodeLocation(uri=path, start_line=10, end_line=12, role="primary",
                                  snippet_sha256=_sha(path))],
        fingerprints=fps, provenance=[prov],
        corroboration=m.Corroboration(deterministic_sources=["semgrep"], count=1),
        disposition=m.Disposition(state="new", lifecycle="open",
                                  decided_by=m.DecidedBy(kind="auto",
                                                         decided_at="2026-08-29T00:00:00Z")),
        title="t", description="d")


def _write_prior_run(tmp_path: Path, *, git_commit: str = PRIOR_COMMIT) -> Path:
    """A minimal canonical prior run: exactly the contract the import arm reads."""
    run_dir = tmp_path / "prior" / "20260829_123340"
    run_dir.mkdir(parents=True)
    findings = [_scanner_finding(), _scanner_finding(path="app/y.py", cwe="CWE-79",
                                                     family="xss")]
    (run_dir / "findings.json").write_text(dumps([to_dict(f) for f in findings]))
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": "20260829_123340",
        "target": {"root": "/somewhere", "git_commit": git_commit},
        "tool": {"security_council": "0.2.0"},
        "arms": [
            {"name": "semgrep", "kind": "scanner", "family": "semgrep",
             "coverage_verdict": "verified", "declined_families": []},
            {"name": "threat-model", "kind": "artifact", "family": "claude"},
        ],
    }))
    return run_dir


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    shutil.copytree(SEED, target)
    return target


def test_prior_security_council_run_import_preserves_sources(tmp_path):
    target = _target(tmp_path)
    arm = SecurityCouncilRunImportArm(run_dir=_write_prior_run(tmp_path))
    arm.bind_target(target=target, git_info={"git_commit": PRIOR_COMMIT, "dirty": False})

    result = arm.run(target, tmp_path / "out", run_id="r", collected_at="2026-08-29T00:00:00Z")

    assert result.ok and len(result.findings) == 2
    assert result.coverage["imported_run_id"] == "20260829_123340"
    [source] = coverage.source_runs_for(result)
    assert source.source_id == "semgrep" and source.kind == "scanner" and source.may_decline
    assert (tmp_path / "out" / "raw" / arm.name / "manifest.json").is_file()


def test_prior_run_import_rejects_revision_mismatch(tmp_path):
    target = _target(tmp_path)
    arm = SecurityCouncilRunImportArm(run_dir=_write_prior_run(tmp_path))
    arm.bind_target(target=target, git_info={"git_commit": "wrong", "dirty": False})

    result = arm.run(target, tmp_path / "out", run_id="r", collected_at="now")

    assert not result.ok and "revision mismatch" in result.error


def _sealed_bundle(tmp_path: Path, *, revision: str = "abc123") -> Path:
    bundle = tmp_path / "bundle"
    shutil.copytree(CX_DIR, bundle)
    manifest_path = bundle / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["target"]["revision"] = revision
    manifest_path.write_text(json.dumps(manifest))
    return bundle


def test_sealed_codex_bundle_import_normalizes_and_attests_snapshot(tmp_path):
    target = _target(tmp_path)
    bundle = _sealed_bundle(tmp_path)
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
    # a host-carried seat is evidence, never external cross-examination
    assert opinion.is_host and not opinion.independent   # advisory, never deciding
    assert not validated[0].validation.convened()
    assert validated[0].validation.external_families() == set()
    [source] = coverage.source_runs_for(result)
    assert source.source_id == "codex-security" and source.family == "codex"


def _reimport_with_validation(tmp_path, target, bundle: Path, validation: dict) -> m.Finding:
    findings_path = bundle / "findings.json"
    doc = json.loads(findings_path.read_text())
    validated = [f for f in doc["findings"] if f.get("validation")]
    assert validated, "fixture must carry one validated finding"
    validated[0]["validation"] = validation
    findings_path.write_text(json.dumps(doc))
    arm = CodexSecurityBundleImportArm(bundle_dir=bundle)
    arm.bind_target(target=target, git_info={"git_commit": "abc123", "dirty": False})
    result = arm.run(target, tmp_path / "out2", run_id="r", collected_at="2026-08-29T00:00:00Z")
    assert result.ok
    [f] = [f for f in result.findings if f.validation is not None]
    return f


def test_unrecognized_native_status_stays_uncertain_even_with_summary(tmp_path):
    # prose alone is not confirmation: the merged disposition and the VEX
    # export both trust this verdict, so unknown statuses must fail safe
    target = _target(tmp_path)
    bundle = _sealed_bundle(tmp_path)
    f = _reimport_with_validation(tmp_path, target, bundle, {
        "status": "reviewed", "summary": "long convincing prose about the finding"})
    assert f.validation.verdict == "uncertain"


def test_negated_native_status_never_reads_as_confirmation(tmp_path):
    target = _target(tmp_path)
    bundle = _sealed_bundle(tmp_path)
    f = _reimport_with_validation(tmp_path, target, bundle, {
        "status": "not confirmed", "summary": "could not reproduce"})
    assert f.validation.verdict == "uncertain"


def test_refuting_native_status_maps_to_false_positive(tmp_path):
    target = _target(tmp_path)
    bundle = _sealed_bundle(tmp_path)
    f = _reimport_with_validation(tmp_path, target, bundle, {
        "status": "refuted", "summary": "sink is unreachable"})
    assert f.validation.verdict == "false_positive"


def test_codex_bundle_import_rejects_dirty_target(tmp_path):
    target = _target(tmp_path)
    arm = CodexSecurityBundleImportArm(bundle_dir=CX_DIR)
    arm.bind_target(target=target, git_info={"git_commit": "abc", "dirty": True})

    result = arm.run(target, tmp_path / "out", run_id="r", collected_at="now")

    assert not result.ok and "dirty" in result.error


def test_manifest_records_import_identity(tmp_path):
    target = _target(tmp_path)
    arm = SecurityCouncilRunImportArm(run_dir=_write_prior_run(tmp_path))
    arm.bind_target(target=target, git_info={"git_commit": PRIOR_COMMIT, "dirty": False})
    result = arm.run(target, tmp_path / "out", run_id="r", collected_at="2026-08-29T00:00:00Z")

    manifest = build_manifest(
        run_id="r", target=str(target), arm_results=[result], merged=result.findings,
        config={}, started_at="2026-08-29T00:00:00Z", finished_at="2026-08-29T00:00:01Z",
        git={}, degradations=[], reports=[])

    [row] = manifest["arms"]
    assert row["imported_run_id"] == "20260829_123340"
    assert row["imported_sources"] == ["semgrep"]
