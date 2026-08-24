"""SBOM arm (syft -> CycloneDX artifact) + findings-into-SBOM merge."""

import json


from security_council import model as m
from security_council import proc
from security_council.arms import sbom as sbom_mod
from security_council.export import cyclonedx
from tests.test_cluster import mk
from tests.test_export_formats import MANIFEST, _bom_validator, _pkg_finding

FAKE_SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555", "version": 1,
    "metadata": {
        "component": {"type": "application", "bom-ref": "app:repo", "name": "repo"},
        "tools": {"components": [{"type": "application", "name": "syft",
                                  "version": "1.20.0"}]},
    },
    "components": [
        {"type": "library", "bom-ref": "pkg:pypi/flask@0.12", "name": "flask",
         "version": "0.12", "purl": "pkg:pypi/flask@0.12"},
        {"type": "library", "bom-ref": "pkg:pypi/requests@2.31.0", "name": "requests",
         "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
    ],
}


def _fake_proc(stdout="", *, ok=True, exit_code=0, stderr="", timed_out=False):
    def runner(cmd, **kw):
        return proc.ProcResult(ok, exit_code, stdout, stderr, 0.1, timed_out)
    return runner


def test_sbom_arm_produces_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(proc, "run_command", _fake_proc(json.dumps(FAKE_SBOM)))
    arm = sbom_mod.SbomArm()
    res = arm.run(tmp_path, tmp_path / "out", run_id="r1", collected_at="2026-08-24T00:00:00Z")
    assert res.ok and res.kind == "artifact" and res.findings == []
    assert res.tool_version == "1.20.0"                       # parsed from syft's own tools
    assert res.coverage["components"] == 2
    art = res.artifacts[0]
    assert art["kind"] == "sbom" and art["path"] == "raw/sbom/sbom.cdx.json"
    assert art["export_excluded"] is False and art["dual_use"] is False
    written = json.loads((tmp_path / "out" / "raw" / "sbom" / "sbom.cdx.json").read_text())
    assert written["bomFormat"] == "CycloneDX"


def test_sbom_arm_fails_closed(tmp_path, monkeypatch):
    for kwargs, why in [
        (dict(stdout="not json", ok=True), "non-JSON"),
        (dict(stdout="{}", ok=True), "not CycloneDX"),
        (dict(stdout="", ok=False, exit_code=3, stderr="boom"), "syft failed"),
        (dict(stdout="", ok=False, timed_out=True), "timed out"),
    ]:
        monkeypatch.setattr(proc, "run_command", _fake_proc(**kwargs))
        res = sbom_mod.SbomArm().run(tmp_path, tmp_path / "out",
                                     run_id="r1", collected_at="t")
        assert not res.ok and res.artifacts == [], why
        assert res.findings == []


def test_merge_into_sbom_validates_and_resolves_refs():
    sast = mk(path="app/x.py", cwe="CWE-89", family="injection",
              source_id="semgrep", source_kind="scanner", vendor="semgrep")
    flask = _pkg_finding()                                    # purl pkg:pypi/flask
    stray = mk(path="requirements.txt", cwe="CWE-1395", family="supply_chain",
               source_id="osv-scanner", source_kind="scanner", vendor="osv",
               package=m.PackageRef(purl="pkg:pypi/left-pad",
                                    advisory_ids=["GHSA-xxxx-yyyy-zzzz"]))
    doc, meta = cyclonedx.to_cyclonedx([sast, flask, stray], MANIFEST, sbom=FAKE_SBOM)
    _bom_validator().validate(doc)
    assert doc["serialNumber"] == FAKE_SBOM["serialNumber"]   # syft identity preserved
    tool_names = [c["name"] for c in doc["metadata"]["tools"]["components"]]
    assert tool_names == ["syft", "security-council"]
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    # flask vuln resolves to syft's inventory component (version-less purl match)
    assert by_id["GHSA-562c-5r94-xh97"]["affects"][0]["ref"] == "pkg:pypi/flask@0.12"
    # a package missing from the inventory is appended minimally, not dropped
    assert by_id["GHSA-xxxx-yyyy-zzzz"]["affects"][0]["ref"] == "pkg:pypi/left-pad"
    assert any(c.get("purl") == "pkg:pypi/left-pad" for c in doc["components"])
    # SAST finding affects the root component
    assert by_id[f"security-council/{sast.id}"]["affects"][0]["ref"] == "app:repo"
    assert meta["matched_inventory_refs"] == 1 and meta["sbom_components"] == 3
    assert FAKE_SBOM.get("vulnerabilities") is None           # caller's copy untouched


def test_merge_handles_legacy_tools_array_and_missing_root():
    legacy = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
              "metadata": {"tools": [{"name": "syft", "version": "0.9"}]},
              "components": []}
    f = mk(path="app/x.py", cwe="CWE-89", family="injection",
           source_id="semgrep", source_kind="scanner", vendor="semgrep")
    doc, _ = cyclonedx.to_cyclonedx([f], MANIFEST, sbom=legacy)
    assert {"name": "security-council", "version": "0.1.0"} in doc["metadata"]["tools"]
    root_ref = doc["metadata"]["component"]["bom-ref"]        # synthesized root
    assert doc["vulnerabilities"][0]["affects"][0]["ref"] == root_ref


def test_cli_load_sbom_reads_artifact(tmp_path):
    from security_council.cli import _load_sbom
    run = tmp_path
    (run / "raw" / "sbom").mkdir(parents=True)
    (run / "raw" / "sbom" / "sbom.cdx.json").write_text(json.dumps(FAKE_SBOM))
    manifest = {"artifacts": [{"kind": "sbom", "path": "raw/sbom/sbom.cdx.json"}]}
    assert _load_sbom(run, manifest)["bomFormat"] == "CycloneDX"
    assert _load_sbom(run, {"artifacts": []}) is None
    assert _load_sbom(run, {"artifacts": [{"kind": "sbom", "path": "raw/nope.json"}]}) is None


def test_sbom_arm_available_reports_docker_or_local():
    ok, detail = sbom_mod.SbomArm().available()
    assert ok in (True, False) and detail
