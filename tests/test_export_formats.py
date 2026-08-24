"""CSV / CKLB / CycloneDX / HTML exporters: contract shape, D7 withholding,
hardened escaping boundaries, deterministic ids."""

import json
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from security_council import model as m
from security_council.export import cklb, csv_export, cyclonedx, html_export
from tests.test_cluster import mk

HERE = Path(__file__).parent
BOM_SCHEMA = json.load(open(HERE / "fixtures" / "schemas" / "bom-1.6.schema.json"))
CKLB_SCHEMA = json.load(open(HERE / "fixtures" / "schemas" / "cklb-conformance.schema.json"))

MANIFEST = {
    "run_id": "20260824_000000",
    "started_at": "2026-08-24T00:00:00Z", "finished_at": "2026-08-24T00:01:00Z",
    "tool": {"security_council": "0.1.0"},
    "target": {"root": "/repo/acme-app", "git_commit": "a" * 40},
    "counts": {"total": 2, "by_severity": {"high": 2}, "by_state": {"new": 2}},
    "arms": [{"name": "semgrep", "kind": "scanner", "ok": True, "tool_version": "1.173.0",
              "raw_results": 5, "normalized": 5, "elapsed_seconds": 3.2}],
    "exit_code": 1, "degradations": [], "reports": [],
}


def _suppressed(f):
    f.disposition.lifecycle = "suppressed"
    f.disposition.state = "validated"
    f.disposition.vex_status = "not_affected"
    f.disposition.vex_justification = "inline_mitigations_already_exist"
    return f


def _pkg_finding():
    pkg = m.PackageRef(purl="pkg:pypi/flask", version="0.12",
                       advisory_ids=["GHSA-562c-5r94-xh97"])
    return mk(path="requirements.txt", cwe="CWE-1395", family="supply_chain",
              source_id="osv-scanner", source_kind="scanner", vendor="osv", package=pkg)


# --- CSV ---

def test_csv_includes_demoted_and_neutralizes_formula_injection():
    hostile = mk(path="app/x.py", cwe="CWE-89", family="injection",
                 source_id="semgrep", source_kind="scanner", vendor="semgrep")
    hostile.title = "=cmd|' /C calc'!A0 injected title"
    sup = _suppressed(mk(path="app/y.py", cwe="CWE-79", family="xss",
                         source_id="semgrep", source_kind="scanner", vendor="semgrep"))
    out = csv_export.to_csv([hostile, sup])
    lines = out.strip().split("\n")
    assert lines[0].startswith('"finding_id"')
    assert len(lines) == 3                                  # triage export hides nothing
    assert '"\'=cmd' in out                                 # formula neutralized, visible
    assert '"suppressed"' in out                            # state spelled out, not hidden


# --- CKLB ---

def test_cklb_shape_mapping_and_statuses():
    sqli = mk(path="src/A.java", cwe="CWE-89", family="injection",
              source_id="semgrep", source_kind="scanner", vendor="semgrep")
    weird = mk(path="src/B.java", cwe="CWE-1004", family="other",
               source_id="semgrep", source_kind="scanner", vendor="semgrep")
    sup = _suppressed(mk(path="src/C.java", cwe="CWE-79", family="xss",
                         source_id="semgrep", source_kind="scanner", vendor="semgrep"))
    doc, meta = cklb.to_cklb([sqli, weird, sup], MANIFEST)
    # conformance subset derived from the DoD reference producer (STIG Manager)
    # + the official DISA STIG Viewer 3.x User Guide status vocabulary
    jsonschema.validate(instance=doc, schema=CKLB_SCHEMA)
    stig = doc["stigs"][0]
    assert stig["stig_id"] == "Application_Security_Development_STIG"
    assert stig["version"] == "6" and "Release: 4" in stig["release_info"]
    assert stig["size"] == len(stig["rules"]) == meta["rules_total"]
    by_ver = {r["rule_version"]: r for r in stig["rules"]}
    assert by_ver["APSC-DV-002540"]["status"] == "open"          # SQLi -> exact CWE rule
    assert sqli.id in by_ver["APSC-DV-002540"]["finding_details"]
    assert by_ver[cklb.CATCH_ALL]["status"] == "open"            # unmapped -> code review
    assert meta["catch_all_findings"] == 1
    # suppressed finding withheld (D7): its rule stays not_reviewed, never not_a_finding
    assert by_ver["APSC-DV-002490"]["status"] == "not_reviewed"
    assert meta["withheld_by_disposition"] == 1
    assert all(r["status"] in ("open", "not_reviewed") for r in stig["rules"])
    # embedded metadata is the real STIG's (verbatim from the official XCCDF)
    r = by_ver["APSC-DV-002540"]
    assert r["group_id"] == "V-222607" and r["rule_id"] == "SV-222607r961158"
    assert r["severity"] == "high" and r["ccis"]
    assert r["check_content"] and r["fix_text"] and r["discussion"]
    # deterministic uuids for a given run id
    doc2, _ = cklb.to_cklb([sqli, weird, sup], MANIFEST)
    assert doc2["id"] == doc["id"] and doc2["stigs"][0]["uuid"] == stig["uuid"]


def test_cklb_exact_cwe_beats_family_and_table_is_consistent():
    weakrand = mk(path="src/R.java", cwe="CWE-330", family="crypto",
                  source_id="semgrep", source_kind="scanner", vendor="semgrep")
    assert cklb.rule_for(weakrand) == "APSC-DV-002290"           # not the crypto default
    rules = json.loads(cklb.RULES_PATH.read_text())["rules"]
    for target in list(cklb.CWE_TO_RULE.values()) + list(cklb.FAMILY_TO_RULE.values()) \
            + [cklb.CATCH_ALL]:
        assert target in rules, f"mapping targets missing vendored rule {target}"


# --- CycloneDX ---

def _bom_validator():
    registry = Registry().with_resources([
        ("spdx.schema.json", Resource.from_contents(
            json.load(open(HERE / "fixtures" / "schemas" / "spdx.schema.json")))),
        ("jsf-0.82.schema.json", Resource.from_contents(
            json.load(open(HERE / "fixtures" / "schemas" / "jsf-0.82.schema.json")))),
    ])
    return jsonschema.Draft7Validator(BOM_SCHEMA, registry=registry)


def test_cyclonedx_validates_and_withholds():
    sast = mk(path="app/x.py", cwe="CWE-89", family="injection",
              source_id="semgrep", source_kind="scanner", vendor="semgrep")
    sup = _suppressed(mk(path="app/y.py", cwe="CWE-79", family="xss",
                         source_id="semgrep", source_kind="scanner", vendor="semgrep"))
    doc, meta = cyclonedx.to_cyclonedx([sast, _pkg_finding(), sup], MANIFEST)
    _bom_validator().validate(doc)                               # official 1.6 schema
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert meta["vulnerabilities"] == 2 and meta["withheld_by_disposition"] == 1
    # affects refs all resolve to declared bom-refs
    refs = {doc["metadata"]["component"]["bom-ref"]} | {c["bom-ref"] for c in doc["components"]}
    for v in doc["vulnerabilities"]:
        assert all(a["ref"] in refs for a in v["affects"])
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    assert "GHSA-562c-5r94-xh97" in by_id                        # advisory id kept
    assert by_id["GHSA-562c-5r94-xh97"]["affects"][0]["ref"] == "pkg:pypi/flask"
    sast_v = by_id[f"security-council/{sast.id}"]
    assert sast_v["cwes"] == [89]
    # deterministic serial number
    doc2, _ = cyclonedx.to_cyclonedx([sast, _pkg_finding(), sup], MANIFEST)
    assert doc2["serialNumber"] == doc["serialNumber"]


# --- HTML ---

def test_html_escapes_hostile_text_and_keeps_demoted_visible():
    hostile = mk(path="app/x.py", cwe="CWE-89", family="injection",
                 source_id="semgrep", source_kind="scanner", vendor="semgrep")
    hostile.title = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    sup = _suppressed(mk(path="app/y.py", cwe="CWE-79", family="xss",
                         source_id="semgrep", source_kind="scanner", vendor="semgrep"))
    page = html_export.to_html([hostile, sup], MANIFEST)
    # hostile markup can never re-form a tag: raw < is escaped everywhere
    assert "<script" not in page and "<img" not in page
    assert "&lt;script&gt;" in page                              # escaped, still shown
    assert "Appendix — demoted and closed findings" in page      # demoted-not-hidden
    assert "GATE: FAIL" in page
    # self-contained: no external fetches, no links, no JS anywhere in the page
    assert "http://" not in page and "https://" not in page
    assert "src=" not in page.replace("src=x", "")               # only the escaped text
    assert "javascript" not in page.lower()


def test_html_renders_fitted_scores_never_calibrated():
    f = mk(path="src/A.java", cwe="CWE-79", family="xss",
           source_id="semgrep", source_kind="scanner", vendor="semgrep")
    scores = {f.id: {"p": 0.6538, "measured_p": 0.6538, "clamps": [],
                     "record": "owasp-benchmark-java-1.2@2026-08-24"}}
    mf = dict(MANIFEST, calibration={"status": "active", "applied_findings": 1,
                                     "record": "owasp-benchmark-java-1.2@2026-08-24"})
    page = html_export.to_html([f], mf, scores=scores)
    assert "p 0.65 fitted" in page and "owasp-benchmark-java-1.2" in page
    assert "calibrat" not in page.lower()                        # banned word
