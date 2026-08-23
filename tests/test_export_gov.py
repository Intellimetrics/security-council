"""OpenVEX + OSCAL AR/POA&M exporters, validated against the vendored schemas
(official OpenVEX 0.2.0; a hand-authored OSCAL 1.1.2 conformance subset).
Everything renders from the finding disposition (D7)."""
import json
import pathlib

import jsonschema

from security_council import model as m
from security_council.cli import main as cli_main
from security_council.export import oscal, vex
from tests.test_export_emass import _f
from tests.test_orchestrator import FakeArm, _finding as orch_finding, _run as orch_run

HERE = pathlib.Path(__file__).parent
VEX_SCHEMA = json.load(open(HERE / "fixtures" / "schemas" / "openvex-0.2.0.schema.json"))
OSCAL_SCHEMA = json.load(open(HERE / "fixtures" / "schemas" / "oscal-conformance.schema.json"))
MANIFEST = {"run_id": "r1", "started_at": "2026-08-23T12:00:00Z",
            "finished_at": "2026-08-23T12:05:00Z", "tool": {"security_council": "0.1.0"},
            "target": {"root": "/srv/app", "git_commit": "abcdef1234567890"}}


def _suppressed(f):
    f.disposition.lifecycle = "suppressed"
    f.disposition.decided_by = m.DecidedBy(kind="human", decided_at="t", operator="o")
    f.disposition.decision_ref = "decision:root_cause:x"
    f.disposition.expires_at = "2026-11-20T00:00:00Z"
    f.disposition.vex_status = "not_affected"
    f.disposition.vex_justification = "inline_mitigations_already_exist"
    return f


def _validated(f):
    f.validation = m.Validation(verdict="true_positive", confidence=0.9)
    f.disposition.state = "validated"
    f.remediation = m.Remediation(summary="Use parameterized queries.")
    return f


# --------------------------------------------------------------------------- #
# OpenVEX
# --------------------------------------------------------------------------- #


def test_openvex_document_validates_and_maps_status():
    findings = [_suppressed(_f("CWE-89", "injection", rc="a")),
                _validated(_f("CWE-79", "xss", rc="b")),
                _f("CWE-798", "secrets", rc="c")]           # new/open → under_investigation
    doc = vex.to_openvex(findings, MANIFEST, author="isso@agency.gov")
    jsonschema.validate(instance=doc, schema=VEX_SCHEMA)
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0" and doc["version"] == 1
    st = {s["vulnerability"]["name"]: s for s in doc["statements"]}
    a = st["security-council/" + findings[0].id]
    assert a["status"] == "not_affected" and a["justification"] == "inline_mitigations_already_exist"
    b = st["security-council/" + findings[1].id]
    assert b["status"] == "affected" and "parameterized" in b["action_statement"]
    c = st["security-council/" + findings[2].id]
    assert c["status"] == "under_investigation"


def test_openvex_refuted_unreachable_is_not_affected():
    f = _f("CWE-89", "injection", rc="r")
    f.disposition.state = "refuted"
    f.validation = m.Validation(verdict="false_positive", confidence=0.9,
                                reachability=m.Reachability(verdict="unreachable"))
    status, just, _ = vex.render_status(f)
    assert status == "not_affected" and just == "vulnerable_code_not_in_execute_path"
    # a refuted finding WITHOUT a justification stays under_investigation
    f2 = _f("CWE-89", "injection", rc="r2")
    f2.disposition.state = "refuted"
    assert vex.render_status(f2)[0] == "under_investigation"


def test_openvex_supply_chain_uses_advisory_id():
    f = _f("CWE-1395", "supply_chain", rc="s")
    f.package = m.PackageRef(purl="pkg:pypi/urllib3", advisory_ids=["CVE-2025-1234", "GHSA-xxxx"])
    doc = vex.to_openvex([f], MANIFEST)
    jsonschema.validate(instance=doc, schema=VEX_SCHEMA)
    v = doc["statements"][0]["vulnerability"]
    assert v["name"] == "CVE-2025-1234" and "GHSA-xxxx" in v["aliases"]


# --------------------------------------------------------------------------- #
# OSCAL Assessment Results
# --------------------------------------------------------------------------- #


def test_oscal_ar_validates_and_is_deterministic():
    findings = [_validated(_f("CWE-89", "injection", rc="a")),
                _suppressed(_f("CWE-798", "secrets", rc="b"))]
    doc = oscal.to_oscal_ar(findings, MANIFEST)
    jsonschema.validate(instance=doc, schema=OSCAL_SCHEMA)
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    res = ar["results"][0]
    assert len(res["observations"]) == 2 and len(res["findings"]) == 2 and len(res["risks"]) == 2
    # disposition → risk status + finding target state (D7), keyed by derived uuid
    risks = {r["uuid"]: r["status"] for r in res["risks"]}
    fstate = {fd["uuid"]: fd["target"]["status"]["state"] for fd in res["findings"]}
    assert risks[oscal._uuid("risk", findings[0].id)] == "open"              # validated open
    assert risks[oscal._uuid("risk", findings[1].id)] == "deviation-approved"  # suppressed
    assert fstate[oscal._uuid("finding", findings[0].id)] == "not-satisfied"
    assert fstate[oscal._uuid("finding", findings[1].id)] == "satisfied"
    # deterministic: same input → identical uuids
    assert oscal.to_oscal_ar(findings, MANIFEST) == doc
    # observations/findings/risks cross-reference by uuid
    obs_uuid = res["observations"][0]["uuid"]
    assert any(fd["related-observations"][0]["observation-uuid"] == obs_uuid
               for fd in res["findings"])


def test_oscal_poam_only_lists_actionable():
    validated = _validated(_f("CWE-89", "injection", rc="a"))
    suppressed = _suppressed(_f("CWE-798", "secrets", rc="b"))
    refuted = _f("CWE-79", "xss", rc="c")
    refuted.disposition.state = "refuted"
    doc = oscal.to_oscal_poam([validated, suppressed, refuted], MANIFEST)
    jsonschema.validate(instance=doc, schema=OSCAL_SCHEMA)
    poam = doc["plan-of-action-and-milestones"]
    titles = [i["title"] for i in poam["poam-items"]]
    # only the open, non-refuted, non-suppressed finding is actionable
    assert len(titles) == 1 and validated.title in titles[0]
    assert titles[0].startswith("HIGH:")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_report_gov_formats(tmp_path, capsys):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep")])]
    run = orch_run(arms, tmp_path)
    assert cli_main(["report", str(run.out_dir), "--format", "openvex"]) == 0
    jsonschema.validate(instance=json.loads(capsys.readouterr().out), schema=VEX_SCHEMA)
    assert cli_main(["report", str(run.out_dir), "--format", "oscal-ar"]) == 0
    jsonschema.validate(instance=json.loads(capsys.readouterr().out), schema=OSCAL_SCHEMA)
    assert cli_main(["report", str(run.out_dir), "--format", "oscal-poam"]) == 0
    jsonschema.validate(instance=json.loads(capsys.readouterr().out), schema=OSCAL_SCHEMA)
