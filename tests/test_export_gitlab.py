"""GitLab exporters, validated against the OFFICIAL vendored schema
(sast-report-format.json 15.2.4, draft-07) — plus the Code Quality subset."""
import json
import pathlib

import jsonschema

from security_council import model as m
from security_council.cli import main as cli_main
from security_council.export import gitlab as gl
from tests.test_export_emass import _f
from tests.test_orchestrator import FakeArm, _finding as orch_finding, _run as orch_run

HERE = pathlib.Path(__file__).parent
SCHEMA = json.load(open(HERE / "fixtures" / "schemas" / "gitlab-sast-report-15.2.4.schema.json"))
MANIFEST = {"run_id": "r1", "started_at": "2026-08-23T12:00:00Z",
            "finished_at": "2026-08-23T12:05:30+00:00", "exit_code": 1}


def test_sast_report_validates_against_official_schema():
    doc, meta = gl.to_gitlab_sast(
        [_f("CWE-89", "injection", "high", rc="a"),
         _f("CWE-916", "crypto", "medium", rc="b")], MANIFEST)
    jsonschema.validate(instance=doc, schema=SCHEMA)
    assert doc["version"] == "15.2.4"
    assert doc["scan"]["type"] == "sast" and doc["scan"]["status"] == "success"
    # the classic gotcha: schema times are timezone-less
    assert doc["scan"]["start_time"] == "2026-08-23T12:00:00"
    assert doc["scan"]["end_time"] == "2026-08-23T12:05:30"
    assert meta == {"vulnerabilities": 2, "withheld_by_disposition": 0}


def test_vulnerability_shape_ids_and_identifiers():
    f = _f("CWE-89", "injection", "critical", rc="a")
    doc, _ = gl.to_gitlab_sast([f], MANIFEST)
    [v] = doc["vulnerabilities"]
    assert v["id"] == f.id and v["severity"] == "Critical"
    assert v["identifiers"][0] == {"type": "cwe", "name": "CWE-89", "value": "89",
                                   "url": "https://cwe.mitre.org/data/definitions/89.html"}
    assert v["identifiers"][-1]["type"] == "security_council_rule"
    assert v["location"] == {"file": "app/reports.py", "start_line": 9, "end_line": 9}


def test_noinfo_cwe_still_has_an_identifier():
    doc, _ = gl.to_gitlab_sast([_f("CWE-noinfo", "other", rc="n")], MANIFEST)
    jsonschema.validate(instance=doc, schema=SCHEMA)
    [v] = doc["vulnerabilities"]
    assert len(v["identifiers"]) == 1                 # rule id satisfies minItems 1
    assert v["identifiers"][0]["type"] == "security_council_rule"


def test_disposition_withholding_shared_with_other_exports():
    suppressed = _f("CWE-89", "injection", rc="s")
    suppressed.disposition.lifecycle = "suppressed"
    suppressed.disposition.decided_by = m.DecidedBy(kind="human", decided_at="t", operator="o")
    suppressed.disposition.decision_ref = "decision:root_cause:x"
    suppressed.disposition.expires_at = "2026-11-20T00:00:00Z"
    refuted = _f("CWE-79", "xss", rc="r")
    refuted.disposition.state = "refuted"
    doc, meta = gl.to_gitlab_sast([suppressed, refuted], MANIFEST)
    assert doc["vulnerabilities"] == [] and meta["withheld_by_disposition"] == 2
    rows, q_meta = gl.to_gitlab_code_quality([suppressed, refuted])
    assert rows == [] and q_meta["withheld_by_disposition"] == 2


def test_code_quality_subset_and_severity_map():
    rows, meta = gl.to_gitlab_code_quality([
        _f("CWE-89", "injection", "critical", rc="a"),
        _f("CWE-916", "crypto", "low", rc="b")])
    assert meta["rows"] == 2
    assert rows[0] == {"description": "[CWE-89] SQLi in reports",
                       "check_name": "r", "fingerprint": rows[0]["fingerprint"],
                       "severity": "blocker",
                       "location": {"path": "app/reports.py", "lines": {"begin": 9}}}
    assert rows[1]["severity"] == "minor"
    assert rows[0]["fingerprint"] != rows[1]["fingerprint"]   # stable derived ids
    for r in rows:                                            # documented required keys
        assert {"description", "check_name", "fingerprint", "severity", "location"} <= set(r)


def test_cli_report_gitlab_formats(tmp_path, capsys):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep")])]
    run = orch_run(arms, tmp_path)
    assert cli_main(["report", str(run.out_dir), "--format", "gitlab-sast"]) == 0
    doc = json.loads(capsys.readouterr().out)
    jsonschema.validate(instance=doc, schema=SCHEMA)
    assert doc["vulnerabilities"][0]["identifiers"][0]["value"] == "89"
    assert cli_main(["report", str(run.out_dir), "--format", "gitlab-codequality"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["severity"] == "critical"                  # high -> CodeClimate critical