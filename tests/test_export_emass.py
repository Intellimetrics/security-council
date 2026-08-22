"""eMASS static-code-scans exporter: CWE-keyed aggregation, disposition
withholding, numeric-cweId conformance (validated against the vendored schema
converted from the official eMASSRestOpenApi.yaml), and the CLI path."""
import hashlib
import json
import pathlib

import jsonschema

from security_council import model as m
from security_council.cli import main as cli_main
from security_council.export import emass
from tests.test_orchestrator import FakeArm, _finding as orch_finding, _run as orch_run
from tests.test_validate import _finding

HERE = pathlib.Path(__file__).parent
SCHEMA = json.load(open(HERE / "fixtures" / "schemas" / "emass-static-code.schema.json"))


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _f(cwe, family, sev="high", rc="r1"):
    f = _finding(sev=sev)
    f.taxonomy.cwe = [cwe]
    f.taxonomy.cwe_family = family
    f.fingerprints = m.Fingerprints(
        path_cwe_sink="pathCweSink/v1:" + _sha(rc + "p")[:32],
        context_hash="contextHash/v1:" + _sha(rc + "c")[:32],
        root_cause="rootCause/v1:" + _sha(rc)[:32])
    f.id = m.finding_id(f.fingerprints)
    return f


def _export(findings, **kw):
    return emass.to_emass_static_code_scans(
        findings, application_name="seedapp", version="1.0",
        scan_date=1755864000, **kw)


def test_cwe_keyed_aggregation_and_severity():
    body, meta = _export([
        _f("CWE-89", "injection", "high", rc="a"),
        _f("CWE-89", "injection", "medium", rc="b"),      # same CWE, lower sev
        _f("CWE-916", "crypto", "medium", rc="c"),
    ])
    jsonschema.validate(instance=body, schema=SCHEMA)
    [doc] = body
    assert doc["application"] == {"applicationName": "seedapp", "version": "1.0"}
    rows = doc["applicationFindings"]
    assert [r["cweId"] for r in rows] == ["89", "916"]     # numeric string, sorted
    assert rows[0] == {"codeCheckName": "CWE-89 (injection)", "scanDate": 1755864000,
                       "cweId": "89", "count": 2, "rawSeverity": "High"}
    assert rows[1]["rawSeverity"] == "Moderate"            # medium -> RMF-native term
    assert meta["rows"] == 2 and meta["findings_exported"] == 3
    assert meta["withheld_by_disposition"] == 0 and meta["skipped"] == []


def test_disposition_withholding_matches_render_decision():
    suppressed = _f("CWE-89", "injection", rc="s")
    suppressed.disposition.lifecycle = "suppressed"
    suppressed.disposition.decided_by = m.DecidedBy(kind="human", decided_at="t", operator="o")
    suppressed.disposition.decision_ref = "decision:root_cause:x"
    suppressed.disposition.expires_at = "2026-11-20T00:00:00Z"
    refuted = _f("CWE-79", "xss", rc="r")
    refuted.disposition.state = "refuted"                  # demoted, stays open
    reopened = _f("CWE-79", "xss", rc="q")
    reopened.disposition.lifecycle = "reopened"            # reopened DOES export
    body, meta = _export([suppressed, refuted, reopened])
    [doc] = body
    assert [r["cweId"] for r in doc["applicationFindings"]] == ["79"]
    assert doc["applicationFindings"][0]["count"] == 1
    assert meta["withheld_by_disposition"] == 2


def test_noinfo_cwe_is_skipped_loudly_never_silently():
    ok = _f("CWE-89", "injection", rc="a")
    noinfo = _f("CWE-noinfo", "other", rc="n")
    body, meta = _export([ok, noinfo])
    jsonschema.validate(instance=body, schema=SCHEMA)
    assert len(body[0]["applicationFindings"]) == 1
    assert meta["skipped"] == [{"finding_id": noinfo.id,
                                "reason": "no numeric primary CWE",
                                "cwe": ["CWE-noinfo"]}]


def test_info_severity_omits_optional_rawSeverity():
    f = _f("CWE-532", "logging", rc="i")
    f.severity.label, f.severity.sarif_level, f.severity.security_severity = "info", "none", 0.0
    body, _ = _export([f])
    jsonschema.validate(instance=body, schema=SCHEMA)
    assert "rawSeverity" not in body[0]["applicationFindings"][0]


def test_clear_payload_matches_documented_form():
    body = emass.clear_findings_payload(application_name="seedapp", version="1.0")
    jsonschema.validate(instance=body, schema=SCHEMA)
    assert body[0]["applicationFindings"] == [{"clearFindings": True}]


def test_scan_date_from_manifest():
    assert emass.scan_date_from_manifest({"finished_at": "2026-08-22T12:00:00Z"}) == 1787400000
    assert emass.scan_date_from_manifest({"started_at": "2026-08-22T12:00:00+00:00"}) == 1787400000


def test_cli_report_emass(tmp_path, capsys):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep")])]
    run = orch_run(arms, tmp_path)
    assert cli_main(["report", str(run.out_dir), "--format", "emass",
                     "--app-name", "seedapp", "--app-version", "1.0"]) == 0
    out = capsys.readouterr()
    body = json.loads(out.out)
    jsonschema.validate(instance=body, schema=SCHEMA)
    assert body[0]["applicationFindings"][0]["cweId"] == "89"
    assert "1 rows from 1 findings" in out.err
    # missing identity -> usage error, and the clear form validates too
    assert cli_main(["report", str(run.out_dir), "--format", "emass"]) == 2
    assert cli_main(["report", str(run.out_dir), "--format", "emass", "--emass-clear",
                     "--app-name", "seedapp", "--app-version", "1.0"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body[0]["applicationFindings"] == [{"clearFindings": True}]
