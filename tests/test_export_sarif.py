"""P3 tests: SARIF 2.1.0 export validates, round-trips, and hides no line numbers."""
import json
import pathlib
import re

import jsonschema

from security_council import jsonio, model as m
from security_council.export import sarif
from security_council.normalize import registry
from security_council.normalize.base import ParseContext

HERE = pathlib.Path(__file__).parent
FIX = HERE / "fixtures" / "seedrepo"
SCHEMA = json.load(open(HERE / "fixtures" / "schemas" / "sarif-2.1.0.json"))


def _real_findings():
    ctx = ParseContext(repo_root=FIX, scan_root="/src", source_id="semgrep",
                       source_kind="scanner", family="semgrep", tool_version="1.2.3",
                       collected_at="2026-08-20T00:00:00Z")
    return registry.normalize_sarif(json.load(open(HERE / "fixtures" / "raw" / "semgrep.sarif")),
                                    "semgrep", ctx)


def _suppressed_finding():
    from tests.test_model import valid_finding
    f = valid_finding()
    f.taxonomy = m.Taxonomy(cwe=["CWE-89"], cwe_family="injection")
    f.disposition.lifecycle = "accepted_risk"
    f.disposition.decided_by = m.DecidedBy(kind="human", decided_at="2026-08-20T00:00:00Z",
                                           operator="alice@agency.gov")
    f.disposition.decision_ref = ".security-council/decisions/x.json"
    f.disposition.expires_at = "2026-11-20T00:00:00Z"
    f.disposition.vex_status = "not_affected"
    f.disposition.vex_justification = "vulnerable_code_not_in_execute_path"
    m.assert_invariants(f)
    return f


def test_merged_sarif_validates_against_official_schema():
    s = sarif.to_sarif(_real_findings(), tool_version="0.0.1", run_id="run123")
    jsonschema.validate(instance=s, schema=SCHEMA)
    assert s["version"] == "2.1.0"
    assert s["runs"][0]["automationDetails"]["id"] == "security-council/run123"


def test_raw_sarif_one_run_per_source_validates():
    fs = _real_findings()
    s = sarif.raw_sarif({"semgrep": fs, "gitleaks": []})
    jsonschema.validate(instance=s, schema=SCHEMA)
    assert len(s["runs"]) == 2
    assert {r["tool"]["driver"]["name"] for r in s["runs"]} == {"semgrep", "gitleaks"}


def test_roundtrip_is_lossless():
    fs = _real_findings()
    s = sarif.to_sarif(fs)
    back = sarif.from_sarif(s)
    assert len(back) == len(fs)
    assert [jsonio.dumps(x) for x in back] == [jsonio.dumps(x) for x in fs]


def test_partial_fingerprints_have_no_line_numbers():
    s = sarif.to_sarif(_real_findings())
    hex32 = re.compile(r"^[0-9a-f]{32}$")
    for run in s["runs"]:
        for res in run["results"]:
            pf = res["partialFingerprints"]
            assert set(pf) == {"pathCweSink/v1", "contextHash/v1", "rootCause/v1"}
            for v in pf.values():
                assert hex32.match(v), f"fingerprint not line-free 32-hex: {v!r}"


def test_cwe_tags_and_severity_on_rule():
    s = sarif.to_sarif(_real_findings())
    rule = s["runs"][0]["tool"]["driver"]["rules"][0]
    assert any(t.startswith("external/cwe/cwe-89") for t in rule["properties"]["tags"])
    assert "security-severity" in rule["properties"]


def test_suppressed_finding_renders_and_validates():
    s = sarif.to_sarif([_suppressed_finding()])
    jsonschema.validate(instance=s, schema=SCHEMA)
    res = s["runs"][0]["results"][0]
    assert res["suppressions"][0]["status"] == "accepted"
    assert "execute_path" in res["suppressions"][0]["justification"]
    # and it still round-trips
    [back] = sarif.from_sarif(s)
    assert back.disposition.vex_status == "not_affected"


def test_from_sarif_ignores_results_without_property_bag():
    assert sarif.from_sarif({"runs": [{"results": [{"ruleId": "x"}]}]}) == []
