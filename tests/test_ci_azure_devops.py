"""Azure DevOps integration: ##vso escaping, gate-consistent issue splitting,
PR thread payload/posting, and the step template's shape."""
import io
import json
import pathlib

import yaml

from security_council.ci import azure_devops as azdo
from tests.test_orchestrator import FakeArm, _finding as orch_finding, _run as orch_run

TEMPLATE = pathlib.Path(__file__).parent.parent / "templates" / "security-council.yml"


def _row(sev="high", *, state="new", lifecycle="open", uri="app/x.py", line=9,
         baseline_state=None, suppression=None):
    return {"id": "abc123", "title": "SQLi in reports",
        "severity": {"label": sev},
        "taxonomy": {"cwe": ["CWE-89"]},
        "locations": [{"uri": uri, "start_line": line}],
        "baseline_state": baseline_state,
        "disposition": {"state": state, "lifecycle": lifecycle,
                        "sarif_suppression": suppression}}


MANIFEST = {"run_id": "r1", "exit_code": 1,
            "policy": {"fail_on_severity": "high", "gate_baseline": "all"}}


def test_split_matches_exit_gate_semantics():
    errors, warnings = azdo.split_findings([
        _row("critical"),
        _row("medium"),                                    # below threshold -> warning
        _row("high", state="refuted"),                     # demoted -> neither
        _row("high", lifecycle="suppressed",
             suppression={"status": "accepted"}),          # hidden -> neither
    ], MANIFEST)
    assert len(errors) == 1 and errors[0]["severity"]["label"] == "critical"
    assert len(warnings) == 1 and warnings[0]["severity"]["label"] == "medium"


def test_gate_baseline_new_demotes_baselined_to_warning():
    m = {**MANIFEST, "policy": {"fail_on_severity": "high", "gate_baseline": "new"}}
    errors, warnings = azdo.split_findings(
        [_row("high", baseline_state="unchanged"), _row("high", baseline_state="new")], m)
    assert len(errors) == 1 and errors[0]["baseline_state"] == "new"
    assert len(warnings) == 1


def test_logissue_lines_and_vso_escaping():
    row = _row("high")
    row["title"] = "evil]title;with\nnewline%stuff"
    row["locations"][0]["uri"] = "app/weird];name.py"
    [line] = azdo.logissue_lines([row], MANIFEST)
    assert line.startswith("##vso[task.logissue type=error;sourcepath=app/weird%5D%3Bname.py;linenumber=9]")
    assert "%0A" in line and "%25stuff" in line            # message escaping
    assert "\n" not in line and "]title" not in line.split("]", 1)[1][:20]


def test_logissue_cap_reports_dropped():
    rows = [_row("high") for _ in range(5)]
    lines = azdo.logissue_lines(rows, MANIFEST, max_issues=2)
    assert len(lines) == 3 and "3 further finding(s)" in lines[-1]


def test_pr_thread_payload_status_tracks_gate():
    active = azdo.pr_thread_payload([_row("high")], MANIFEST)
    assert active["status"] == "active"
    assert "gate FAILED" in active["comments"][0]["content"]
    assert "`app/x.py:9`" in active["comments"][0]["content"]
    clean = azdo.pr_thread_payload([], {**MANIFEST, "exit_code": 0})
    assert clean["status"] == "closed" and "clean" in clean["comments"][0]["content"]


def test_post_pr_thread_builds_server_url_and_auth():
    env = {"SYSTEM_TEAMFOUNDATIONCOLLECTIONURI": "https://tfs.corp.local/DefaultCollection/",
           "SYSTEM_TEAMPROJECT": "Sec", "BUILD_REPOSITORY_ID": "repo-guid",
           "SYSTEM_PULLREQUEST_PULLREQUESTID": "42", "SYSTEM_ACCESSTOKEN": "tok"}
    seen = {}

    class _Resp(io.StringIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout):
        seen["url"], seen["auth"] = req.full_url, req.get_header("Authorization")
        seen["body"] = json.loads(req.data)
        return _Resp()

    out = azdo.post_pr_thread(azdo.pr_thread_payload([_row()], MANIFEST), env, opener=opener)
    assert out["posted"] and out["status"] == 200
    assert seen["url"] == ("https://tfs.corp.local/DefaultCollection/Sec/_apis/git/"
                           "repositories/repo-guid/pullRequests/42/threads?api-version=6.0")
    assert seen["auth"] == "Bearer tok" and seen["body"]["status"] == "active"


def test_post_pr_thread_outside_pr_is_a_noop():
    out = azdo.post_pr_thread({"comments": []}, {"SYSTEM_TEAMPROJECT": "x"})
    assert out["posted"] is False and "not a PR build" in out["reason"]


def test_main_on_real_run_never_fails_build(tmp_path, capsys):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep")])]
    run = orch_run(arms, tmp_path)
    assert azdo.main([str(run.out_dir), "--post-pr-thread", "--dry-run"]) == 0
    out = capsys.readouterr()
    assert "##vso[task.logissue type=error" in out.out
    assert "##vso[task.uploadsummary]" in out.out
    assert "not a PR build" in out.err or "dry run" in out.err
    assert azdo.main([str(tmp_path / "nope")]) == 0        # missing run dir: warn, exit 0


def test_template_parses_and_wires_the_pieces():
    doc = yaml.safe_load(TEMPLATE.read_text())
    params = {p["name"] for p in doc["parameters"]}
    assert {"scanPath", "arms", "failOnSeverity", "gateBaseline", "postPrThread"} <= params
    text = TEMPLATE.read_text()
    assert "security_council.cli scan" in text and "--gate-baseline" in text
    assert "security_council.ci.azure_devops" in text
    assert text.count("CodeAnalysisLogs") >= 2
    assert "System.AccessToken" in text
    gate = doc["steps"][-1]
    assert gate["condition"] == "always()" and "securityCouncilExit" in gate["bash"]

def test_baselined_high_assurance_is_an_error_not_a_warning():
    """R12 round 9: the split claims "the same filter as the exit gate" but had
    no equivalent of G9's `baseline_ineligible`, so a BASELINED crypto/critical
    finding was annotated a warning while the gate failed the build. `ci` and
    `gov` both set gate_baseline "new", so this was reachable by default."""
    from security_council.ci.azure_devops import split_findings
    manifest = {"policy": {"fail_on_severity": "high", "gate_baseline": "new"}}
    base = {"disposition": {"lifecycle": "open", "state": "new"},
            "baseline_state": "unchanged", "taxonomy": {"cwe": ["CWE-89"]}}
    critical = {**base, "severity": {"label": "critical"}}
    crypto = {**base, "severity": {"label": "high"},
              "taxonomy": {"cwe": ["CWE-327"], "cwe_family": "crypto"}}
    ordinary = {**base, "severity": {"label": "high"}}
    errors, warnings = split_findings([critical, crypto, ordinary], manifest)
    assert critical in errors and crypto in errors      # G9: never excused by a baseline
    assert ordinary in warnings                         # an ordinary baselined finding still is
