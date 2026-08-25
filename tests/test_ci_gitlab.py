"""GitLab CI glue (MR note, report writing, job template) and the GitHub
Action's composite shape."""
import io
import json
import pathlib

import yaml

from security_council.ci import gitlab as glci
from tests.test_ci_azure_devops import MANIFEST, _row
from tests.test_orchestrator import FakeArm, _finding as orch_finding, _run as orch_run

ROOT = pathlib.Path(__file__).parent.parent
GL_TEMPLATE = ROOT / "templates" / "security-council.gitlab-ci.yml"
ACTION = ROOT / "action.yml"


def test_mr_note_markdown_uses_gate_split():
    md = glci.mr_note_markdown([_row("critical"), _row("medium")], MANIFEST)
    assert "gate FAILED" in md and "1 gating · 1 non-gating" in md
    assert "`app/x.py:9`" in md
    clean = glci.mr_note_markdown([], {**MANIFEST, "exit_code": 0})
    assert "clean" in clean


def test_post_mr_note_env_token_and_url():
    env = {"CI_API_V4_URL": "https://gitlab.corp.local/api/v4", "CI_PROJECT_ID": "77",
           "CI_MERGE_REQUEST_IID": "5"}
    out = glci.post_mr_note("hi", env)
    assert out["posted"] is False and "no token" in out["reason"]
    out = glci.post_mr_note("hi", {})
    assert "not an MR pipeline" in out["reason"]

    seen = {}

    class _Resp(io.StringIO):
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout):
        seen["url"], seen["token"] = req.full_url, req.get_header("Private-token")
        seen["body"] = json.loads(req.data)
        return _Resp()

    env["SECURITY_COUNCIL_GITLAB_TOKEN"] = "glpat-x"
    out = glci.post_mr_note("**hello**", env, opener=opener)
    assert out["posted"] and out["status"] == 201
    assert seen["url"] == "https://gitlab.corp.local/api/v4/projects/77/merge_requests/5/notes"
    assert seen["token"] == "glpat-x" and seen["body"] == {"body": "**hello**"}


def test_main_writes_reports_and_never_fails(tmp_path, capsys):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep")])]
    run = orch_run(arms, tmp_path)
    out_dir = tmp_path / "ci-out"
    assert glci.main([str(run.out_dir), "--write-reports", str(out_dir),
                      "--post-mr-note", "--dry-run"]) == 0
    sast = json.loads((out_dir / "gl-sast-report.json").read_text())
    assert sast["version"] == "15.2.4" and len(sast["vulnerabilities"]) == 1
    quality = json.loads((out_dir / "gl-code-quality-report.json").read_text())
    assert quality[0]["fingerprint"] == sast["vulnerabilities"][0]["id"]
    err = capsys.readouterr().err
    assert "wrote" in err and "not an MR pipeline" in err
    assert glci.main([str(tmp_path / "nope")]) == 0


def test_gitlab_template_wires_reports_and_gate():
    doc = yaml.safe_load(GL_TEMPLATE.read_text())
    job = doc["security_council"]
    assert job["artifacts"]["reports"] == {"sast": "gl-sast-report.json",
                                           "codequality": "gl-code-quality-report.json"}
    assert job["artifacts"]["when"] == "always"
    script = "\n".join(job["script"])
    assert "security_council.cli scan" in script and "--gate-baseline" in script
    assert "security_council.ci.gitlab" in script and "--write-reports" in script
    # R12: SCAN_EXIT must be captured in the SAME script entry as the scan —
    # GitLab Runner runs each entry separately, so a `$?` on the next entry can
    # read that machinery's status and the job would pass with findings.
    scan_entry = next(e for e in job["script"] if "security_council.cli scan" in e)
    assert "SCAN_EXIT=$?" in scan_entry
    assert script.rstrip().endswith('exit "$(cat "$CI_PROJECT_DIR/.security-council-exit")"')


def test_github_action_composite_shape():
    doc = yaml.safe_load(ACTION.read_text())
    assert doc["runs"]["using"] == "composite"
    assert {"path", "arms", "fail-on-severity", "gate-baseline",
            "upload-sarif"} <= set(doc["inputs"])
    assert set(doc["outputs"]) == {"exit-code", "run-dir", "sarif-file"}
    steps = doc["runs"]["steps"]
    names = [s.get("name") for s in steps]
    assert names == ["Install security-council", "Scan", "Upload SARIF to code scanning",
                     "Publish step summary", "Gate"]
    upload = steps[2]
    assert upload["uses"].startswith("github/codeql-action/upload-sarif@")
    assert upload["with"]["category"] == "security-council"
    assert steps[1]["run"].strip().endswith("exit 0")          # capture, don't fail mid-flow
    assert "exit-code" in steps[-1]["run"]                     # gate re-raises