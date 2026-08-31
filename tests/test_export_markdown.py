"""Markdown executive summary: renders real findings, neutralizes hostile text,
surfaces attestation/degradation (D8), and never hides demoted findings."""
import dataclasses
import json
import pathlib
import re

from security_council import model as m
from security_council.arms.base import ArmResult
from security_council.cli import main as cli_main
from security_council.export import markdown
from security_council.manifest import build_manifest
from security_council.normalize import registry
from security_council.normalize.base import ParseContext
from security_council.validate import panel
from tests.test_model import valid_finding
from tests.test_orchestrator import FakeArm, _finding as orch_finding, _run as orch_run
from tests.test_validate import _cite, _finding as val_finding, _runner

HERE = pathlib.Path(__file__).parent
FIX = HERE / "fixtures" / "seedrepo"

_TABLE_ROW = re.compile(r"^\|.*\|$")


def _real_findings():
    ctx = ParseContext(repo_root=FIX, scan_root="/src", source_id="semgrep",
                       source_kind="scanner", family="semgrep", tool_version="1.2.3",
                       collected_at="2026-08-20T00:00:00Z")
    return registry.normalize_sarif(json.load(open(HERE / "fixtures" / "raw" / "semgrep.sarif")),
                                    "semgrep", ctx)


def _arm(name="semgrep", kind="scanner", family="semgrep", ok=True, error="", **cov):
    return ArmResult(name=name, kind=kind, family=family, ok=ok, exit_code=0 if ok else 1,
                     error=error, findings=[], tool_version="1.2.3", elapsed_seconds=1.5,
                     coverage={"raw_results": 3, "normalized": 3, **cov})


def _manifest(findings, arms=None, degradations=None, exit_code=1):
    return build_manifest(
        run_id="20260820_120000", target="/repo", arm_results=arms or [_arm()], merged=findings,
        config={"policy": {"fail_on_severity": "high", "min_arms_ok": 1}},
        started_at="2026-08-20T12:00:00Z", finished_at="2026-08-20T12:01:00Z",
        git={"git_commit": "abcdef1234567890", "dirty": False, "branch": "main"},
        degradations=degradations or [], exit_code=exit_code,
        reports=[{"path": "/repo/out/merged.sarif", "format": "sarif"}])


def _register_rows(md: str) -> list[str]:
    sec = md.split("## Findings register", 1)[1].split("\n## ", 1)[0]
    rows = [ln for ln in sec.splitlines() if _TABLE_ROW.match(ln)]
    return rows[2:]  # drop header + separator


# --------------------------------------------------------------------------- #
# Happy path on real normalized scanner output
# --------------------------------------------------------------------------- #


def test_renders_real_findings_with_header_summary_register_and_details():
    fs = _real_findings()
    md = markdown.to_markdown(fs, _manifest(fs))
    assert md.startswith("# security-council report — run `20260820_120000`")
    assert "commit `abcdef123456`" in md and "branch `main`" in md
    assert "FAIL — gating findings present" in md
    assert f"**{len(fs)} finding instances**" in md
    assert len(_register_rows(md)) == len(fs)
    assert "## Findings" in md and "## Method & attestation" in md and "## Artifacts" in md
    # every finding gets a numbered detail heading
    assert len(re.findall(r"^### \d+\. \*\*", md, re.M)) == len(fs)
    # the method table lists the arm with its version and counts
    assert "| semgrep | scanner | semgrep | 1.2.3 | ok | 3 → 3 | 1.5s |" in md


def test_empty_run_renders_cleanly():
    md = markdown.to_markdown([], _manifest([], exit_code=0))
    assert "No findings were produced by any arm." in md
    assert "PASS — no gating findings" in md
    assert "## Findings register" not in md and "## Appendix" not in md


def test_detail_limit_keeps_register_complete():
    fs = [valid_finding(fingerprints=m.Fingerprints(
            path_cwe_sink=f"pathCweSink/v1:{'%032x' % i}", context_hash=f"contextHash/v1:{'%032x' % i}",
            root_cause=f"rootCause/v1:{'%032x' % i}")) for i in range(3)]
    for f in fs:
        f.id = m.finding_id(f.fingerprints)
    md = markdown.to_markdown(fs, _manifest(fs), detail_limit=1)
    assert len(_register_rows(md)) == 3
    assert len(re.findall(r"^### \d+\. ", md, re.M)) == 1
    assert "2 further finding(s) are listed in the register" in md


# --------------------------------------------------------------------------- #
# Hostile text from the scanned repo must not become markup
# --------------------------------------------------------------------------- #


def test_untrusted_text_cannot_inject_markup_or_break_tables():
    f = valid_finding()
    f.title = 'Bad | thing ![x](http://evil.example/beacon.png)\n<script>alert(1)</script> [link](https://e.x)'
    f.description = "# fake heading\n> quote\n- bullet\n<img src=x onerror=1>\nvisit http://evil.example/exfil?d=1\n\n\n\ntail"
    f.validation = None
    md = markdown.to_markdown([f], _manifest([f]))
    body = md.split("## Findings register", 1)[1].split("## Artifacts", 1)[0]
    # no unescaped markup characters survive anywhere the hostile strings were rendered
    assert not re.search(r"(?<!\\)[<>\[\]]", body), body
    assert "<script>" not in body and "<img" not in body.replace("\\<", "")
    assert "](http" not in md and "](https" not in md
    assert "http://evil" not in md and "hxxp://evil.example/exfil" in md
    # block syntax at line start is disarmed, blank-line runs collapsed
    assert "\n# fake heading" not in md and "\\# fake heading" in md
    assert "\n> quote" not in md and "\n\\> quote" in md
    assert "\n\n\n" not in md.split("## Findings", 1)[1].split("## Artifacts")[0]
    # the register row stays a single, well-formed row
    rows = _register_rows(md)
    assert len(rows) == 1 and len(re.findall(r"(?<!\\)\|", rows[0])) == 9  # 8 cells, pipe escaped


def test_snippet_with_backtick_fence_cannot_escape_code_block():
    f = valid_finding()
    f.locations = [dataclasses.replace(f.locations[0], snippet="x = 1\n```\n# escaped?\nprint('hi')")]
    md = markdown.to_markdown([f], _manifest([f]))
    body = md.split("## Findings\n", 1)[1]
    assert "````python\n" in body
    # the fence opened with 4 backticks closes with 4; the inner ``` stays inside
    block = body.split("````python\n", 1)[1].split("\n````", 1)[0]
    assert "```\n# escaped?" in block


def test_control_chars_are_stripped():
    f = valid_finding()
    f.title = "clean\x1b[31mred\x00 title\x07"
    md = markdown.to_markdown([f], _manifest([f]))
    assert "\x1b" not in md and "\x00" not in md and "\x07" not in md
    assert "clean\\[31mred title" in md  # '[' escaped, control bytes gone


# --------------------------------------------------------------------------- #
# Validation, demotion, corroboration
# --------------------------------------------------------------------------- #


def test_validated_finding_shows_panel_and_refuted_goes_to_appendix_not_hidden():
    tp = val_finding()
    panel.validate_finding(tp, repo_root=".", runner=_runner([
        ("claude", "for", "yes", [_cite()]), ("codex", "against", "yes", [_cite()]),
        ("antigravity", "neutral", "yes", [_cite()])]))
    tp.validation.panel[0].rationale = "MODEL_TRANSCRIPT_MARKER"
    tp.description += ("\n\nCodex Security confidence: high — internal scoring note."
                       "\n\nValidation: validated — internal workflow note."
                       "\n\nAdditional validated detail: MODEL_APPENDIX_MARKER")
    tp.remediation = m.Remediation(
        summary="Use parameterized queries. Additional validated requirement: MODEL_REQUIREMENT_MARKER",
        guidance="Bind every value.\n\nAdditional validation: MODEL_GUIDANCE_MARKER",
        effort="S",
    )
    fp = val_finding(family="xss")
    fp.taxonomy = m.Taxonomy(cwe=["CWE-79"], cwe_family="xss")
    fp.fingerprints = m.Fingerprints(path_cwe_sink="pathCweSink/v1:" + "1" * 32,
                                     context_hash="contextHash/v1:" + "2" * 32,
                                     root_cause="rootCause/v1:" + "3" * 32)
    fp.id = m.finding_id(fp.fingerprints)
    fp.title = "reflected param in template"
    panel.validate_finding(fp, repo_root=".", runner=_runner([
        ("claude", "for", "no", [_cite()]), ("codex", "against", "no", [_cite()]),
        ("antigravity", "neutral", "no", [_cite()])]))
    assert fp.disposition.state == "refuted"
    md = markdown.to_markdown([tp, fp], _manifest([tp, fp]))
    # summary line
    assert ("2 reviewed (2 reached two-vendor quorum) → 1 true positive · "
            "1 false positive (demoted) · 0 need human review") in md
    assert "**Demoted, not hidden:** 1 finding(s)" in md
    # detail: panel table rows with verified citation counts; state + never-auto-close note
    assert "| risk confirmation | claude | m | true_positive | 1/1 | ok |" in md
    assert "MODEL_TRANSCRIPT_MARKER" not in md
    assert "internal scoring note" not in md and "internal workflow note" not in md
    assert "MODEL_APPENDIX_MARKER" not in md
    assert "MODEL_REQUIREMENT_MARKER" not in md
    assert "MODEL_GUIDANCE_MARKER" not in md
    assert "**Remediation:** Use parameterized queries. (effort S)" in md
    assert "Bind every value." in md
    assert "→ state `validated`" in md
    assert "→ state `refuted` · lifecycle remains **open** (auto-demote, never auto-close)" in md
    # appendix lists the refuted finding and explains nothing is deleted
    app = md.split("## Appendix — demoted and closed findings", 1)[1]
    assert "reflected param in template" in app and "refuted / open" in app
    assert "panel false_positive (1.00)" in app
    assert "nothing is deleted" in app
    # attestation: validator participants + models
    assert "**Independent reviewers:** `antigravity` (`m`); `claude` (`m`); `codex` (`m`)" in md


def test_human_accepted_risk_appears_in_appendix_with_operator_and_expiry():
    f = valid_finding()
    f.taxonomy = m.Taxonomy(cwe=["CWE-89"], cwe_family="injection")
    f.disposition.lifecycle = "accepted_risk"
    f.disposition.decided_by = m.DecidedBy(kind="human", decided_at="2026-08-20T00:00:00Z",
                                           operator="alice@agency.gov")
    f.disposition.decision_ref = "decisions/x.json"
    f.disposition.expires_at = "2026-11-20T00:00:00Z"
    f.disposition.vex_status = "not_affected"
    f.disposition.vex_justification = "vulnerable_code_not_in_execute_path"
    m.assert_invariants(f)
    md = markdown.to_markdown([f], _manifest([f]))
    app = md.split("## Appendix", 1)[1]
    assert "human (alice@agency.gov)" in app
    assert "vulnerable_code_not_in_execute_path · expires 2026-11-20T00:00:00Z" in app


def test_corroboration_flags_and_secret_redaction_note():
    f = valid_finding()
    f.taxonomy = m.Taxonomy(cwe=["CWE-798"], cwe_family="secrets")
    f.corroboration = m.Corroboration(agent_sources=["house"], count=1, vendor_families=["claude"],
                                      independent_family_count=1, corroboration_score=1.0,
                                      coverage_denominator=3.25, singleton_by_policy=False,
                                      declined_sources=["gitleaks", "semgrep"],
                                      independence_warning={"distinct_vendors": 1, "required": 2})
    f.locations = [dataclasses.replace(f.locations[0], snippet=None)]  # redacted
    md = markdown.to_markdown([f], _manifest([f]))
    assert "corroboration 1.00/3.25" in md
    assert "eligible but silent: gitleaks, semgrep" in md
    assert "independence warning: 1 < 2 vendors" in md
    assert "_snippet redacted (secret material)_" in md
    g = valid_finding()
    g.corroboration = m.Corroboration(agent_sources=["house"], count=1, independent_family_count=1,
                                      singleton_by_policy=True, eligible_sources=["house"])
    md2 = markdown.to_markdown([g], _manifest([g]))
    assert "1 only one eligible arm (singleton-by-policy)" in md2
    assert "singleton-by-policy" in _register_rows(md2)[0]


def test_supply_chain_package_line():
    f = valid_finding()
    f.taxonomy = m.Taxonomy(cwe=["CWE-1395"], cwe_family="supply_chain")
    f.package = m.PackageRef(purl="pkg:pypi/requests@2.19.0", version="2.19.0", fixed_version="2.31.0",
                             advisory_ids=["GHSA-j8r2-6x86-q33q", "CVE-2023-32681"])
    f.locations = [dataclasses.replace(f.locations[0], uri="requirements.txt", snippet="Flask==2.0.1")]
    md = markdown.to_markdown([f], _manifest([f]))
    assert ("- **package** `pkg:pypi/requests@2.19.0` · installed `2.19.0` · fixed in `2.31.0` · "
            "`GHSA-j8r2-6x86-q33q`, `CVE-2023-32681`") in md
    assert "Flask==2.0.1" not in md   # a manifest line is not evidence for a CVE; package block is


def test_related_locations_and_artifact_listing():
    f = valid_finding()
    extra = [dataclasses.replace(f.locations[0], uri="app/routes.py", start_line=3, end_line=3, role="source"),
             dataclasses.replace(f.locations[0], uri="app/other.py", start_line=9, end_line=9, role="primary")]
    f.locations = [f.locations[0], *extra]
    man = _manifest([f])
    man["reports"] = [{"path": "/repo/out/merged.sarif", "format": "sarif"},
                      {"path": "/repo/out/summary.md", "format": "markdown"}]
    md = markdown.to_markdown([f], man)
    assert "· also at: `app/routes.py:3` (source), `app/other.py:9`" in md
    assert "Run directory: `/repo/out`" in md and "- `summary.md` (markdown)" in md


# --------------------------------------------------------------------------- #
# Attestation / degradation (D8)
# --------------------------------------------------------------------------- #


def test_model_substitution_and_degradations_are_loud():
    fs = [valid_finding()]
    arms = [_arm(),
            _arm(name="claude", kind="agent_cli", family="claude", ok=False,
                 error="model_substituted: requested claude-fable-5 served claude-opus-4-8",
                 classifier_fallback=True),
            _arm(name="gitleaks", family="gitleaks", ok=False, error="docker: timeout")]
    degr = [{"kind": "arm_failed", "arm": "claude", "detail": "model_substituted: requested claude-fable-5 served claude-opus-4-8"},
            {"kind": "arm_failed", "arm": "gitleaks", "detail": "docker: timeout"}]
    md = markdown.to_markdown(fs, _manifest(fs, arms=arms, degradations=degr, exit_code=3))
    assert "DEGRADED — partial results (exit 3)" in md
    assert "> ⚠️ **Degraded run** — results are partial:" in md
    assert "> - arm_failed `gitleaks`: docker: timeout" in md
    assert "**MODEL SUBSTITUTION** — model\\_substituted: requested claude-fable-5 served claude-opus-4-8" in md
    assert "❌ **Model substitution detected** on `claude`" in md and "decision D8" in md
    assert "| gitleaks | scanner | gitleaks | 1.2.3 | **FAILED** — docker: timeout |" in md
    # models that produced findings come from provenance
    assert "**Models that produced findings:** `house` ← `claude-fable-5`" in md


def test_llm_arm_coverage_flags_surface():
    fs = [valid_finding()]
    arms = [_arm(name="claude", kind="agent_cli", family="claude", completion="partial",
                 coverage_unverified=True)]
    md = markdown.to_markdown(fs, _manifest(fs, arms=arms))
    assert "ok · ⚠ coverage unverified · completion partial" in md


# --------------------------------------------------------------------------- #
# Orchestrator + CLI integration
# --------------------------------------------------------------------------- #


def test_orchestrator_writes_summary_and_cli_regenerates_it(tmp_path, capsys):
    arms = [FakeArm("semgrep", "scanner", "semgrep",
                    [orch_finding(source_id="semgrep", kind="scanner", vendor="semgrep")]),
            FakeArm("house", "agent_cli", "claude",
                    [orch_finding(source_id="house", kind="agent_cli", vendor="claude")])]
    run = orch_run(arms, tmp_path)
    summary = (run.out_dir / "summary.md").read_text()
    assert summary.startswith(f"# security-council report — run `{run.run_id}`")
    assert run.manifest["exit_code"] == 1
    assert any(r["format"] == "markdown" and r["path"].endswith("summary.md") for r in run.manifest["reports"])
    assert "FAIL — gating findings present (exit 1)" in summary
    # CLI regeneration from the run dir reproduces the same report
    assert cli_main(["report", str(run.out_dir), "--format", "md"]) == 0
    assert capsys.readouterr().out.strip() == summary.strip()
    assert cli_main(["report", str(run.out_dir)]) == 0
    assert json.loads(capsys.readouterr().out)["exit_code"] == 1
