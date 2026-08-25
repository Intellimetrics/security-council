"""R12 follow-through (2026-08-25): the batch that closed everything still open
after sixteen council rounds. Each test names the defect it pins."""

from __future__ import annotations

import json

import pytest

from security_council import config as cfg
from security_council import fence, model as m
from security_council.arms import scanner as sc
from security_council.arms.scanner import SCANNER_SPECS, ScannerArm
from security_council.decisions import DecisionStore
from security_council.normalize import coverage as cov
from security_council.workspace import prepare_workspace
from tests.test_scanner_arm import _R, _run
from tests.test_store_hardening import _finding as _store_finding
from tests.test_validate import _finding


# ------------------------------------------------------------------ osv ----


def test_osv_scans_recursively():
    """Verified live: without --recursive osv-scanner reads only top-level
    manifests, printed "No package sources found" for a repo whose
    requirements.txt sat one directory down, and that read as a VERIFIED
    clean. Any monorepo with nested manifests got a silent osv pass."""
    spec = SCANNER_SPECS["osv-scanner"]
    assert "--recursive" in spec.local_args and "--recursive" in spec.docker_args
    # round 19: it also honours .gitignore by default, so naming the manifest
    # there hid it and the scan came out verified-clean. Not the repo's call.
    assert "--no-ignore" in spec.local_args and "--no-ignore" in spec.docker_args
    sg = SCANNER_SPECS["semgrep"]
    assert "--no-git-ignore" in sg.local_args and "--no-git-ignore" in sg.docker_args


def test_gitleaks_and_osv_configs_are_pinned_not_auto_loaded():
    """R12 round 20 (claude + codex): gitleaks auto-loads <source>/.gitleaks.toml
    and osv-scanner reads osv-scanner.toml when no --config is given, so the
    scanned repository could allowlist everything — reproduced as a verified
    clean exit 0. Both now pass a config WE ship; verified live that a repo
    allowlisting every path and one ignoring a real CVE change nothing."""
    from pathlib import Path
    pkg = Path(sc.__file__).resolve().parent.parent
    for name in ("gitleaks", "osv-scanner"):
        spec = SCANNER_SPECS[name]
        assert spec.config_file and (pkg / spec.config_file).is_file(), name
        assert any(a.startswith("--config") for a in spec.local_args), name
        assert any(a.startswith("--config") for a in spec.docker_args), name
    assert "useDefault = true" in (pkg / "data" / "gitleaks.toml").read_text()
    assert "IgnoredVulns" not in (pkg / "data" / "osv-scanner.toml").read_text().replace(
        "# a repository could ignore vulnerabilities by id", "")


def test_a_missing_pinned_config_fails_the_arm_rather_than_falling_back(monkeypatch, tmp_path):
    """Never fall back to "no --config": that is exactly the auto-load path the
    pinned file exists to close."""
    spec = SCANNER_SPECS["gitleaks"]
    monkeypatch.setitem(SCANNER_SPECS, "gitleaks",
                        type(spec)(**{**spec.__dict__, "config_file": "data/does-not-exist.toml"}))
    monkeypatch.setattr(sc.shutil, "which", lambda b: f"/usr/bin/{b}")
    res = ScannerArm("gitleaks").run(tmp_path, tmp_path, run_id="r", collected_at="t")
    assert res.ok is False and "pinned config missing" in res.error


def test_not_applicable_needs_the_tools_exit_code_too(monkeypatch, tmp_path):
    """The marker line alone was not enough: a different failure that also
    prints the phrase must not be excused. osv exits 128 for the real case."""
    r = _R(ok=False, exit_code=1, stderr="No package sources found, --help for usage")
    res = _run(monkeypatch, tmp_path, "osv-scanner", r)
    assert res.ok is False and not res.coverage.get("not_applicable")
    r = _R(ok=False, exit_code=128, stderr="No package sources found, --help for usage")
    res = _run(monkeypatch, tmp_path, "osv-scanner", r)
    assert res.ok is True and res.coverage["not_applicable"] is True


# ---------------------------------------------------------------- fence ----


def test_certificate_must_match_the_fence_it_certified():
    """R11: fix.py checked only `cert is None`; live() and config_hash were never
    consulted. Now a posture change or expiry is refused."""
    import pathlib
    work, home = pathlib.Path("/tmp/w"), pathlib.Path("/tmp/h")
    h = fence.config_hash_for(work_dir=work, home=home, allow_network=False)
    cert = fence.FenceCertificate(config_hash=h, bwrap_version="v", host="t", minted_at=1000.0)
    assert fence.verify_certificate(cert, work_dir=work, home=home, now=1001.0) is None
    assert "different fence" in fence.verify_certificate(
        cert, work_dir=work, home=home, allow_network=True, now=1001.0)
    assert "expired" in fence.verify_certificate(
        cert, work_dir=work, home=home, now=1000.0 + fence.FENCE_TTL_SECONDS + 1)
    assert fence.verify_certificate(None, work_dir=work, home=home) == "no certificate"


def test_config_hash_is_not_tmpdir_dependent_and_keeps_bind_scope():
    """R11: the ephemeral filter was `startswith("/tmp/")` and stripped every
    path arg, so different bind scopes hashed identically."""
    import pathlib
    a = fence.config_hash_for(work_dir=pathlib.Path("/var/x/work"), home=pathlib.Path("/var/x/home"))
    b = fence.config_hash_for(work_dir=pathlib.Path("/tmp/y/work"), home=pathlib.Path("/tmp/y/home"))
    assert a == b                                   # ephemeral paths do not matter
    argv = fence.bwrap_argv(work_dir=pathlib.Path("/tmp/w"), home=pathlib.Path("/tmp/h"))
    argv2 = [x if x != "/etc" else "/opt" for x in argv]   # a different bind target
    assert fence._config_hash(argv, ephemeral=("/tmp/w", "/tmp/h")) != \
        fence._config_hash(argv2, ephemeral=("/tmp/w", "/tmp/h"))


@pytest.mark.skipif(not fence.bwrap_available()[0], reason="bwrap not installed")
def test_canary_has_positive_controls(tmp_path):
    """R11: the probes failed benignly on a host lacking ~/.ssh/id_rsa or a
    resolver, so the canary could pass without proving anything. Each escape
    probe is now paired with a control that must succeed."""
    work = tmp_path / "work"
    work.mkdir()
    (work / "a").write_text("x")
    orig = tmp_path / "orig"
    orig.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    cert, report = fence.certify(work_dir=work, original=orig, home=home)
    assert cert is not None, report
    assert report["controls_missing"] == [] and report["breaches"] == []
    assert not (work / ".sc-work-write").exists()      # the control cleans up


# ------------------------------------------------------------ workspace ----


def test_scratch_copy_records_what_it_excluded(tmp_path):
    """R12 round 12: DEFAULT_EXCLUDES were applied silently, so a scan that
    never saw a vendored tree presented itself as "the whole repository"."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("x=1")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "m.js").write_text("")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    ws = prepare_workspace(tmp_path)
    try:
        assert set(ws.excluded) == {"node_modules", ".git"}
        assert not (ws.root / "node_modules").exists()
    finally:
        ws.cleanup()


# ---------------------------------------------------------------- store ----


def test_a_record_the_model_rejects_degrades_instead_of_crashing(tmp_path):
    """R12 round 15 follow-up: assert_invariants ran OUTSIDE the malformed-record
    guard, so a record carrying a state I13 / I6 now reject crashed the scan."""
    f = _store_finding()
    store = DecisionStore(tmp_path)
    rc = f.fingerprints.root_cause
    path = store._path(rc)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": 1, "root_cause": rc, "history": [],
        "context_hash": f.fingerprints.context_hash,
        "suppression": {"status": "active", "lifecycle": "wontfix",     # I13 rejects
                        "decision_ref": "ref", "expires_at": "2099-01-01T00:00:00Z",
                        "decided_by": {"kind": "human", "operator": "x",
                                       "decided_at": "2026-08-20T00:00:00Z"}}}))
    actions = store.apply_prior_decisions([f], now_iso="2026-08-25T00:00:00Z")
    assert any(a["action"] == "ignored_malformed" and "I13" in a["detail"] for a in actions)
    assert f.disposition.lifecycle == "open"          # reverted, fail-safe
    m.assert_invariants(f)


# --------------------------------------------------------------- config ----


def test_wrong_policy_values_fail_closed(tmp_path):
    """R12 round 9: `.security-council.yaml` had no validation. A right key with
    a wrong value must not be silently coerced to something else."""
    (tmp_path / ".security-council.yaml").write_text("policy:\n  fail_on_severity: hgh\n")
    with pytest.raises(ValueError, match="fail_on_severity"):
        cfg.load_config(tmp_path)
    (tmp_path / ".security-council.yaml").write_text("policy:\n  gate_baseline: New\n")
    with pytest.raises(ValueError, match="gate_baseline"):
        cfg.load_config(tmp_path)
    (tmp_path / ".security-council.yaml").write_text("policy:\n  auto_suppress: yes please\n")
    with pytest.raises(ValueError, match="auto_suppress"):
        cfg.load_config(tmp_path)


def test_a_typoed_key_is_named_not_ignored(tmp_path):
    (tmp_path / ".security-council.yaml").write_text("policy:\n  fail_on_severty: high\n")
    with pytest.raises(ValueError, match="unknown policy key"):
        cfg.load_config(tmp_path)


def test_a_valid_config_still_loads(tmp_path):
    (tmp_path / ".security-council.yaml").write_text(
        "profile: ci\npolicy:\n  fail_on_severity: medium\n  min_arms_ok: 2\n")
    c = cfg.load_config(tmp_path)
    assert c["policy"]["fail_on_severity"] == "medium" and c["policy"]["gate_baseline"] == "new"


# --------------------------------------------------------------- panel ----


def test_unverified_citations_do_not_count_as_navigation():
    """R12 round 8: max_files_cited counted unique paths, so dummy citations
    defeated the cross-file check."""
    from security_council.validate import panel
    from tests.test_vendor_validate import _cr
    f = _finding()
    f.locations.append(type(f.locations[0])(
        uri="app/routes.py", start_line=3, end_line=3, role="related",
        snippet_sha256=f.locations[0].snippet_sha256, snippet="x"))
    fake = [{"path": "app/reports.py", "start_line": 9, "end_line": 9, "text": "a", "verified": True},
            {"path": "app/routes.py", "start_line": 3, "end_line": 3, "text": "b", "verified": False}]
    val = panel.synthesize_validation(f, _cr([("claude", "for", "yes", fake),
                                              ("codex", "against", "no", fake),
                                              ("antigravity", "neutral", "yes", fake)]),
                                      prompt_sha256="p")
    assert val.no_cross_file_navigation is True     # only ONE verified file was cited


def test_unanchored_citations_do_not_move_the_score():
    """R11: `_term_evidence` weighted every verified citation regardless of
    anchoring, so a verified README.md:1 moved p for a SQL sink in reports.py."""
    from security_council import score
    from tests.test_score import _op, _validated
    f = _validated(_finding(), panel=[_op("defender", "false_positive", cites=3)])
    anchored = score.score_finding(f).terms.get("evidence", 0.0)
    far = m.EvidenceCitation(path="README.md", start_line=1, end_line=1, claim="c", verified=True)
    op = _op("defender", "false_positive", cites=0)
    op.citations = [far, far, far]
    op.citation_pass_rate = 1.0
    f2 = _validated(_finding(), panel=[op])
    assert anchored < 0                          # anchored defender evidence counts
    assert score.score_finding(f2).terms.get("evidence", 0.0) == 0.0   # unanchored does not


# ---------------------------------------------------------------- misc ----


def test_verdict_partial_when_ignore_file_present_is_reported_by_name(monkeypatch, tmp_path):
    (tmp_path / ".gitleaksignore").write_text("x\n")
    empty = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks"}},
                                           "results": []}]}
    res = _run(monkeypatch, tmp_path, "gitleaks", _R(ok=True, exit_code=0), write_sarif=empty)
    assert cov.coverage_verdict(res) == cov.PARTIAL
    assert res.coverage["ignore_files"] == [".gitleaksignore"]


# ------------------------------------------------------ repo config trust ----


def test_repo_config_is_honoured_locally_but_recorded_as_repository_sourced(tmp_path):
    """R12 round 21 (claude): the scanned repository's own .security-council.yaml
    chooses the arms and the gate, so a branch can configure its own scan.
    Locally that is the normal workflow — but the source must be recorded."""
    (tmp_path / ".security-council.yaml").write_text("arms:\n  enabled: [osv-scanner]\n")
    c = cfg.load_config(tmp_path)
    assert c["arms"]["enabled"] == ["osv-scanner"]
    assert c["_source"]["kind"] == "repository"


def test_ignore_repo_config_uses_defaults(tmp_path):
    (tmp_path / ".security-council.yaml").write_text("arms:\n  enabled: [osv-scanner]\n")
    c = cfg.load_config(tmp_path, ignore_repo=True)
    assert c["arms"]["enabled"] == cfg.DEFAULT_CONFIG["arms"]["enabled"]
    assert c["_source"]["kind"] == "defaults" and "ignored" in c["_source"]["note"]


def test_explicit_config_does_not_walk_the_target(tmp_path):
    (tmp_path / ".security-council.yaml").write_text("arms:\n  enabled: [osv-scanner]\n")
    op = tmp_path.parent / f"{tmp_path.name}-operator.yaml"
    op.write_text("policy:\n  fail_on_severity: medium\n")
    c = cfg.load_config(tmp_path, explicit=op)
    assert c["arms"]["enabled"] == cfg.DEFAULT_CONFIG["arms"]["enabled"]   # repo file unused
    assert c["policy"]["fail_on_severity"] == "medium"
    assert c["_source"]["kind"] == "explicit"
    with pytest.raises(ValueError, match="not a file"):
        cfg.load_config(tmp_path, explicit=tmp_path / "missing.yaml")


def test_every_ci_template_ignores_the_repo_config():
    """The branch under test must never configure its own gate."""
    from pathlib import Path
    for path in ("action.yml", "templates/security-council.yml",
                 "templates/security-council.gitlab-ci.yml"):
        lines = Path(path).read_text().splitlines()
        start = next(i for i, ln in enumerate(lines) if "-P -m security_council.cli scan" in ln)
        block = [lines[start]]
        while block[-1].rstrip().endswith("\\"):        # the command's continuation lines
            block.append(lines[start + len(block)])
        assert any("--ignore-repo-config" in ln for ln in block), (path, block)


def test_ci_scan_commands_shell_parse_cleanly():
    """R12 round 22 (claude): the round-21 edit appended ` \\` to a scan line
    that already ended in ` \\`, leaving `... "$path" \\ \\` — bash reads
    `\\ ` as an escaped-space ARGUMENT, argparse exits 2, and every CI scan
    failed. Fail-closed, but the shipped templates were broken. Assemble each
    scan command the way bash would and check the tokens."""
    import shlex
    from pathlib import Path
    for path in ("action.yml", "templates/security-council.yml",
                 "templates/security-council.gitlab-ci.yml"):
        lines = Path(path).read_text().splitlines()
        start = next(i for i, ln in enumerate(lines) if "-P -m security_council.cli scan" in ln)
        block = [lines[start]]
        while block[-1].rstrip().endswith("\\"):
            block.append(lines[start + len(block)])
        joined = " ".join(ln.rstrip().rstrip("\\") for ln in block)
        tokens = shlex.split(joined)
        assert all(t.strip() for t in tokens), (path, tokens)       # no whitespace-only args
        assert "\\" not in tokens, (path, tokens)                      # no stray backslash arg
        assert tokens[:4] == tokens[0:1] + ["-P", "-m", "security_council.cli"], (path, tokens)
        assert "--ignore-repo-config" in tokens, path


def test_ci_templates_take_the_run_dir_from_the_scan_record_not_a_glob():
    """R12 round 23 (claude): `ls -d runs/*/ | sort | tail -1` picked the
    lexically-last run dir under the SCANNED repo, so a committed
    runs/99999999_999999/ would be uploaded and annotated in place of the real
    run (the exit code was unaffected; the reports were spoofable)."""
    from pathlib import Path
    for path in ("action.yml", "templates/security-council.yml",
                 "templates/security-council.gitlab-ci.yml"):
        text = Path(path).read_text()
        assert 'runs"/*/' not in text, path
        assert "--json" in text and '["out_dir"]' in text, path


def test_scan_json_record_always_carries_out_dir(tmp_path, monkeypatch, capsys):
    """The CI templates now depend on `scan --json` emitting `out_dir`; pin the
    contract on a real (fake-arm) run, including a degraded one."""
    import json as _json
    from security_council import cli
    from tests.test_orchestrator import FakeArm
    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.setattr(cli, "_build_arms",
                        lambda names, config, diff=None: [FakeArm("semgrep", "scanner", "semgrep", [])])
    for extra in ([], ["--min-arms", "5"]):        # clean, and degraded (insufficient arms)
        rc = cli.main(["scan", str(tmp_path), "--json", "--out", str(tmp_path / "out"), *extra])
        out = capsys.readouterr().out
        rec = _json.loads(out[out.index("{"):])          # the record is pretty-printed
        assert rec["out_dir"] and rec["run_id"] and rec["exit_code"] == rc
