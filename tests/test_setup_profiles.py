"""R8 guided surface: profiles, the setup wizard, and report --bundle."""

import json

import pytest
import yaml

from security_council import config as cfg
from security_council import setup_wizard as sw
from security_council.arms.registry import known_arms


# --- profiles ---

def test_profiles_reference_only_known_arms_and_valid_keys():
    for name, prof in cfg.PROFILES.items():
        merged = cfg.deep_merge(cfg.DEFAULT_CONFIG, prof)
        for arm in merged["arms"]["enabled"]:
            assert arm in known_arms(), f"profile {name} references unknown arm {arm}"
        assert set(prof) <= set(cfg.DEFAULT_CONFIG), f"profile {name} invents config keys"


def test_config_file_profile_applies_under_file_keys(tmp_path):
    """A profile fills in what the file does not say; the file always wins."""
    (tmp_path / ".security-council.yaml").write_text(
        "profile: deep\narms:\n  options:\n    codex: {max_cost_usd: 3}\n")
    c = cfg.load_config(tmp_path)
    assert "codex" in c["arms"]["enabled"]                        # from the profile
    assert c["defaults"]["validate"] is True                      # from the profile
    assert c["arms"]["options"]["codex"]["max_cost_usd"] == 3     # from the file
    assert c["profile"] == "deep"


def test_config_file_overrides_a_value_the_profile_sets(tmp_path):
    (tmp_path / ".security-council.yaml").write_text(
        "profile: deep\ndefaults:\n  validate: false\n")
    c = cfg.load_config(tmp_path)
    assert c["defaults"]["validate"] is False      # file beats the profile's True


def test_deep_profile_only_ships_live_verified_arms(tmp_path):
    """R12: `deep` used to enable the dedicated vendor plugins, one of which
    needs its own login. A shipped profile must only contain arms that work."""
    enabled = cfg.resolve_profile({}, "deep")["arms"]["enabled"]
    assert "claude-security" not in enabled and "codex-security" not in enabled
    assert {"claude", "codex", "agy"} <= set(enabled)   # one per vendor family


def test_unknown_profile_in_config_fails_closed(tmp_path):
    (tmp_path / ".security-council.yaml").write_text("profile: turbo\n")
    with pytest.raises(ValueError, match="unknown profile 'turbo'"):
        cfg.load_config(tmp_path)


def test_ci_profile_gates_on_baseline():
    merged = cfg.deep_merge(cfg.DEFAULT_CONFIG, cfg.PROFILES["ci"])
    assert merged["policy"]["gate_baseline"] == "new"
    assert merged["arms"]["enabled"] == ["semgrep", "gitleaks", "osv-scanner"]


# --- setup wizard ---

@pytest.fixture
def quiet_arms(monkeypatch):
    monkeypatch.setattr(sw, "arm_readiness", lambda: [("semgrep", True, "docker")])


def test_setup_yes_writes_valid_selfexplaining_config(tmp_path, quiet_arms, capsys):
    assert sw.run_setup(tmp_path, yes=True) == 0
    p = tmp_path / ".security-council.yaml"
    text = p.read_text()
    assert text.count("#") >= 4                                   # self-explaining comments
    data = yaml.safe_load(text)
    assert data["profile"] == "quick"
    loaded = cfg.load_config(tmp_path)                            # round-trips through loader
    assert loaded["arms"]["enabled"] == ["semgrep", "gitleaks", "osv-scanner"]
    out = capsys.readouterr().out
    assert "Next steps" in out and "security-council scan ." in out


def test_setup_gov_profile_cheatsheet_mentions_bundle(tmp_path, quiet_arms, capsys):
    assert sw.run_setup(tmp_path, profile="gov", yes=True) == 0
    out = capsys.readouterr().out
    assert "--bundle gov" in out and "checklist.cklb" in out
    assert yaml.safe_load((tmp_path / ".security-council.yaml").read_text())["profile"] == "gov"
    assert cfg.load_config(tmp_path)["policy"]["gate_baseline"] == "new"


def test_setup_refuses_overwrite_without_force(tmp_path, quiet_arms, capsys):
    (tmp_path / ".security-council.yaml").write_text("profile: ci\n")
    assert sw.run_setup(tmp_path, yes=True) == 0
    assert (tmp_path / ".security-council.yaml").read_text() == "profile: ci\n"   # untouched
    assert "already exists" in capsys.readouterr().out
    assert sw.run_setup(tmp_path, profile="quick", yes=True, force=True) == 0
    assert yaml.safe_load((tmp_path / ".security-council.yaml").read_text())["profile"] == "quick"


def test_setup_interactive_deep_cost_declined_falls_back(tmp_path, quiet_arms,
                                                         monkeypatch, capsys):
    answers = iter(["3", "n"])                                    # choose deep, decline cost
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert sw.run_setup(tmp_path, yes=False) == 0
    assert yaml.safe_load((tmp_path / ".security-council.yaml").read_text())["profile"] == "quick"
    assert "free 'quick' profile" in capsys.readouterr().out


def test_detect_reports_languages_and_ci(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    (tmp_path / "Main.java").write_text("class Main {}\n")
    (tmp_path / ".gitlab-ci.yml").write_text("stages: [test]\n")
    d = sw.detect(tmp_path)
    assert d["languages"][0] == "Python" and "Java" in d["languages"]
    assert d["ci"] == ["gitlab"] and d["git"] is False


# --- report --bundle ---

def test_report_bundle_writes_audience_sets(tmp_path, capsys):
    from security_council.cli import build_parser, cmd_report
    from security_council.jsonio import dumps, to_dict
    from tests.test_cluster import mk
    run = tmp_path / "run"
    run.mkdir()
    f = mk(path="src/A.java", cwe="CWE-89", family="injection",
           source_id="semgrep", source_kind="scanner", vendor="semgrep")
    manifest = {"run_id": "r1", "counts": {"total": 1, "by_severity": {"high": 1},
                                           "by_state": {"new": 1}},
                "target": {"root": "/repo/x"}, "tool": {"security_council": "0.1.0"},
                "finished_at": "2026-08-24T00:01:00Z",
                "arms": [], "degradations": [], "exit_code": 1, "reports": []}
    (run / "manifest.json").write_text(json.dumps(manifest))
    (run / "findings.json").write_text(dumps([to_dict(f)]))
    args = build_parser().parse_args(["report", str(run), "--bundle", "all",
                                      "--app-name", "acme", "--app-version", "1.0"])
    assert cmd_report(args) == 0
    exports = run / "exports"
    expect = {"findings.csv", "summary.html", "summary.md", "openvex.json",
              "oscal-ar.json", "oscal-poam.json", "checklist.cklb", "cyclonedx.json",
              "emass.json"}
    assert {p.name for p in exports.iterdir()} == expect
    cklb_doc = json.loads((exports / "checklist.cklb").read_text())
    assert cklb_doc["stigs"][0]["stig_id"] == "Application_Security_Development_STIG"
    assert "GATE" in (exports / "summary.html").read_text()
    out = capsys.readouterr().out
    assert out.count("wrote ") == 9


def test_report_bundle_gov_without_app_identity_skips_emass_loudly(tmp_path, capsys):
    from security_council.cli import build_parser, cmd_report
    run = tmp_path / "run"
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps(
        {"run_id": "r1", "counts": {}, "target": {"root": "/repo/x"},
         "arms": [], "degradations": [], "reports": []}))
    (run / "findings.json").write_text("[]")
    args = build_parser().parse_args(["report", str(run), "--bundle", "gov"])
    assert cmd_report(args) == 0
    captured = capsys.readouterr()
    assert "emass.json skipped" in captured.err
    assert not (run / "exports" / "emass.json").exists()
    assert (run / "exports" / "checklist.cklb").exists()          # rest still written


def test_cheat_sheet_has_no_checkout_only_paths_and_follows_the_version():
    """A pip/wheel install has no docs/ or templates/ beside it; the cheat sheet
    must point at the published tree and the action tag must track the version
    (it was hard-coded to v0.1.0)."""
    from security_council import __version__
    detected = {"languages": ["Python"], "git": True, "config": None,
                "ci": ["github", "gitlab", "azure-devops"]}
    sheet = sw.cheat_sheet("quick", detected)
    assert f"security-council@v{__version__}" in sheet
    assert sw.REPO_URL + "/docs/triage.md" in sheet
    assert sw.REPO_URL + "/templates/security-council.gitlab-ci.yml" in sheet
    for line in sheet.splitlines():
        assert " docs/" not in line and " templates/" not in line, line   # bare relative paths


def test_doctor_reports_the_validator_backend(monkeypatch, capsys, quiet_arms):
    import shutil
    from security_council.cli import main as cli_main
    real = shutil.which
    monkeypatch.setattr(shutil, "which", lambda n, *a, **k: None if n == "llm-council" else real(n, *a, **k))
    assert cli_main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "llm-council" in out and "unavailable" in out and "validator_unavailable" in out
    monkeypatch.setattr(shutil, "which", lambda n, *a, **k: "/usr/bin/llm-council" if n == "llm-council" else real(n, *a, **k))
    cli_main(["doctor"])
    assert "llm-council   ready" in capsys.readouterr().out
