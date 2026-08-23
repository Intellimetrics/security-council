"""M-V2 gated model tiers: classification, zero-network probe ladder, preflight
enforcement (Red refused, undeclared refused), provenance posture stamping, and
the CLI surface."""
import json

from security_council import entitlements as ent
from security_council.cli import main as cli_main
from security_council.orchestrator import run_scan
from tests.test_diff_lane import FakeDiffArm
from tests.test_orchestrator import DEFAULT_CONFIG, _finding as orch_finding


# --------------------------------------------------------------------------- #
# classification + posture
# --------------------------------------------------------------------------- #


def test_classify_gated_and_ga_models():
    assert ent.classify_model("claude-mythos-5").name == "mythos"
    assert ent.classify_model("daybreak-blue-latest").name == "daybreak-blue"
    assert ent.classify_model("gpt-5.6-cyber").name == "daybreak-red"      # by snapshot
    assert ent.classify_model("daybreak-red-latest").is_red is True
    assert ent.classify_model("gpt-5.6-sol") is None                       # GA, not a gated tier
    assert ent.classify_model("claude-fable-5") is None
    assert ent.classify_model(None) is None


def test_safeguard_posture():
    assert ent.safeguard_posture_for("claude-mythos-5") == "relaxed"
    assert ent.safeguard_posture_for("gpt-5.6-sol") == "default"


# --------------------------------------------------------------------------- #
# probe ladder (rung 1 is real; rungs 2-4 injectable)
# --------------------------------------------------------------------------- #


def test_catalog_probe_red_absent_here():
    # gpt-5.6-cyber is not in this machine's codex cache -> definitively unavailable
    avail, source = ent.catalog_probe(ent.KNOWN_TIERS["daybreak-red"])
    assert avail is False and "absent" in source


def test_probe_is_unverifiable_without_a_prober():
    res = ent.probe_entitlement("mythos", {"entitlements": [{"tier": "mythos"}]})
    assert res.declared is True and res.available is None and res.rung == 1
    assert res.safeguard_posture == "relaxed"


def test_probe_uses_injected_prober_for_deep_rungs():
    def prober(tier):
        return ent.EntitlementResult(tier=tier.name, family=tier.family, model_id=tier.model_id,
                                     declared=True, available=True, rung=3,
                                     safeguard_posture=tier.safeguard_posture, is_red=tier.is_red,
                                     source="capability probe ok")
    res = ent.probe_entitlement("daybreak-blue", {"entitlements": [{"tier": "daybreak-blue"}]},
                                prober=prober)
    assert res.available is True and res.rung == 3


def test_probe_caches_availability(tmp_path):
    ent.probe_entitlement("mythos", {}, cache_dir=tmp_path)
    cached = json.loads((tmp_path / "entitlements.json").read_text())
    assert cached["mythos"]["model_id"] == "claude-mythos-5"


def test_unknown_tier_reported_not_crashed():
    res = ent.probe_entitlement("nope", {})
    assert res.available is False and "not a known tier" in (res.error or "")


# --------------------------------------------------------------------------- #
# preflight enforcement
# --------------------------------------------------------------------------- #


def test_preflight_refuses_red_always():
    r = ent.preflight(["daybreak-red-latest"], {"entitlements": [{"tier": "daybreak-red"}]})
    assert len(r) == 1 and r[0].kind == "red_refused"    # declared makes no difference


def test_preflight_refuses_undeclared_gated_tier():
    r = ent.preflight(["claude-mythos-5"], {"entitlements": []})
    assert len(r) == 1 and r[0].kind == "entitlement_undeclared"


def test_preflight_allows_declared_blue_tier():
    assert ent.preflight(["claude-mythos-5"],
                         {"entitlements": [{"tier": "mythos"}]}) == []


def test_preflight_ignores_ga_models():
    assert ent.preflight(["gpt-5.6-sol", "claude-fable-5", None], {}) == []


# --------------------------------------------------------------------------- #
# orchestrator preflight → exit codes 4/5
# --------------------------------------------------------------------------- #


def _arm_with_model(model, name="codex-security", family="codex"):
    arm = FakeDiffArm(name, "agent_cli", family,
                      [orch_finding(source_id=name, kind="agent_cli", vendor=family, rc="e")])
    arm.model = model
    return arm


def _cfg(**over):
    return {**DEFAULT_CONFIG, **over}


def test_orchestrator_refuses_red_exit_5(tmp_path):
    run = run_scan(tmp_path, [_arm_with_model("daybreak-red-latest")],
                   _cfg(entitlements=[{"tier": "daybreak-red"}]), out_dir=tmp_path / "out")
    assert run.exit_code == 5
    assert run.findings == [] and run.arm_results == []           # nothing scanned
    assert run.manifest["degradations"][0]["kind"] == "red_refused"


def test_orchestrator_refuses_undeclared_exit_4(tmp_path):
    run = run_scan(tmp_path, [_arm_with_model("claude-mythos-5", "claude-security", "claude")],
                   _cfg(entitlements=[]), out_dir=tmp_path / "out")
    assert run.exit_code == 4
    assert run.manifest["degradations"][0]["kind"] == "entitlement_undeclared"


def test_orchestrator_allows_declared_blue(tmp_path):
    run = run_scan(tmp_path, [_arm_with_model("claude-mythos-5", "claude-security", "claude")],
                   _cfg(entitlements=[{"tier": "mythos"}]), out_dir=tmp_path / "out")
    assert run.exit_code in (0, 1) and run.arm_results          # it actually ran


# --------------------------------------------------------------------------- #
# provenance posture stamping (via the normalization boundary)
# --------------------------------------------------------------------------- #


def test_relaxed_posture_stamped_and_surfaced_in_summary(tmp_path):
    from security_council.export import markdown
    from security_council.manifest import build_manifest
    from security_council.normalize import registry
    from security_council.normalize.base import ParseContext
    env = {
        "schema_version": "sc-agent-finding/1",
        "scan": {"angle": "crypto", "completion": "complete",
                 "files_examined": ["app/crypto_util.py"], "coverage_notes": "",
                 "declined_categories": []},
        "findings": [{"local_id": "F1", "title": "MD5 hash",
                      "description": "md5", "cwe": ["CWE-916"], "category": "crypto",
                      "severity": "high", "confidence": "high",
                      "locations": [{"path": "app/crypto_util.py", "start_line": 6, "end_line": 7,
                                     "role": "primary", "symbol": "h", "snippet": "md5"}],
                      "data_flow": [], "entry_point": "e", "exploit_precondition": "p",
                      "remediation": "argon2", "evidence": []}]}
    tier = ent.classify_model("claude-mythos-5")
    ctx = ParseContext(repo_root=tmp_path.parent / "seedrepo", source_id="claude-security",
                       source_kind="agent_cli", family="claude", model_id="claude-mythos-5",
                       prompt_sha256="a" * 64, collected_at="2026-08-23T00:00:00Z",
                       entitlement=tier.name, safeguard_posture=tier.safeguard_posture)
    # point at the real fixture file so the snippet resolves
    ctx.repo_root = __import__("pathlib").Path(__file__).parent / "fixtures" / "seedrepo"
    findings, _ = registry.normalize_envelope(env, ctx)
    assert findings and findings[0].provenance[0].safeguard_posture == "relaxed"
    assert findings[0].provenance[0].entitlement == "mythos"
    mani = build_manifest(run_id="r", target="t", arm_results=[], merged=findings, config={},
                          started_at="s", finished_at="f", git={}, degradations=[], reports=[])
    md = markdown.to_markdown(findings, mani)
    assert "Relaxed-safeguard tier in use" in md


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_entitlements_lists_and_probes(tmp_path, capsys):
    (tmp_path / ".security-council.yaml").write_text("entitlements:\n  - tier: mythos\n")
    assert cli_main(["entitlements", "--target", str(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["declared"] == ["mythos"]
    red = [t for t in out["tiers"] if t["tier"] == "daybreak-red"][0]
    assert red["red"] is True and red["availability"] == "unavailable"    # rung-1 absent here
    mythos = [t for t in out["tiers"] if t["tier"] == "mythos"][0]
    assert mythos["declared"] is True and mythos["safeguard_posture"] == "relaxed"


def test_cli_scan_tier_unknown_errors(tmp_path, capsys):
    (tmp_path / "f.py").write_text("x=1\n")
    rc = cli_main(["scan", str(tmp_path), "--arms", "claude-security", "--tier", "nope"])
    assert rc == 2 and "unknown tier" in capsys.readouterr().err
