"""R19 A1: `decisions.baseline_max_age_days` bounds the baseline replay window.

A signed baseline was the one signed artifact with no expiry (the R13
residual: replay an unexpired signed record from git history). The knob makes
a too-old baseline stop being honoured — everything gates as new (fail-closed:
exit can flip 0->1, NEVER 0->3) — with a stale-soon warning window so a
default-on knob does not turn pipelines red overnight.

Vacuity discipline (R12): every behavioural test carries an `off` (or fresh)
control showing the same input honoured without the bound.
"""
import json
from datetime import UTC, datetime, timedelta

import pytest

from security_council import decisions as dec
from security_council.config import DEFAULT_CONFIG, PROFILES, deep_merge, validate_config
from security_council.export.markdown import to_markdown
from security_council.orchestrator import run_scan
from tests.test_orchestrator import FakeArm, _finding


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
NOW_ISO = _iso(NOW)


def _age(set_at, max_age=365, now=NOW_ISO):
    return dec.baseline_age_status({"set_at": set_at}, now_iso=now, max_age_days=max_age)


# --------------------------------------------------------------------- #
# baseline_age_status boundaries (timestamps compared as datetimes, R13)
# --------------------------------------------------------------------- #

def test_exactly_max_age_is_still_honoured():
    st = _age(_iso(NOW - timedelta(days=365)))
    assert st["status"] == "stale_soon"          # within the warning window
    assert st["age_days"] == 365


def test_one_second_past_max_age_is_stale():
    st = _age(_iso(NOW - timedelta(days=365, seconds=1)))
    assert st["status"] == "stale"
    assert st["age_days"] == 365                 # whole days; the DATETIME decided


def test_stale_soon_window_opens_at_max_minus_30_days():
    assert _age(_iso(NOW - timedelta(days=335)))["status"] == "fresh"
    assert _age(_iso(NOW - timedelta(days=335, seconds=1)))["status"] == "stale_soon"


def test_future_within_tolerance_is_fresh_age_zero():
    st = _age(_iso(NOW + timedelta(hours=2)))
    assert st["status"] == "fresh"
    assert st["age_days"] == 0


def test_future_beyond_tolerance_is_refused_not_age_zero():
    # codex R19: max(0, ...) silently rendered a future timestamp as age 0,
    # which would then be fresh FOREVER
    st = _age(_iso(NOW + timedelta(days=2)))
    assert st["status"] == "future"


def test_malformed_set_at_fails_closed_when_bounded():
    assert _age("not-a-date")["status"] == "unparseable"
    assert _age(None)["status"] == "unparseable"
    # naive timestamp (no tz) cannot be compared to an aware now: same class
    assert _age("2026-01-01T00:00:00")["status"] == "unparseable"


def test_off_disables_the_bound_but_still_reports_age():
    for off in (None, False, "off"):
        st = _age(_iso(NOW - timedelta(days=4000)), max_age=off)
        assert st["status"] == "unbounded"
        assert st["age_days"] == 4000
    # off + malformed keeps the pre-A1 behaviour (age unknown, honoured)
    assert _age("garbage", max_age="off")["status"] == "unbounded"


def test_invalid_knob_values_never_silently_disable_the_bound():
    for bad in (0, -5, "365", True, 1.5):
        assert _age(_iso(NOW), max_age=bad)["status"] == "unparseable"


# --------------------------------------------------------------------- #
# config surface
# --------------------------------------------------------------------- #

def test_default_on_and_profiles_tighter():
    assert DEFAULT_CONFIG["decisions"]["baseline_max_age_days"] == 365
    for prof in ("ci", "gov"):
        merged = deep_merge(DEFAULT_CONFIG, PROFILES[prof])
        assert merged["decisions"]["baseline_max_age_days"] == 180


def test_config_validation_rejects_ambiguous_shapes():
    ok = validate_config({"decisions": {"baseline_max_age_days": 365}})
    assert ok == []
    assert validate_config({"decisions": {"baseline_max_age_days": "off"}}) == []
    for bad in (0, -1, "1y", True):
        problems = validate_config({"decisions": {"baseline_max_age_days": bad}})
        assert any("baseline_max_age_days" in p for p in problems), bad


def test_yaml_bare_off_normalises(tmp_path):
    from security_council.config import load_config
    p = tmp_path / ".security-council.yaml"
    p.write_text("decisions:\n  baseline_max_age_days: off\n")
    cfg = load_config(tmp_path)
    assert cfg["decisions"]["baseline_max_age_days"] == "off"


# --------------------------------------------------------------------- #
# end-to-end: the gate, the exit code, the manifest, the summary
# --------------------------------------------------------------------- #

def _repo(tmp_path):
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "x.py").write_text("q = 1\n")
    return target


def _bl_row(f):
    return {"id": f.id, "title": f.title,
            "fingerprints": {"root_cause": f.fingerprints.root_cause,
                             "context_hash": f.fingerprints.context_hash,
                             "path_cwe_sink": f.fingerprints.path_cwe_sink},
            "severity": {"label": f.severity.label},
            "locations": [{"uri": f.locations[0].uri}]}


def _cfg(max_age=365, gate_baseline="new"):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg["policy"]["gate_baseline"] = gate_baseline
    # unsigned-store lane: these tests are about AGE, not signatures
    cfg["decisions"]["require_signatures"] = "warn"
    cfg["decisions"]["baseline_max_age_days"] = max_age
    return cfg


def _scan(target, findings, **cfg_kw):
    return run_scan(target, [FakeArm("semgrep", "scanner", "semgrep", findings)],
                    _cfg(**cfg_kw), isolate=False)


@pytest.fixture()
def baselined(tmp_path):
    """A repo with one finding and a store ready to baseline it at any age."""
    target = _repo(tmp_path)
    finding = _finding(source_id="semgrep", kind="scanner", vendor="semgrep")
    store = dec.DecisionStore(target / ".security-council")

    def set_at(days_ago):
        store.set_baseline([_bl_row(finding)], run_id="r",
                           now_iso=_iso(datetime.now(UTC) - timedelta(days=days_ago)),
                           operator="alice@example")
    return target, finding, set_at, store


def test_stale_baseline_stops_gating_off_exit_flips_0_to_1(baselined):
    target, finding, set_at, _ = baselined
    set_at(10)
    control = _scan(target, [finding])
    assert control.exit_code == 0                     # control: fresh baseline honours
    set_at(400)
    run = _scan(target, [finding])
    assert run.exit_code == 1                         # 0 -> 1, and NEVER 3
    assert any(d["kind"] == "baseline_stale" for d in run.degradations)
    assert not any(d["kind"] in ("arm_failed", "partial_coverage",
                                 "coverage_unverified") for d in run.degradations)
    # off control: the same 400-day baseline is honoured when the knob is off
    off = _scan(target, [finding], max_age="off")
    assert off.exit_code == 0
    assert not any(d["kind"] == "baseline_stale" for d in off.degradations)


def test_stale_on_clean_repo_stays_exit_0(baselined):
    target, _, set_at, _ = baselined
    set_at(400)
    run = _scan(target, [])                           # nothing found: nothing gates
    assert run.exit_code == 0
    assert any(d["kind"] == "baseline_stale" for d in run.degradations)


def test_ignored_baseline_keeps_provenance_in_manifest(baselined):
    target, finding, set_at, store = baselined
    set_at(400)
    run = _scan(target, [finding])
    assert run.manifest["baseline_delta"] is None
    bi = run.manifest["baseline_ignored"]
    assert bi["reason"] == "stale"
    assert bi["operator"] == "alice@example"
    assert bi["age_days"] == 400 and bi["max_age_days"] == 365
    assert bi["content_sha256"]
    md = to_markdown(run.findings, run.manifest)
    assert "Baseline NOT honoured" in md and "stale" in md


def test_stale_soon_warns_but_honours(baselined):
    target, finding, set_at, _ = baselined
    set_at(345)
    run = _scan(target, [finding])
    assert run.exit_code == 0                         # still honoured
    assert any(d["kind"] == "baseline_stale_soon" for d in run.degradations)
    bd = run.manifest["baseline_delta"]
    assert bd["age_status"] == "stale_soon" and bd["max_age_days"] == 365
    assert "nearing max age" in to_markdown(run.findings, run.manifest)


def test_off_is_stamped_loudly(baselined):
    target, finding, set_at, _ = baselined
    set_at(400)
    run = _scan(target, [finding], max_age="off")
    bd = run.manifest["baseline_delta"]
    assert bd["age_status"] == "unbounded" and bd["max_age_days"] is None
    assert bd["age_days"] == 400                      # age still reported
    assert "max-age check disabled" in to_markdown(run.findings, run.manifest)


def test_future_timestamp_is_refused(baselined):
    target, finding, set_at, _ = baselined
    set_at(-3)                                        # three days in the future
    run = _scan(target, [finding])
    assert run.exit_code == 1
    assert any(d["kind"] == "baseline_refused" and "future" in d["detail"]
               for d in run.degradations)
    assert run.manifest["baseline_ignored"]["reason"] == "future"
    # off control: the future timestamp is not refused without the bound
    assert _scan(target, [finding], max_age="off").exit_code == 0


def test_malformed_set_at_is_refused_when_bounded(baselined):
    target, finding, set_at, store = baselined
    set_at(10)
    doc = json.loads(store.baseline_path.read_text())
    doc["set_at"] = "not-a-date"
    store.baseline_path.write_text(json.dumps(doc))
    # hand-editing set_at also breaks the digest? No: set_at is not IN the
    # content digest (it digests finding identity) — this isolates the age lane.
    run = _scan(target, [finding])
    assert run.exit_code == 1
    assert any(d["kind"] == "baseline_refused" and "parseable" in d["detail"]
               for d in run.degradations)
    # off control: pre-A1 behaviour (honoured, age unknown)
    off = _scan(target, [finding], max_age="off")
    assert off.exit_code == 0
    assert off.manifest["baseline_delta"]["age_days"] is None


def test_gate_all_still_reports_staleness(baselined):
    target, finding, set_at, _ = baselined
    set_at(400)
    run = _scan(target, [finding], gate_baseline="all")
    assert run.exit_code == 1                         # gates under "all" regardless
    assert any(d["kind"] == "baseline_stale" for d in run.degradations)
    assert run.manifest["baseline_delta"] is None     # not honoured for SARIF states


def test_honoured_provenance_renders_age_and_max(baselined):
    target, finding, set_at, _ = baselined
    set_at(10)
    run = _scan(target, [finding])
    md = to_markdown(run.findings, run.manifest)
    assert "days ago, max 365" in md
