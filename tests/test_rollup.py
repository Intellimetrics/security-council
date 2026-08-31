"""Pattern rollup + representative validation sampling (dogfood items 1-2)."""
from security_council import model as m
from security_council import rollup
from security_council.export import html_export, markdown
from security_council.validate.panel import select_for_validation
from tests.test_cluster import mk
from tests.test_export_markdown import _manifest


def _inst(rule="sc/http", sev="high", family="injection", n=0, path=None,
          source_rule_id="set"):
    f = mk(path=path or f"app/mod{n % 3}/f{n}.py", sev=sev, family=family, sink=f"s{n}")
    f.rule = m.RuleRef(id=rule, source="semgrep",
                       source_rule_id=(rule if source_rule_id == "set" else source_rule_id))
    return f


def test_groups_form_above_min_count_and_sort_by_weight():
    fs = ([_inst(rule="sc/http", n=i) for i in range(4)]
          + [_inst(rule="sc/sqli", sev="critical", n=10 + i) for i in range(3)]
          + [_inst(rule="sc/rare", n=99)])
    groups = rollup.pattern_groups(fs)
    assert [(g.rule, g.count) for g in groups] == [("sc/http", 4), ("sc/sqli", 3)]
    assert groups[1].highest_severity == "critical"
    assert groups[0].components == ["app"]
    slim = rollup.rollup_json(fs)
    assert slim[0]["rule"] == "sc/http" and len(slim[0]["representative_ids"]) == 3
    assert all("members" not in g for g in slim)


def test_sampling_spreads_the_budget_across_patterns_in_a_band():
    # 5 instances of one rule + 1 of another AT THE SAME SEVERITY: a cap of 2
    # must cross-examine BOTH patterns, not spend twice on the big one
    big = [_inst(rule="sc/http", sev="high", n=i) for i in range(5)]
    other = _inst(rule="sc/sqli", sev="high", n=9)
    ranked, selected = select_for_validation([*big, other], max_findings=2)
    assert {f.rule.id for f in selected} == {"sc/http", "sc/sqli"}
    # with no cap every instance is still selected
    _, everyone = select_for_validation([*big, other])
    assert len(everyone) == 6


def test_severity_is_honored_absolutely_across_bands():
    # R17 blocker repro: 3 criticals sharing a pattern + 3 lows in distinct
    # patterns, cap 3 — pattern diversity must NEVER cost a critical its panel
    crits = [_inst(rule="sem/injection", sev="critical", n=i) for i in range(3)]
    lows = [_inst(rule=f"r{i}", sev="low", n=10 + i) for i in range(3)]
    _, selected = select_for_validation([*crits, *lows], max_findings=3)
    assert [f.severity.label for f in selected] == ["critical", "critical", "critical"]


def test_synthesized_rule_ids_never_collapse_distinct_agent_findings():
    # claude-security ids are synthesized from the CWE: three distinct critical
    # findings must each keep their own panel slot, not share one representative
    agents = [_inst(rule="claude-security/CWE-89", sev="critical", n=i) for i in range(3)]
    real = [_inst(rule="sem/xss", sev="critical", n=10 + i) for i in range(3)]
    _, selected = select_for_validation([*agents, *real], max_findings=4)
    assert sum(1 for f in selected if f.rule.id.startswith("claude-security/")) == 3
    # and the rollup never presents the CWE bucket as a "repeated rule"
    assert rollup.pattern_groups(agents) == []
    fallback = [_inst(rule="sc/injection", sev="high", n=i, source_rule_id=None)
                for i in range(3)]
    assert rollup.pattern_groups(fallback) == []


def test_demoted_and_closed_instances_do_not_inflate_the_rollup():
    # R17 blocker repro: 4 suppressed (incl. the critical) + 1 open low must
    # not read as "5 instances, highest critical"
    fs = [_inst(rule="sem/http", sev="critical" if i == 0 else "low", n=i)
          for i in range(5)]
    for f in fs[:4]:
        f.disposition = m.Disposition(
            state=f.disposition.state, lifecycle="suppressed",
            decided_by=f.disposition.decided_by)
    assert rollup.pattern_groups(fs) == []          # one live low is not a pattern
    fs2 = [_inst(rule="sem/http", sev="low", n=10 + i) for i in range(3)]
    groups = rollup.pattern_groups([*fs, *fs2])
    assert [(g.count, g.highest_severity) for g in groups] == [(4, "low")]


def test_singletons_degrade_to_plain_severity_order():
    fs = [_inst(rule=f"r{i}", sev=s, n=i)
          for i, s in enumerate(["medium", "critical", "high"])]
    _, selected = select_for_validation(fs)
    assert [f.severity.label for f in selected] == ["critical", "high", "medium"]


def test_reports_render_the_rollup_without_collapsing_instances():
    fs = [_inst(rule="sc/http", n=i) for i in range(3)] + [_inst(rule="sc/one", n=7)]
    mf = _manifest(fs)
    assert mf["patterns"][0]["rule"] == "sc/http"          # manifest carries it
    md = markdown.to_markdown(fs, mf)
    assert "## Recurring patterns" in md
    assert "**Concentration:**" in md and "`sc/http` × 3" in md
    assert "not** one proven root cause" in md
    assert len([ln for ln in md.splitlines() if ln.startswith("| `sc/http` |")]) == 1
    page = html_export.to_html(fs, mf)
    assert "Concentration" in page and "recurring pattern" in page
    assert "<code>sc/http</code>" in page


def test_no_rollup_noise_without_repeats():
    fs = [_inst(rule=f"r{i}", n=i) for i in range(3)]
    mf = _manifest(fs)
    assert mf["patterns"] == []
    md = markdown.to_markdown(fs, mf)
    assert "Recurring patterns" not in md and "Concentration" not in md


def test_rollup_gating_column_matches_the_real_gate_in_baseline_new_mode():
    # the rollup must read the SAME gate predicate as the dashboard: a
    # baselined member under gate_baseline:new is not "gating" anywhere
    fs = [_inst(rule="sc/http", n=i) for i in range(3)]
    for f in fs[:2]:
        f.baseline_state = "unchanged"
    mf = _manifest(fs)
    mf["policy"]["gate_baseline"] = "new"
    md = markdown.to_markdown(fs, mf)
    [row] = [ln for ln in md.splitlines() if ln.startswith("| `sc/http` |")]
    assert "| 3 | **HIGH** | 1 | 0 |" in row
