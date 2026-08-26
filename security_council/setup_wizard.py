"""`security-council setup` — the guided front door (R8).

The tool grew a lot of surface (9 arms, validation panel, baselines,
suppressions, 12 report formats, 3 CI systems, MCP, calibration). The wizard
collapses that into one decision a newcomer can actually make — "what are you
trying to do?" — and turns the answer into:

- a written `.security-council.yaml` (a PROFILE plus the same keys materialized
  with comments, so the file explains itself and can be edited by hand), and
- a printed, repo-specific cheat sheet of the 3–5 commands that matter next,
  tailored to what was detected (CI system, languages, arm readiness).

Design rules: at most two questions (goal; a cost confirmation only when the
goal implies vendor spend); every question has a safe default; `--yes` is
fully non-interactive for scripts; never overwrites an existing config without
`--force` — with one present, setup becomes a read-only guide instead.
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from pathlib import Path

from .config import PROFILES, find_config

_LANG = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".java": "Java",
         ".go": "Go", ".rb": "Ruby", ".cs": "C#", ".c": "C", ".cpp": "C++",
         ".rs": "Rust", ".php": "PHP", ".tf": "Terraform", ".kt": "Kotlin"}
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "target",
              ".security-council", ".llm-council", "__pycache__", ".corpora"}

GOALS = [
    ("quick", "Quick local scan — free, deterministic scanners only, results in minutes"),
    ("ci", "CI gate — fail builds on new findings; pairs with `baseline set` on brownfield"),
    ("deep", "Deep AI-assisted audit — adds the Claude/Codex security reviewers and the "
             "cross-vendor validation panel (costs real vendor money, budget-capped)"),
    ("gov", "Government / compliance package — scan plus eMASS, OSCAL, OpenVEX and "
            "STIG-checklist paperwork via `report --bundle gov`"),
]


def detect(target: Path) -> dict:
    langs: Counter = Counter()
    seen = 0
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            ext = Path(name).suffix.lower()
            if ext in _LANG:
                langs[_LANG[ext]] += 1
            seen += 1
            if seen >= 20000:
                break
        if seen >= 20000:
            break
    ci = []
    if (target / ".github" / "workflows").is_dir():
        ci.append("github")
    if (target / ".gitlab-ci.yml").is_file():
        ci.append("gitlab")
    if (target / "azure-pipelines.yml").is_file() or (target / "azure-pipelines.yaml").is_file():
        ci.append("azure-devops")
    return {
        "git": (target / ".git").exists(),
        "languages": [name for name, _ in langs.most_common(3)],
        "ci": ci,
        "config": find_config(target),
    }


def arm_readiness() -> list[tuple[str, bool, str]]:
    from .arms.registry import build_arm, known_arms
    out = []
    for name in known_arms():
        ok, detail = build_arm(name).available()
        out.append((name, ok, detail))
    return out


def _ask_choice(prompt: str, options: list[tuple[str, str]], default: str) -> str:
    print(f"\n{prompt}")
    for i, (key, desc) in enumerate(options, 1):
        marker = " (default)" if key == default else ""
        print(f"  {i}. {desc}{marker}")
    try:
        raw = input(f"choice [1-{len(options)}]: ").strip()
    except EOFError:
        return default
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1][0]
    return default


def _ask_yn(prompt: str, default: bool) -> bool:
    try:
        raw = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    except EOFError:
        return default
    return default if not raw else raw.startswith("y")


def config_text(profile: str) -> str:
    """Materialized config: the profile key plus its keys spelled out with
    comments, so the written file is self-explanatory and hand-editable."""
    head = [
        "# security-council configuration — written by `security-council setup`.",
        f"# Profile: {profile}. Edit freely; explicit keys here always win over",
        "# the profile's presets. Reference: docs/getting-started.md",
        f"profile: {profile}",
        "",
    ]
    body: list[str] = []
    if profile == "deep":
        body += [
            "arms:",
            "  # deterministic scanners are free; the two AI reviewers cost real",
            "  # vendor money per scan and are budget-capped below",
            "  enabled: [semgrep, gitleaks, osv-scanner, claude-security, codex-security]",
            "  options:",
            "    claude-security: {effort: low, max_budget_usd: 10}",
            "    codex-security: {max_cost_usd: 8}",
            "",
            "defaults:",
            "  validate: true   # cross-vendor validation panel on every scan",
            "",
        ]
    else:
        body += [
            "arms:",
            "  enabled: [semgrep, gitleaks, osv-scanner]   # free, deterministic",
            "",
        ]
    if profile in ("ci", "gov"):
        body += [
            "policy:",
            "  fail_on_severity: high   # exit 1 at/above this severity",
            "  gate_baseline: new       # only findings NEW since `baseline set` gate;",
            "                           # without a baseline everything gates (fail-safe)",
            "",
            "decisions:",
            "  require_signatures: enforce   # suppressions/baselines apply only with a",
            "                                # verified ssh-keygen signature (see docs/signing.md)",
            "",
        ]
    else:
        body += [
            "policy:",
            "  fail_on_severity: high   # exit 1 at/above this severity",
            "",
        ]
    body += [
        "score:",
        "  calibration: off   # opt-in fitted confidence record: off | auto | <path>",
        "",
    ]
    return "\n".join(head + body)


def cheat_sheet(profile: str, detected: dict) -> str:
    lines = ["", "Next steps (copy/paste):", "  security-council doctor" +
             "                        # confirm which arms are ready"]
    lines.append("  security-council scan .                       # run the scan")
    lines.append("  security-council report <run_dir> --format md # readable report "
                 "(or --format html)")
    if profile in ("ci", "gov"):
        lines.append("  security-council baseline set --target .      # brownfield: gate "
                     "only NEW findings")
    if profile == "gov":
        lines.append("  security-council report <run_dir> --bundle gov --app-name APP "
                     "--app-version 1.0")
        lines.append("      # writes openvex.json, oscal-ar.json, oscal-poam.json, "
                     "checklist.cklb, cyclonedx.json, emass.json")
    if profile == "deep":
        lines.append("  # deep scans spend vendor budget (caps above); a fixture-scale run "
                     "was ~$7-12 total")
    ci = detected.get("ci") or []
    tmpl = {"azure-devops": "templates/security-council.yml",
            "gitlab": "templates/security-council.gitlab-ci.yml",
            "github": "action.yml (uses: Intellimetrics/security-council@v0.1.0)"}
    for system in ci:
        lines.append(f"  # detected {system} — CI template: {tmpl[system]} (docs/ci/)")
    lines.append("  # full triage loop (suppress/outcome/baseline): docs/triage.md")
    return "\n".join(lines)


def run_setup(target: Path, *, profile: str | None = None, yes: bool = False,
              force: bool = False) -> int:
    detected = detect(target)
    langs = ", ".join(detected["languages"]) or "none detected"
    print(f"security-council setup — {target}")
    print(f"  languages: {langs} · git: {'yes' if detected['git'] else 'no'}"
          f" · CI: {', '.join(detected['ci']) or 'none detected'}")

    existing = detected["config"]
    if existing and not force:
        print(f"\nA config already exists: {existing} (use --force to overwrite).")
        print("Current quick reference for this repo:")
        print(cheat_sheet(profile or "quick", detected))
        return 0

    interactive = sys.stdin.isatty() and not yes and profile is None
    if profile is None:
        profile = _ask_choice("What are you trying to do?", GOALS, "quick") \
            if interactive else "quick"
    if profile not in PROFILES:
        print(f"error: unknown profile {profile!r}; known: {sorted(PROFILES)}",
              file=sys.stderr)
        return 2
    if profile == "deep" and interactive:
        if not _ask_yn("Deep scans call vendor AI CLIs and cost real money per scan "
                       "(budget-capped). Continue?", False):
            print("Switching to the free 'quick' profile — rerun setup anytime.")
            profile = "quick"

    cfg_path = target / ".security-council.yaml"
    cfg_path.write_text(config_text(profile))
    print(f"\nwrote {cfg_path}  (profile: {profile})")

    print("\nArm readiness:")
    for name, ok, detail in arm_readiness():
        print(f"  {name:<15} {'ready' if ok else 'unavailable':<12} {detail}")
    print(cheat_sheet(profile, detected))
    return 0
