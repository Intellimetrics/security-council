"""GitLab CI integration.

GitLab has no ##vso-style logging commands — annotations come from the two
report artifacts (`export/gitlab.py`): ``gl-sast-report.json``
(``artifacts:reports:sast``, Ultimate security widget) and
``gl-code-quality-report.json`` (``artifacts:reports:codequality``, inline MR
diff annotations on every tier). This module writes both from a run directory
and optionally posts ONE merge-request note summarizing the gate.

MR notes: ``POST {CI_API_V4_URL}/projects/{CI_PROJECT_ID}/merge_requests/
{CI_MERGE_REQUEST_IID}/notes``. ``CI_JOB_TOKEN`` cannot post notes — provide a
project access token (``api`` scope) as ``SECURITY_COUNCIL_GITLAB_TOKEN`` (or
``GITLAB_TOKEN``); without one the note is skipped with a reason, never an
error. Like the ADO annotate step, this never fails the build — the scan's
exit code is the gate (see ``templates/security-council.gitlab-ci.yml``).

The error/warning split is imported from ``ci.azure_devops`` so every CI
surface uses the exact exit-gate semantics (including ``gate_baseline``).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

from .azure_devops import _sev, split_findings

MR_ENV = ("CI_API_V4_URL", "CI_PROJECT_ID", "CI_MERGE_REQUEST_IID")
TOKEN_ENV = ("SECURITY_COUNCIL_GITLAB_TOKEN", "GITLAB_TOKEN")
SAST_NAME = "gl-sast-report.json"
CODE_QUALITY_NAME = "gl-code-quality-report.json"


def mr_note_markdown(rows: list[dict], manifest: dict, *, limit: int = 10) -> str:
    errors, warnings = split_findings(rows, manifest)
    gate = manifest.get("exit_code")
    head = ("❌ **security-council: gate FAILED**" if gate == 1 else
            "⚠️ **security-council: degraded run**" if gate == 3 else
            "✅ **security-council: clean**")
    lines = [head, "",
             f"{len(errors)} gating · {len(warnings)} non-gating finding(s) — "
             f"run `{manifest.get('run_id')}`", ""]
    listed = [*errors, *warnings][:limit]
    if listed:
        lines += ["| Severity | CWE | Finding | Location |", "|---|---|---|---|"]
        for r in listed:
            loc = (r.get("locations") or [{}])[0]
            where = f"{loc.get('uri', '?')}:{loc.get('start_line', '?')}"
            cwe = ((r.get("taxonomy") or {}).get("cwe") or ["?"])[0]
            title = str(r.get("title", "")).replace("|", "\\|")[:80]
            lines.append(f"| {_sev(r)} | {cwe} | {title} | `{where}` |")
        if len(errors) + len(warnings) > limit:
            lines.append(f"| … | | {len(errors) + len(warnings) - limit} more — "
                         f"see the job artifacts | |")
    return "\n".join(lines)


def post_mr_note(body_md: str, env: dict | None = None, *,
                 dry_run: bool = False, opener=None) -> dict:
    env = dict(env if env is not None else os.environ)
    missing = [k for k in MR_ENV if not env.get(k)]
    if missing:
        return {"posted": False, "reason": f"not an MR pipeline (missing {', '.join(missing)})"}
    token = next((env[k] for k in TOKEN_ENV if env.get(k)), None)
    if not token:
        return {"posted": False,
                "reason": f"no token (set {TOKEN_ENV[0]}; CI_JOB_TOKEN cannot post notes)"}
    url = (f"{env['CI_API_V4_URL'].rstrip('/')}/projects/{env['CI_PROJECT_ID']}"
           f"/merge_requests/{env['CI_MERGE_REQUEST_IID']}/notes")
    if dry_run:
        return {"posted": False, "reason": "dry run", "url": url}
    req = urllib.request.Request(
        url, data=json.dumps({"body": body_md}).encode(), method="POST",
        headers={"Content-Type": "application/json", "PRIVATE-TOKEN": token})
    open_fn = opener or urllib.request.urlopen
    with open_fn(req, timeout=30) as resp:                       # noqa: S310 - CI-internal URL
        return {"posted": True, "url": url, "status": getattr(resp, "status", None)}


def write_reports(run_dir: Path, out_dir: Path) -> dict:
    from ..export import gitlab as gl
    from ..jsonio import finding_from_dict
    manifest = json.loads((run_dir / "manifest.json").read_text())
    fj = run_dir / "findings.json"
    findings = [finding_from_dict(d) for d in json.loads(fj.read_text())] if fj.is_file() else []
    sast, sast_meta = gl.to_gitlab_sast(findings, manifest)
    quality, q_meta = gl.to_gitlab_code_quality(findings)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / SAST_NAME).write_text(json.dumps(sast, indent=2))
    (out_dir / CODE_QUALITY_NAME).write_text(json.dumps(quality, indent=2))
    return {"sast": {**sast_meta, "path": str(out_dir / SAST_NAME)},
            "code_quality": {**q_meta, "path": str(out_dir / CODE_QUALITY_NAME)}}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="security-council-gitlab")
    p.add_argument("run_dir")
    p.add_argument("--write-reports", metavar="DIR",
                   help="write gl-sast-report.json + gl-code-quality-report.json into DIR")
    p.add_argument("--post-mr-note", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    run_dir = Path(args.run_dir)
    if not (run_dir / "manifest.json").is_file():
        print(f"security-council: no manifest.json in {run_dir}", file=sys.stderr)
        return 0                     # annotation step never fails the build
    if args.write_reports:
        meta = write_reports(run_dir, Path(args.write_reports))
        print(f"security-council: wrote {meta['sast']['path']} "
              f"({meta['sast']['vulnerabilities']} vulns) and "
              f"{meta['code_quality']['path']} ({meta['code_quality']['rows']} rows)",
              file=sys.stderr)
    if args.post_mr_note:
        manifest = json.loads((run_dir / "manifest.json").read_text())
        fj = run_dir / "findings.json"
        rows = json.loads(fj.read_text()) if fj.is_file() else []
        result = post_mr_note(mr_note_markdown(rows, manifest), dry_run=args.dry_run)
        print(f"security-council: MR note {result}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
