"""Azure DevOps Server integration (D4: ADO Server is the first-class CI target).

GHAzDO does not exist on Server, so the pipeline story is built from parts that
do (see ``templates/security-council.yml`` for the ready-made step template):

- ``merged.sarif`` is published as the **CodeAnalysisLogs** build artifact —
  the "SARIF SAST Scans Tab" marketplace extension renders it on the build.
- Gating findings become ``##vso[task.logissue type=error]`` annotations
  (warnings below the policy threshold), with sourcepath/linenumber so they
  land on the file view.
- ``##vso[task.uploadsummary]`` attaches the run's ``summary.md``.
- On PR builds, one comment **thread** is posted via the REST API
  (``api-version=6.0`` — Server 2020+ compatible), auth via
  ``System.AccessToken``. Thread status: ``active`` when the gate failed,
  ``closed`` when clean, so a passing scan doesn't nag reviewers.

Invocation: ``python -m security_council.ci.azure_devops <run_dir>
[--post-pr-thread] [--dry-run] [--max-issues N]``. This step never fails the
build — the scan's own exit code is the gate (the template re-raises it last,
after artifacts are published).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from .. import model as _m
from pathlib import Path

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
API_VERSION = "6.0"
PR_ENV = ("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", "SYSTEM_TEAMPROJECT",
          "BUILD_REPOSITORY_ID", "SYSTEM_PULLREQUEST_PULLREQUESTID",
          "SYSTEM_ACCESSTOKEN")


def _esc_msg(s: str) -> str:
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(s: str) -> str:
    return _esc_msg(s).replace("]", "%5D").replace(";", "%3B")


_CRYPTO_CWES = frozenset(_m.CRYPTO_CWES)


def _sev(row: dict) -> str:
    return ((row.get("severity") or {}).get("label")) or "info"


def _high_assurance(row: dict) -> bool:
    """Row-level mirror of `policy.high_assurance` (crypto family or critical).

    R12 round 9: this split claims "the same filter as the exit gate" but had no
    equivalent of G9's `baseline_ineligible`, so a BASELINED crypto or critical
    finding was annotated as a mere warning while the gate — correctly — still
    failed the build. `ci` and `gov` both set `gate_baseline: "new"`, so the
    divergence was reachable by default: the annotations a reviewer reads would
    disagree with the exit code they are gated on.
    """
    if _sev(row) == "critical":
        return True
    tax = row.get("taxonomy") or {}
    if tax.get("cwe_family") == "crypto":
        return True
    return any(str(c) in _CRYPTO_CWES for c in (tax.get("cwe") or []))


def _open_unresolved(row: dict) -> bool:
    d = row.get("disposition") or {}
    return (d.get("lifecycle") in ("open", "reopened")
            and d.get("state") != "refuted"
            and not d.get("sarif_suppression"))


def split_findings(rows: list[dict], manifest: dict) -> tuple[list[dict], list[dict]]:
    """(errors, warnings): the same filter as the exit gate; below-threshold
    open findings become warnings."""
    policy = manifest.get("policy") or {}
    threshold = _SEV_RANK.get(policy.get("fail_on_severity", "high"), 4)
    gate_baseline = policy.get("gate_baseline", "all")
    errors, warnings = [], []
    for r in rows:
        if not _open_unresolved(r):
            continue
        baselined = (gate_baseline == "new"
                     and r.get("baseline_state") in ("unchanged", "updated")
                     and not _high_assurance(r))          # G9
        if _SEV_RANK.get(_sev(r), 1) >= threshold and not baselined:
            errors.append(r)
        else:
            warnings.append(r)
    return errors, warnings


def _issue_line(row: dict, kind: str) -> str:
    loc = (row.get("locations") or [{}])[0]
    props = [f"type={kind}"]
    if loc.get("uri"):
        props.append(f"sourcepath={_esc_prop(loc['uri'])}")
    if loc.get("start_line"):
        props.append(f"linenumber={int(loc['start_line'])}")
    cwe = ((row.get("taxonomy") or {}).get("cwe") or ["CWE-?"])[0]
    msg = f"[{_sev(row)}] {cwe} {row.get('title', '')} (security-council {row.get('id', '')})"
    return f"##vso[task.logissue {';'.join(props)}]{_esc_msg(msg)}"


def logissue_lines(rows: list[dict], manifest: dict, *, max_issues: int = 50) -> list[str]:
    errors, warnings = split_findings(rows, manifest)
    out = [_issue_line(r, "error") for r in errors[:max_issues]]
    out += [_issue_line(r, "warning") for r in warnings[:max(0, max_issues - len(out))]]
    dropped = len(errors) + len(warnings) - len(out)
    if dropped > 0:
        out.append(f"##vso[task.logissue type=warning]{_esc_msg(f'security-council: {dropped} further finding(s) not annotated (max-issues); see the CodeAnalysisLogs artifact')}")
    return out


def uploadsummary_line(summary_path: Path) -> str:
    return f"##vso[task.uploadsummary]{summary_path}"


def pr_thread_payload(rows: list[dict], manifest: dict, *, limit: int = 10) -> dict:
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
                         f"see the CodeAnalysisLogs artifact | |")
    return {"comments": [{"parentCommentId": 0, "commentType": "text",
                          "content": "\n".join(lines)}],
            "status": "active" if errors else "closed"}


def post_pr_thread(payload: dict, env: dict | None = None, *,
                   dry_run: bool = False, opener=None) -> dict:
    env = dict(env if env is not None else os.environ)
    missing = [k for k in PR_ENV if not env.get(k)]
    if missing:
        return {"posted": False, "reason": f"not a PR build (missing {', '.join(missing)})"}
    base = env["SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"].rstrip("/")
    # The {project} path segment accepts the project GUID or its name. On Server,
    # project names routinely contain spaces (and other characters illegal in a
    # URL path), which made http.client raise InvalidURL before the request was
    # even sent — no thread posted AND the step crashed, violating the "never
    # fails the build" contract below. Prefer the GUID (System.TeamProjectId,
    # never needs escaping); fall back to a percent-encoded name.
    project = env.get("SYSTEM_TEAMPROJECTID") or env["SYSTEM_TEAMPROJECT"]
    url = (f"{base}/{urllib.parse.quote(project, safe='')}/_apis/git/repositories/"
           f"{urllib.parse.quote(env['BUILD_REPOSITORY_ID'], safe='')}/pullRequests/"
           f"{env['SYSTEM_PULLREQUEST_PULLREQUESTID']}/threads?api-version={API_VERSION}")
    if dry_run:
        return {"posted": False, "reason": "dry run", "url": url, "payload": payload}
    # A failed PR-thread post must NEVER fail the build (see the module
    # docstring): the scan's own exit code is the gate and this annotation is
    # best-effort. Any error — malformed URL, auth/permission rejection, a
    # network blip — degrades to a structured result that main() surfaces as a
    # ##vso warning rather than propagating out and failing the step.
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {env['SYSTEM_ACCESSTOKEN']}"})
        open_fn = opener or urllib.request.urlopen
        with open_fn(req, timeout=30) as resp:                   # noqa: S310 - CI-internal URL
            return {"posted": True, "url": url, "status": getattr(resp, "status", None)}
    except Exception as e:                                       # noqa: BLE001 - never fail the build
        return {"posted": False, "reason": f"post failed: {type(e).__name__}: {e}", "url": url}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="security-council-azdo")
    p.add_argument("run_dir")
    p.add_argument("--max-issues", type=int, default=50)
    p.add_argument("--post-pr-thread", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    run_dir = Path(args.run_dir)
    mf = run_dir / "manifest.json"
    if not mf.is_file():
        print(f"##vso[task.logissue type=warning]security-council: no manifest.json in {run_dir}")
        return 0                     # annotation step never fails the build
    manifest = json.loads(mf.read_text())
    fj = run_dir / "findings.json"
    rows = json.loads(fj.read_text()) if fj.is_file() else []
    for line in logissue_lines(rows, manifest, max_issues=args.max_issues):
        print(line)
    summary = run_dir / "summary.md"
    if summary.is_file():
        print(uploadsummary_line(summary.resolve()))
    if args.post_pr_thread:
        try:
            result = post_pr_thread(pr_thread_payload(rows, manifest), dry_run=args.dry_run)
        except Exception as e:                                   # noqa: BLE001 - never fail the build
            result = {"posted": False, "reason": f"post failed: {type(e).__name__}: {e}"}
        if not result.get("posted") and str(result.get("reason", "")).startswith("post failed"):
            print("##vso[task.logissue type=warning]"
                  + _esc_msg("security-council: PR thread not posted — " + str(result["reason"])))
        print(f"security-council: PR thread {result}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
