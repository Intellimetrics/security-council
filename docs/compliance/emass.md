# eMASS static-code-scans export

For ISSOs/ISSMs feeding scan results into a system's eMASS assets module.

```bash
security-council report <run_dir> --format emass \
  --app-name "MyApplication" --app-version "2.4" [--scan-date <unix>] > body.json
# POST body.json to /api/systems/{systemId}/static-code-scans (emasser works too)
```

## What the export is

The exact request body for eMASS's `POST
/api/systems/{systemId}/static-code-scans` endpoint, one row per CWE:

```json
[{
  "application": {"applicationName": "MyApplication", "version": "2.4"},
  "applicationFindings": [
    {"codeCheckName": "CWE-89 (injection)", "scanDate": 1787318610,
     "cweId": "89", "count": 1, "rawSeverity": "Critical"}
  ]
}]
```

- `codeCheckName` is deliberately **stable across scans** ("CWE-n (family)")
  so eMASS tracks the same weakness row over successive uploads.
- `count` = number of distinct root-cause clusters for that CWE.
- `cweId` is the numeric string the spec requires (no "CWE-" prefix).
- Severity maps critical→`Critical`, high→`High`, **medium→`Moderate`** (the
  RMF-native term), low→`Low`; info omits the optional field.
- `--emass-clear` emits the documented clear-findings body
  (`{"clearFindings": true}`).

## Verification status — stated precisely

The contract was verified against the **official eMASS REST OpenAPI
specification** (`mitre/emass_client`, `eMASSRestOpenApi.yaml`) and MITRE's
`emasser` reference client *before* the exporter was written; a conformance
schema derived from those components is vendored in
`tests/fixtures/schemas/` and every payload in the test suite validates
against it. The export has **not yet been exercised against a live eMASS
instance** — if your import is rejected, please open an issue with the error;
eMASS import validation is notoriously picky and that report is valuable.

## Disposition semantics (what does and doesn't go to eMASS)

Renders under D7 rules, same as every export:

- **Exported:** open and reopened findings that are not panel-refuted.
- **Withheld:** suppressed, accepted-risk, and demoted (refuted-but-open)
  findings — they remain visible in `summary.md`'s appendix and are never
  deleted, but they do not pollute the assets module.
- **Skipped loudly:** findings with no numeric primary CWE (`CWE-noinfo`)
  cannot be represented in this format; they are listed in the export's
  stderr accounting (`skipped`), never silently dropped. The meta counts
  (exported / withheld / skipped) always add up — a partial export cannot
  masquerade as complete.

## Data handling reminder

The export itself contains only finding metadata (CWE, counts, severity,
dates) — no source code. What you must review is upstream: if the findings
were produced by **hosted LLM arms**, source code was sent to vendor APIs
during the scan — see [../data-boundaries.md](../data-boundaries.md) for the
per-arm breakdown and the deterministic-only profile.

## Related / roadmap

Also relevant to RMF packages today: `merged.sarif` (tool-neutral evidence
artifact) and `summary.md` (method & model attestation — which models saw the
code, with hashes). Not built yet, planned: OSCAL Assessment Results / POA&M,
OpenVEX, and CKLB exports. The Trivy scanner is deliberately not a supported
arm (supply-chain compromise, GHSA-69fq-xp46-6x23); SBOM/SCA lanes will use
cdxgen/syft/grype.
