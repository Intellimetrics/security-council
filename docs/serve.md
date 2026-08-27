# The report viewer (`security-council serve`)

**Who this is for:** anyone who wants to *look at* reports in a browser —
yours, or a teammate's on the same network — without digging through
`.security-council/runs/`.

## The plain-language version

`security-council serve` starts a small web page on your machine that lists
every scan run, opens each run's report, lets you download any file from a
run (or the whole run as a zip), and shows this documentation. It is a
**viewer**: it never changes anything, and it stops when you press Ctrl-C.

```bash
security-council serve                 # http://127.0.0.1:8642/  — this machine only
security-council serve --open          # same, and open it in your browser
```

By default only your own machine can reach it. To let people on your LAN
open it, bind a network address — the viewer then **requires a token**, which
it generates and prints once:

```bash
security-council serve --bind 0.0.0.0
#   security-council viewer: http://192.168.1.20:8642/?token=k3…Qw
#   LAN-exposed on 0.0.0.0 — anyone with the token can read every report
```

Share that URL (token included). The first visit sets a cookie, after which
the links inside the pages work without the token. Pick your own with
`--token`, a different port with `--port`, and `--target` for a repo other
than the current directory.

What you can open:

| URL | What it is |
|---|---|
| `/` | every run, newest first: gate result, counts, arms, a zip link |
| `/runs/<id>/` | that run's `summary.html` (rendered on the spot if missing) |
| `/runs/<id>/summary.md`, `…/merged.sarif`, `…/findings.json`, `…/raw/<arm>/…` | any file from the run; directories list their contents |
| `/runs/<id>.zip` | the whole run directory as a download |
| `/runs/latest/…` | the newest run |
| `/docs/` | this documentation (when a `docs/` directory is found, or `--docs DIR`) |

From an AI assistant over MCP, `sc_serve` with `action: start|stop|status`
does the same; the viewer lives as long as that assistant session.

## What it deliberately does not do — read this part

A run directory contains **source excerpts, exploit reasoning and
secret-adjacent strings**. Serving it turns "files on my disk" into
"anything that can reach the socket", so:

- **Loopback by default.** Anything else needs the token. There is no
  "open, no token" mode.
- **`DEPLOY_MODE=secret`** refuses non-loopback binds entirely.
- **Read-only, GET only.** No uploads, no forms, no accounts, no persistence.
- **Confined.** Every path is resolved inside the runs directory (or the docs
  directory); `..`, absolute paths and symlinks pointing outside are refused.
  The decision store, `store.json` and `allowed_signers` are never served.
- **Dual-use analysis artifacts** (attack paths, write-ups) are withheld —
  the same rule the exporters apply — unless you start with
  `--include-dual-use`.
- **Hardened responses.** No script anywhere (`Content-Security-Policy:
  default-src 'none'`), `nosniff`, no referrer, no caching; only our own
  `summary.html` is served as HTML — a vendor's `.html` in `raw/` comes back
  as plain text.
- **The token is the whole lock.** Anyone who has it can read every report of
  that target; it travels in a URL, so treat the link like the reports
  themselves. Restart the viewer to rotate it.
- **Not a portal.** It has no TLS and no users. For a team-wide, always-on
  report site, publish `summary.html` and `exports/` as CI artifacts (the
  shipped templates already do), or run `serve` behind your own
  reverse proxy that adds TLS and authentication.

Data-boundary summary: [data-boundaries.md](data-boundaries.md).
