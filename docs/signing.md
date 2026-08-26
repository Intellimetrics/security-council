# Signed decisions

**Who this is for:** anyone who suppresses findings, sets baselines, or records
ground truth — and anyone who has to trust that those decisions were made by
the people they claim. Assumes you've read [triage.md](triage.md).

## The plain-language version

A suppression is a file that says *"this finding is fine, stop failing the
build over it."* Whoever can write that file can switch the gate off for that
finding. Before this feature, the file just *said* who made the decision.
Now it can *prove* it: each decision is signed with the operator's **SSH key**
— the same key you already use to push to GitHub, GitLab or Azure DevOps —
and every scan checks the signature against a small list of trusted keys
committed next to the decisions.

- A decision that verifies is applied — and the report says who signed it.
- A decision that doesn't verify (no signature, wrong key, edited after
  signing, copied in from another repo) is **not applied**: the finding
  comes back and the gate stays on. Failing safe means "the finding
  reappears", never "the finding stays hidden".

No new software is needed: it uses `ssh-keygen -Y`, which ships with OpenSSH
8.2 and later (2020), on every Linux, macOS and Windows 10+ machine.

## Set it up (three commands, once per repo)

```bash
# 1. give the store an identity and an (empty) trusted-signers list
security-council decisions init --operator you@example.com

# 2. trust your key. The principal MUST be the exact --operator string you
#    will sign with — that is how "who decided" becomes attested, not asserted.
security-council decisions trust --principal you@example.com --key ~/.ssh/id_ed25519.pub

# 3. commit the store's identity and roster with the decisions
git add .security-council/store.json .security-council/allowed_signers \
        .security-council/decisions .security-council/baseline
```

Then sign each decision as you make it:

```bash
security-council suppress <finding-id> --operator you@example.com \
  --justification "..." --signing-key ~/.ssh/id_ed25519
security-council outcome mark <finding-id> --verdict fp --operator you@example.com \
  --signing-key ~/.ssh/id_ed25519
security-council baseline set --operator you@example.com --signing-key ~/.ssh/id_ed25519
```

Instead of repeating `--signing-key`, set `SECURITY_COUNCIL_SIGNING_KEY` in
your shell or `decisions.signing_key` in `.security-council.yaml`. A key with
a passphrase prompts on the terminal; with `ssh-agent` running you can pass
the **`.pub`** file and never type the passphrase (this is also the shape to
use from an AI assistant over MCP, which has no terminal).

Check the whole store at any time:

```bash
security-council decisions verify          # exit 1 if anything would be refused
security-council decisions verify --json   # machine-readable audit
```

## What gets applied, and when

`decisions.require_signatures` in `.security-council.yaml`:

| Level | Behaviour |
|---|---|
| `enforce` (default) | A human suppression, outcome mark or baseline applies **only** if its signature verifies. Anything else is refused: the finding stays open and gates, the mark does not feed scoring, the baseline is ignored (so everything gates). The CI templates pass it explicitly. |
| `warn` | Everything applies, but every unsigned or failed decision is named in the manifest, the summary and the degradations box. The opt-out for a team that is not ready to sign yet. |
| `off` | No verification. |
| `auto` | Opt-in adoption mode, per store: `enforce` for a store that has been `decisions init`-ed or has no decisions yet; `warn` for a store that has unsigned decisions and no `store.json` — **until 2027-01-01**, after which `auto` means `enforce` everywhere. Because the store is inside the scanned repo, this level can be lowered from a branch (see residuals), which is why it is not the default. |

Two things follow from the default:

- **An unsigned `suppress` is refused up front** with the three lines to fix
  it (or `require_signatures: warn` to opt down). A record that could never
  apply is worse than an error message.
- **A repo with decisions from before signing** sees them come back as
  "refused" on the next scan — the findings gate again, and the summary's
  refused table says why. Sign them (`decisions init`, `decisions trust`,
  re-make each decision with `--signing-key`), or set `warn` while you do.

Under `enforce` the scan applies the **signed values** — the expiry, the
lifecycle, the context hash — not whatever the record's editable block says.
So "extend the expiry by hand", "update the context hash so drift isn't
noticed" and "copy a signed record from another repo" all fail, and the tests
in `tests/test_signing.py` show each attack working with signing `off` and
failing with it on.

What is signed:

| Event | Signed fields |
|---|---|
| suppression / accepted risk | store id, root cause, context hash, finding, operator, time, expiry, lifecycle, justification, VEX justification |
| outcome mark | store id, root cause, finding, operator, time, verdict, note |
| baseline set | store id, run, time, operator, content digest (which covers every entry) |

Machine writes — automatic suppressions, reapply counters, expiry/drift stamps
— are **never signed**. That is deliberate (council decision R9 Q6): signing
whole records would put a signing key on CI runners, the one credential the
threat model says CI must not have. An automatic suppression replays only
while your config still has auto-suppression armed.

## What this does and does not buy you — read this part

A signature is **provenance, not assurance**. It proves *who* recorded a
decision and that nobody changed it since. It does not prove the decision
was right, and it does not stop an insider who can write **both** the
decisions and the `allowed_signers` roster — they can add their own key.

What makes it load-bearing is review:

- Commit `.security-council/store.json`, `allowed_signers`, `decisions/` and
  `baseline/` (keep `runs/` ignored).
- Put those paths behind **CODEOWNERS + required review**. Adding a signer
  is then a reviewed diff; so is every suppression.
- In CI, pass `--require-signatures enforce` (the shipped GitHub Action,
  GitLab and Azure DevOps templates do, alongside `--ignore-repo-config`),
  or use `--profile ci`, so a branch cannot lower the level from inside the
  repo it is trying to get past. The level always comes from the operator's
  side — flag, profile or `--config` file — never from the store.

Without protected paths, signing is theater — the docs say so because the
council review that designed this said so.

Residuals, stated plainly:

- **Replay inside the window.** A genuinely signed suppression that has not
  expired can be restored from git history after it was removed. Expiry
  (90 days; 30 for crypto/critical) bounds this; a signed sequence counter
  was considered and dropped as a hot, merge-conflicting file that is itself
  rollback-able.
- **`auto` is attacker-influenced.** Under the opt-in `auto` level, deleting
  `store.json` — or committing a first unsigned record without one — resolves
  the store to `warn` until the sunset date, always visibly (the reason is
  printed on every run). This is why the default is `enforce`.
- **Machine suppressions are unsigned.** In a repo whose config arms
  auto-suppression (both flags), a hand-written `kind: auto` record replays
  under `enforce`, bounded by G1/G7 (never crypto/critical), expiry, drift and
  the operator's double opt-in; the run reports it as
  `machine_decisions_replayed`. The shipped CI templates are unarmed.
- **The roster is the trust root.** `trust` refuses pattern principals
  (`*`, `?`, `!`, `,`) and always writes a `namespaces=` line; a hand-edited
  roster line that vouches for any name, any namespace, or a whole CA is
  flagged by `decisions verify`, not refused.
- **No verifier, no verification.** If `ssh-keygen -Y` is missing on the
  scanning machine, signed decisions are *unverifiable* and `enforce`
  refuses them (fail-closed). `security-council doctor` shows the verifier.

## Troubleshooting

**`suppress must be signed here`** — the level is `enforce` (the default) and
you gave no key. Follow the three printed lines, or set `warn`.

**`signature ... does not verify against allowed_signers`** at write time —
the key you signed with is not listed for that `--operator` principal. Run
`decisions trust` with the matching `.pub`, and check the principal is
*exactly* the operator string (one token, no spaces — an email works well).

**A decision shows `invalid` in `decisions verify`** — a signed field was
edited after signing, or the signer was removed from the roster. Re-make the
decision (it will be re-signed) or restore the record from git.

**`foreign`** — the record was signed for a different store id: it was copied
from another repository. Decisions are bound to one codebase on purpose;
re-make it here.

**`unverifiable`** — no usable `ssh-keygen -Y` on this machine (OpenSSH
< 8.2, or a minimal container image). Install OpenSSH client ≥ 8.2.

**Windows:** OpenSSH 8.x ships with Windows 10 1809+ / Server 2019+ as an
optional feature; Git for Windows also bundles it.

## Reference

- Namespace: `security-council-decision` (a key trusted here is not thereby
  trusted for git commit signing, and vice versa).
- Roster format: OpenSSH `allowed_signers` (`principal namespaces="..." keytype key`),
  the same format git's `gpg.ssh.allowedSignersFile` uses.
- Signed bytes: canonical JSON (sorted keys, no whitespace) of the per-event
  field list above plus `"v": 1`, stored as the armored `SSHSIG` block inside
  the event under `signature`.
- Manifest: `signature_policy` (configured, effective, reason, verifier,
  store id, trusted principals), a `signature` on every `prior_decisions`
  row and on `baseline_delta`, `history_audit` for outcome marks.
- Code: `security_council/signing.py`, `decisions.py`; design record
  [reviews/R9-decision-store-trust.md](reviews/R9-decision-store-trust.md).
