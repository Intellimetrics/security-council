"""Decision-store signing: ``ssh-keygen -Y`` as a subprocess (R9 Q1, option B).

Why this shape (council-settled, R9 2026-08-24; do not re-litigate):

- **Asymmetric, no new dependency.** The runtime is stdlib-only and the stdlib
  has no Ed25519, so we shell out to OpenSSH (>= 8.2) exactly as D2 shells out
  to ``llm-council`` instead of importing it. Every developer already has an
  SSH key the forge knows; CI needs only the *public* roster to verify.
  HMAC was rejected (a verifier can forge), ``cryptography`` was rejected (a
  heavyweight dep plus invented key management), git ``verify-commit`` is a
  possible later add-on (dies on dirty trees, shallow clones, squash merges).
- **Events are signed, not records** (Q6). A record mixes human writes (the
  suppression, outcome marks) with machine writes (reapplied counters, expiry
  and drift stamps, auto-suppressions). Signing whole records would put a
  signing key on CI runners — the exact credential the threat model excludes.
- **The signing principal IS ``decided_by.operator``** (Q1 hard requirement):
  the roster line that verifies a signature names the operator the decision
  claims, so "who decided" is attested, not asserted.
- **Fail closed when the verifier is missing** (Q1): under ``enforce`` a
  signature that cannot be checked is not honored — the finding reappears.
- **Signing is provenance, never assurance** (Q6). Nothing here stops an
  insider with write access to *both* the store and ``allowed_signers``; what
  it buys is a reviewable chokepoint (adding a signer is a diff), detection
  of tampering outside a reviewed commit, and per-person attribution. It is
  load-bearing only when the store paths are behind CODEOWNERS + required
  review — the docs say so in those words.

Wire format: the signature is the armored ``SSHSIG`` block ``ssh-keygen``
emits, stored inside the event it covers. The signed payload is canonical
JSON (sorted keys, no whitespace, ASCII) of a fixed per-kind field list —
never the whole event — so machine fields added later cannot invalidate a
human signature, and a human field cannot be edited without invalidating it.
The signature namespace domain-separates these from any other use of the
same SSH key (git commit signing uses ``git``; ours is below).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

NAMESPACE = "security-council-decision"
PAYLOAD_VERSION = 1

# require_signatures levels. The DEFAULT is `enforce` (R13): R9 Q2 asked for
# "new stores enforce, pre-existing warn + sunset", but in code "pre-existing"
# is a fact about files the adversary writes — a branch that commits its first
# unsigned record and no store.json would make itself "pre-existing" and be
# honoured under warn. `auto` keeps that per-store adoption mode as an
# explicit opt-in: enforce for an initialised or empty store; warn for a
# store with unsigned decisions and no store.json until the sunset below,
# after which `auto` means `enforce` everywhere. The sunset is a fixed date
# so the flip is predictable and a store cannot stay grandfathered forever.
LEVELS = ("off", "warn", "enforce", "auto")
WARN_SUNSET = "2027-01-01T00:00:00Z"

# statuses a verification can return; ACCEPTED is what `enforce` honors
VERIFIED = "verified"
UNSIGNED = "unsigned"
INVALID = "invalid"
FOREIGN = "foreign"            # good signature, but for a different store id
UNVERIFIABLE = "unverifiable"  # ssh-keygen -Y not available on this machine
UNCHECKED = "unchecked"        # policy `off`: nothing was looked at
MACHINE = "machine"            # a machine (auto-suppression) write; never signed
ACCEPTED = frozenset({VERIFIED})

# One roster token — and NOT an allowed_signers pattern: `*` `?` (wildcards),
# `!` (negation) and `,` (pattern lists) would make `trust --principal '*'`
# vouch for every operator name while the report still said "verified" (R13).
_PRINCIPAL_RE = re.compile(r"^[^\s\"*?!,]{1,256}$")
_KEYTYPE_RE = re.compile(r"^(ssh-|ecdsa-|sk-)[A-Za-z0-9@.\-]+$")
_SUBPROCESS_TIMEOUT = 30


class SigningError(Exception):
    """A signing or roster operation could not be completed (not a verify
    failure — those are returned as statuses, never raised)."""


def canonical(payload: dict) -> bytes:
    """The exact bytes that get signed. Sorted keys, no whitespace, ASCII —
    any two producers agreeing on the field values produce identical bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def valid_principal(principal: str | None) -> bool:
    """A principal is one token in the ``allowed_signers`` line format: no
    whitespace, no quotes. It is also the ``decided_by.operator`` string."""
    return bool(principal) and bool(_PRINCIPAL_RE.match(principal))


_verifier_cache: dict[str, str | None] = {}


def verifier() -> str | None:
    """Version string of a usable ``ssh-keygen -Y``, or None. Cached per
    process; tests reset ``_verifier_cache``."""
    if "v" in _verifier_cache:
        return _verifier_cache["v"]
    found: str | None = None
    exe = shutil.which("ssh-keygen")
    if exe:
        try:
            # `-Y` without a subcommand: OpenSSH >= 8.2 complains about the
            # missing argument; an older ssh-keygen says "unknown option".
            probe = subprocess.run([exe, "-Y"], capture_output=True, text=True,
                                   timeout=_SUBPROCESS_TIMEOUT)
            err = (probe.stderr or "") + (probe.stdout or "")
            if "unknown option" not in err and "illegal option" not in err:
                ver = subprocess.run(["ssh", "-V"], capture_output=True, text=True,
                                     timeout=_SUBPROCESS_TIMEOUT)
                found = ((ver.stderr or ver.stdout or "").strip().split(",")[0]
                         or "ssh-keygen (version unknown)")
        except (OSError, subprocess.SubprocessError):
            found = None
    _verifier_cache["v"] = found
    return found


def sign(payload: bytes, *, key_path: str | Path) -> str:
    """Sign ``payload`` with the SSH key at ``key_path`` (a private key, or a
    public key whose private half is loaded in ``ssh-agent``). Returns the
    armored SSHSIG block. A passphrase prompt, if any, goes to the terminal —
    this is a human action by construction."""
    exe = shutil.which("ssh-keygen")
    if not exe or verifier() is None:
        raise SigningError("ssh-keygen with -Y support (OpenSSH >= 8.2) is required to sign "
                           "decisions and was not found on PATH")
    key = Path(os.path.expanduser(str(key_path)))
    if not key.is_file():
        raise SigningError(f"signing key not found: {key}")
    try:
        proc = subprocess.run([exe, "-Y", "sign", "-f", str(key), "-n", NAMESPACE, "-"],
                              input=payload, capture_output=True, timeout=_SUBPROCESS_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise SigningError(f"ssh-keygen -Y sign timed out after {_SUBPROCESS_TIMEOUT}s "
                           "(a passphrase prompt with no terminal?)") from e
    if proc.returncode != 0:
        raise SigningError("ssh-keygen -Y sign failed: "
                           + (proc.stderr.decode(errors="replace").strip() or "unknown error"))
    armored = proc.stdout.decode("ascii", errors="replace").strip()
    if not armored.startswith("-----BEGIN SSH SIGNATURE-----"):
        raise SigningError("ssh-keygen -Y sign produced no signature")
    return armored + "\n"


def verify(payload: bytes, signature: str, *, allowed_signers: str | Path,
           principal: str) -> tuple[str, str]:
    """Check ``signature`` over ``payload`` for ``principal`` against the
    roster. Returns ``(status, detail)`` with status one of VERIFIED, INVALID,
    UNVERIFIABLE — never raises for a bad signature (that is a result, not an
    error). ``principal`` must be a roster token; anything else is INVALID."""
    if verifier() is None:
        return UNVERIFIABLE, "ssh-keygen -Y (OpenSSH >= 8.2) not available on this machine"
    roster = Path(allowed_signers)
    if not roster.is_file():
        return INVALID, f"no signer roster at {roster}"
    if not valid_principal(principal):
        return INVALID, f"principal {principal!r} is not a valid roster token"
    if not signature or "BEGIN SSH SIGNATURE" not in signature:
        return INVALID, "malformed signature block"
    exe = shutil.which("ssh-keygen")
    with tempfile.TemporaryDirectory(prefix="sc-sig-") as td:
        sig_path = Path(td) / "event.sig"
        sig_path.write_text(signature if signature.endswith("\n") else signature + "\n")
        try:
            proc = subprocess.run([exe, "-Y", "verify", "-f", str(roster), "-I", principal,
                                   "-n", NAMESPACE, "-s", str(sig_path)],
                                  input=payload, capture_output=True,
                                  timeout=_SUBPROCESS_TIMEOUT)
        except subprocess.TimeoutExpired:
            return UNVERIFIABLE, f"ssh-keygen -Y verify timed out after {_SUBPROCESS_TIMEOUT}s"
    if proc.returncode == 0:
        return VERIFIED, proc.stdout.decode(errors="replace").strip()
    err = proc.stderr.decode(errors="replace").strip().splitlines()
    return INVALID, (err[0] if err else "signature verification failed")[:200]


def roster_line(principal: str, pubkey_text: str) -> str:
    """One ``allowed_signers`` line, namespace-scoped to ours so a key trusted
    here is not thereby trusted for anything else (and vice versa: a key
    listed for git commit signing is not automatically a decision signer)."""
    if not valid_principal(principal):
        raise SigningError(f"principal {principal!r} must be a single token (no spaces/quotes)")
    if "PRIVATE KEY" in pubkey_text:
        raise SigningError("that is a PRIVATE key; the roster takes the .pub file")
    first = next((ln.strip() for ln in pubkey_text.splitlines() if ln.strip()
                  and not ln.strip().startswith("#")), "")
    parts = first.split()
    if len(parts) < 2 or not _KEYTYPE_RE.match(parts[0]):
        raise SigningError("not an OpenSSH public key line (expected `<keytype> <base64> "
                           "[comment]`, e.g. the contents of ~/.ssh/id_ed25519.pub)")
    return f'{principal} namespaces="{NAMESPACE}" {parts[0]} {parts[1]}\n'


def roster_principals(allowed_signers: str | Path) -> list[str]:
    """Principals listed in the roster (for `decisions verify` and doctor)."""
    try:
        text = Path(allowed_signers).read_text()
    except OSError:
        return []
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln.split()[0])
    return out


def roster_warnings(allowed_signers: str | Path) -> list[str]:
    """Hand-edited roster lines that weaken attribution without breaking
    verification (R13): pattern principals, lines valid for EVERY namespace,
    and certificate-authority lines that trust a whole CA. `trust` never
    writes these; `decisions verify` surfaces them."""
    try:
        text = Path(allowed_signers).read_text()
    except OSError:
        return []
    out = []
    for n, ln in enumerate(text.splitlines(), 1):
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        principal = ln.split()[0]
        if not valid_principal(principal):
            out.append(f"line {n}: principal {principal!r} is a pattern — it vouches for any "
                       "matching operator name")
        if f'namespaces="{NAMESPACE}"' not in ln and "namespaces=" not in ln:
            out.append(f"line {n}: no namespaces= option — this key is trusted for every "
                       "signature namespace, not just decisions")
        if "cert-authority" in ln:
            out.append(f"line {n}: cert-authority — every certificate this CA issues is trusted")
    return out


def resolve_policy(config: dict, *, store_initialised: bool, store_has_decisions: bool,
                   now_iso: str) -> dict:
    """Turn the configured level into the level that RUNS, and say why.

    The configured value comes from operator config (defaults < profile <
    config file < CLI flag), never from the store: a level stored in the
    target would be writable by the same party the signatures are meant to
    catch. Only the opt-in ``auto`` looks at the store, and its residual is
    documented (deleting ``store.json``, or committing a first unsigned record
    without one, resolves `auto` to `warn` until the sunset — visible in every
    manifest and report as the reason).
    """
    configured = str((config.get("decisions") or {}).get("require_signatures", "enforce"))
    if configured not in LEVELS:
        raise ValueError(f"decisions.require_signatures must be one of {LEVELS}, "
                         f"got {configured!r}")
    if configured == "auto":
        if store_initialised:
            effective, reason = "enforce", "store initialised for signing (store.json present)"
        elif not store_has_decisions:
            effective, reason = "enforce", "new store: no decisions recorded yet"
        elif now_iso >= WARN_SUNSET:
            effective, reason = "enforce", (f"pre-existing unsigned store; the warn period "
                                            f"ended {WARN_SUNSET[:10]}")
        else:
            effective, reason = "warn", (f"auto: store has decisions but no store.json, so "
                                         f"unsigned decisions still apply until "
                                         f"{WARN_SUNSET[:10]} (run `decisions init` + sign "
                                         "them, or set require_signatures: enforce)")
    else:
        effective, reason = configured, "set by config"
    return {"configured": configured, "effective": effective, "reason": reason,
            "verifier": verifier(), "namespace": NAMESPACE, "warn_sunset": WARN_SUNSET}
