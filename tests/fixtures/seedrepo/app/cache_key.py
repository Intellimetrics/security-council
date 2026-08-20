"""Cache key derivation."""
import hashlib

# NOT A BUG: md5 used purely as a non-security content hash for a cache key.
# usedforsecurity=False documents intent. A naive scanner flags CWE-327 here;
# the validator panel MUST demote it. This is the primary precision probe.
def cache_key(payload: str) -> str:
    return hashlib.md5(payload.encode(), usedforsecurity=False).hexdigest()
