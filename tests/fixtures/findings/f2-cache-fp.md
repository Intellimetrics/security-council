# Candidate F2 — CWE-327 weak hash (cache key)
- file: app/cache_key.py, function `cache_key`, line ~8
- claim: MD5 used; flagged as weak crypto.
- reported_by: semgrep
- expected: FALSE POSITIVE. md5(..., usedforsecurity=False) as a non-security
  cache key. The panel must DEMOTE this. Primary precision probe.
