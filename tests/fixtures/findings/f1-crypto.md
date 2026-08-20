# Candidate F1 — CWE-327/CWE-916 weak password hash
- file: app/crypto_util.py, function `hash_password`, line ~7
- claim: user passwords hashed with unsalted MD5; trivially reversible/brute-forceable.
- reported_by: semgrep, house-prompt
- expected: TRUE POSITIVE. Crypto family — must_not_demote.
