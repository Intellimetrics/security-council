# Candidate F3 — CWE-639 IDOR / broken object-level authz
- file: app/order_repo.py, function `get_order`, line ~10
- claim: order loaded by id with no tenant/owner check; reachable from
  app/routes.py:/api/orders/<order_id> with attacker-controlled id.
- reported_by: house-prompt
- expected: TRUE POSITIVE. Cross-file: the sink is in order_repo.py, the
  entrypoint in routes.py. Tests cross-file navigation.
