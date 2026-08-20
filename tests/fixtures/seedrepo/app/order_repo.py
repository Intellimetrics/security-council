"""Data access. The cross-tenant guard is MISSING here, not in routes.py."""
import sqlite3

def _db():
    return sqlite3.connect("orders.db")

def get_order(order_id):
    # BUG (CWE-639): loads by primary key only. No tenant/owner check, so any
    # authenticated user can read any other tenant's order by guessing the id.
    # The reachability path is app/routes.py:orders -> here.
    cur = _db().cursor()
    cur.execute("SELECT id, tenant_id, total FROM orders WHERE id = ?", (order_id,))
    row = cur.fetchone()
    return {"id": row[0], "tenant_id": row[1], "total": row[2]} if row else {}
