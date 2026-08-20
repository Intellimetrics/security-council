"""Report builder."""
import os
import sqlite3

def build_report(name, fmt):
    con = sqlite3.connect("orders.db")
    # BUG (CWE-89): f-string SQL on request data.
    q = f"SELECT * FROM orders WHERE customer_name = '{name}'"
    rows = con.execute(q).fetchall()
    # BUG (CWE-78): shell=True on request-derived format string.
    os.system(f"/usr/bin/render --format {fmt} --rows {len(rows)}")
    return {"rows": len(rows)}
