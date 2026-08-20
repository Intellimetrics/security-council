"""HTTP entrypoints. Untrusted input enters here."""
from flask import Flask, request, jsonify
from app.order_repo import get_order
from app.reports import build_report
from app.crypto_util import hash_password

app = Flask(__name__)

@app.route("/api/orders/<order_id>")
def orders(order_id):
    # order_id comes straight from the URL — external, attacker-controlled.
    return jsonify(get_order(order_id))

@app.route("/api/reports")
def reports():
    fmt = request.args.get("format", "pdf")
    return build_report(request.args.get("name", ""), fmt)

@app.route("/api/register", methods=["POST"])
def register():
    return jsonify({"pw": hash_password(request.form["password"])})
