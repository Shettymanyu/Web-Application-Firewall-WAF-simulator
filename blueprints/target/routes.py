from __future__ import annotations
import secrets
import hashlib
import hmac
from flask import current_app, render_template, request, redirect, url_for, session
from . import target_bp


def _generate_csrf_token() -> str:
    token = secrets.token_hex(32)
    session["csrf_token"] = token
    return token


def _get_csrf_token() -> str:
    if "csrf_token" not in session:
        return _generate_csrf_token()
    return session["csrf_token"]


@target_bp.route("/")
def index():
    return render_template("target/index.html")


@target_bp.route("/login", methods=["GET", "POST"])
def login():
    csrf_token = _get_csrf_token()
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Simulated "vulnerable" query display only - no real DB execution
        result = {
            "type": "success",
            "message": f"Query would execute: SELECT * FROM users WHERE username='{username}' AND password='{password}'",
            "username": username,
        }
    return render_template("target/login.html", csrf_token=csrf_token, result=result)


@target_bp.route("/search")
def search():
    query = request.args.get("q", "")
    results = []
    if query:
        # Simulate search results - no real execution
        results = [
            {"title": f"Result for: {query}", "url": f"/target/item/1"},
            {"title": "About Us", "url": "/target/item/2"},
        ]
    return render_template("target/search.html", query=query, results=results)


@target_bp.route("/files")
def files():
    filepath = request.args.get("file", "")
    content = None
    if filepath:
        content = f"[Simulated] File contents of: {filepath}"
    return render_template("target/files.html", filepath=filepath, content=content)


@target_bp.route("/cmd")
def cmd():
    host = request.args.get("host", "")
    output = None
    if host:
        output = f"[Simulated] PING {host}: 64 bytes from {host}: icmp_seq=1 ttl=64 time=0.042 ms"
    return render_template("target/cmd.html", host=host, output=output)


@target_bp.route("/comment", methods=["POST"])
def comment():
    csrf_token = _get_csrf_token()
    comment_text = request.form.get("comment", "")
    return render_template(
        "target/comment_result.html",
        comment=comment_text,
        csrf_token=csrf_token,
    )
