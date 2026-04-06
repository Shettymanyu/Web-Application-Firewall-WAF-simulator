from __future__ import annotations
import time
import json
from flask import current_app, jsonify, render_template, request, Response, stream_with_context
from . import dashboard_bp
from waf.request_context import WAFRequest


def _engine():
    return current_app.extensions["waf_engine"]

def _store():
    return current_app.extensions["waf_store"]


@dashboard_bp.route("/")
@dashboard_bp.route("")
def index():
    return render_template("dashboard/index.html")


@dashboard_bp.route("/api/logs")
def api_logs():
    limit = min(int(request.args.get("limit", 100)), 500)
    severity = request.args.get("severity") or None
    action = request.args.get("action") or None
    logs = _store().get_logs(limit=limit, severity_filter=severity, action_filter=action)
    return jsonify(logs)


@dashboard_bp.route("/api/stats")
def api_stats():
    return jsonify(_store().get_stats())


@dashboard_bp.route("/api/rules")
def api_rules():
    return jsonify(_engine().get_rules_info())


@dashboard_bp.route("/api/rules/<rule_id>/toggle", methods=["POST"])
def api_toggle_rule(rule_id):
    states = _store().get_rule_states()
    if rule_id not in states:
        return jsonify({"error": "Rule not found"}), 404
    new_state = not states[rule_id]
    _store().set_rule_state(rule_id, new_state)
    return jsonify({"rule_id": rule_id, "enabled": new_state})


@dashboard_bp.route("/api/stream")
def api_stream():
    """Server-Sent Events endpoint for live log streaming."""
    store = _store()

    def generate():
        version = store.get_log_version()
        # Send current state immediately
        yield f"data: {json.dumps({'type': 'connected'})}\n\n"
        while True:
            new_entries, version = store.get_new_entries_since(version)
            for entry in reversed(new_entries):
                yield f"data: {json.dumps({'type': 'log', 'entry': entry})}\n\n"
            time.sleep(0.5)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@dashboard_bp.route("/api/test-request", methods=["POST"])
def api_test_request():
    """Accept a test request definition and run it through the WAF engine."""
    data = request.get_json(silent=True) or {}

    # Parse headers from text format ("Key: Value\nKey2: Value2")
    headers = {}
    raw_headers = data.get("headers", "")
    if isinstance(raw_headers, str):
        for line in raw_headers.strip().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
    elif isinstance(raw_headers, dict):
        headers = raw_headers

    # Parse query string from URL if included
    path = data.get("path", "/")
    query_string = ""
    if "?" in path:
        path, query_string = path.split("?", 1)

    waf_req = WAFRequest.from_dict({
        "method": data.get("method", "GET"),
        "path": path,
        "query_string": query_string,
        "headers": headers,
        "body": data.get("body", ""),
        "form_data": data.get("form_data", {}),
        "json_data": data.get("json_data"),
        "ip": request.remote_addr or "127.0.0.1",
        "csrf_token": headers.get("X-CSRFToken") or headers.get("X-Csrf-Token"),
    })

    engine = _engine()
    decision = engine.inspect(waf_req)

    response = {
        "action": decision.action,
        "rule_id": None,
        "rule_name": None,
        "severity": None,
        "matched_field": None,
        "matched_value": None,
    }

    if decision.rule_match:
        rm = decision.rule_match
        response.update({
            "rule_id": rm.rule.rule_id,
            "rule_name": rm.rule.name,
            "severity": rm.rule.severity,
            "matched_field": rm.matched_field,
            "matched_value": rm.matched_value,
            "pattern": rm.pattern,
        })

    return jsonify(response)
