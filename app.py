from flask import Flask, request, jsonify, render_template_string
from config import Config
from waf.engine import WAFEngine
from waf.store import WAFStore
from waf.request_context import WAFRequest


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = Config.SECRET_KEY

    store = WAFStore(max_entries=Config.LOG_MAX_ENTRIES)
    engine = WAFEngine(store=store, config=Config)

    app.extensions["waf_engine"] = engine
    app.extensions["waf_store"] = store

    from blueprints.dashboard import dashboard_bp
    from blueprints.target import target_bp

    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
    app.register_blueprint(target_bp, url_prefix="/target")

    @app.before_request
    def waf_intercept():
        # Skip WAF for dashboard UI itself
        if request.path.startswith("/dashboard"):
            return None
        if request.path in ("/", "/favicon.ico"):
            return None

        waf_req = WAFRequest.from_flask_request(request)
        decision = engine.inspect(waf_req)

        if decision.action == "block" and Config.WAF_MODE == "block":
            rule = decision.rule_match.rule if decision.rule_match else None
            rule_id = rule.rule_id if rule else "N/A"
            rule_name = rule.name if rule else "Unknown"
            severity = rule.severity if rule else "unknown"
            matched_field = decision.rule_match.matched_field if decision.rule_match else ""
            matched_value = decision.rule_match.matched_value if decision.rule_match else ""

            blocked_html = render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>403 - Blocked by WAF</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-white min-h-screen flex items-center justify-center">
  <div class="max-w-lg w-full mx-4">
    <div class="bg-red-900/40 border border-red-500 rounded-2xl p-8 shadow-2xl text-center">
      <div class="text-6xl mb-4">🛡️</div>
      <h1 class="text-3xl font-bold text-red-400 mb-2">Request Blocked</h1>
      <p class="text-gray-300 mb-6">This request was intercepted by the Web Application Firewall.</p>
      <div class="bg-gray-900 rounded-xl p-4 text-left text-sm space-y-2 mb-6">
        <div class="flex justify-between">
          <span class="text-gray-400">Rule ID</span>
          <span class="font-mono text-yellow-400">{{ rule_id }}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">Rule</span>
          <span class="font-semibold text-white">{{ rule_name }}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">Severity</span>
          <span class="font-semibold
            {% if severity == 'critical' %}text-red-400
            {% elif severity == 'high' %}text-orange-400
            {% elif severity == 'medium' %}text-yellow-400
            {% else %}text-blue-400{% endif %}">
            {{ severity|upper }}
          </span>
        </div>
        {% if matched_field %}
        <div class="flex justify-between">
          <span class="text-gray-400">Matched Field</span>
          <span class="font-mono text-purple-400">{{ matched_field }}</span>
        </div>
        {% endif %}
        {% if matched_value %}
        <div class="pt-2">
          <span class="text-gray-400 block mb-1">Matched Value</span>
          <span class="font-mono text-red-300 bg-red-950/50 px-2 py-1 rounded block break-all text-xs">
            {{ matched_value[:120] }}{% if matched_value|length > 120 %}...{% endif %}
          </span>
        </div>
        {% endif %}
      </div>
      <a href="/dashboard" class="inline-block bg-blue-600 hover:bg-blue-500 text-white font-semibold px-6 py-2 rounded-lg transition-colors">
        View WAF Dashboard →
      </a>
    </div>
  </div>
</body>
</html>
""", rule_id=rule_id, rule_name=rule_name, severity=severity,
                matched_field=matched_field, matched_value=matched_value)
            return blocked_html, 403

        return None

    @app.route("/")
    def index():
        return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WAF Simulator</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-white min-h-screen flex items-center justify-center">
  <div class="text-center max-w-md mx-4">
    <div class="text-7xl mb-6">🛡️</div>
    <h1 class="text-4xl font-bold mb-3">WAF Simulator</h1>
    <p class="text-gray-400 mb-8">A real-time Web Application Firewall with live attack detection, ModSecurity-style rules, and an interactive dashboard.</p>
    <div class="flex flex-col sm:flex-row gap-3 justify-center">
      <a href="/dashboard" class="bg-blue-600 hover:bg-blue-500 px-6 py-3 rounded-xl font-semibold transition-colors">
        Open Dashboard
      </a>
      <a href="/target" class="bg-gray-700 hover:bg-gray-600 px-6 py-3 rounded-xl font-semibold transition-colors">
        Target App
      </a>
    </div>
  </div>
</body>
</html>
"""

    return app


if __name__ == "__main__":
    app = create_app()
    print("\n  WAF Simulator running at http://127.0.0.1:5000")
    print("  Dashboard:  http://127.0.0.1:5000/dashboard")
    print("  Target App: http://127.0.0.1:5000/target\n")
    app.run(debug=True, threaded=True)
