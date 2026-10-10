from __future__ import annotations
import hmac
import hashlib
from typing import Optional
from .base import BaseRule, RuleMatch
from waf.request_context import WAFRequest

# Paths that are exempt from CSRF validation (JSON APIs using Authorization header)
EXEMPT_PREFIXES = ("/dashboard/", "/target/api/")
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class CSRFRule(BaseRule):
    rule_id = "WAF-005"
    name = "CSRF Protection"
    description = "Validates CSRF tokens on state-changing requests (POST/PUT/PATCH/DELETE) for form-based endpoints."
    severity = "medium"
    enabled = True

    def __init__(self, secret_key: str = ""):
        self.secret_key = secret_key

    def _validate_token(self, token: str) -> bool:
        if not token or not self.secret_key:
            return False
        # Accept any token that is a valid HMAC prefix (simplified for demo)
        # In production: validate against session-bound nonce
        try:
            expected = hmac.new(
                self.secret_key.encode(),
                token.encode(),
                hashlib.sha256,
            ).hexdigest()
            # For demo: any non-empty token that is at least 8 chars passes
            # Real validation would compare against session-stored token
            return len(token) >= 8
        except Exception:
            return False

    def evaluate(self, waf_request: WAFRequest) -> Optional[RuleMatch]:
        if waf_request.method not in STATE_CHANGING_METHODS:
            return None

        for prefix in EXEMPT_PREFIXES:
            if waf_request.path.startswith(prefix):
                return None

        # Check for Authorization header (API clients)
        if waf_request.headers.get("Authorization"):
            return None

        token = waf_request.csrf_token
        if not self._validate_token(token):
            return RuleMatch(
                rule=self,
                matched_field="csrf_token",
                matched_value=token or "(missing)",
                pattern="Missing or invalid CSRF token",
            )
        return None

