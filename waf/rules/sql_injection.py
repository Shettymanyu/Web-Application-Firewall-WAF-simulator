from __future__ import annotations
import re
from html import unescape
from urllib.parse import unquote_plus
from typing import Optional
from .base import BaseRule, RuleMatch
from waf.request_context import WAFRequest


PATTERNS = [
    (re.compile(r"('|\b)(OR|AND)\b.{0,20}?(=|LIKE)\s*['\"\d]", re.IGNORECASE), "Boolean-based SQLi"),
    (re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE), "UNION SELECT"),
    (re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|TRUNCATE)\b", re.IGNORECASE), "Stacked queries"),
    (re.compile(r"(--\s*$|--\s+\w|#\s*$|\/\*[\s\S]*?\*\/)", re.IGNORECASE), "SQL comment stripping"),
    (re.compile(r"\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY)\s*\(", re.IGNORECASE), "Time-based blind SQLi"),
    (re.compile(r"\b(xp_cmdshell|information_schema|sysobjects|sys\.tables|pg_sleep)\b", re.IGNORECASE), "SQL enumeration"),
    (re.compile(r"'\s*(OR|AND)\s*'", re.IGNORECASE), "Classic OR/AND quote injection"),
    (re.compile(r"\b(CHAR|CONCAT|GROUP_CONCAT|HEX|UNHEX|ASCII|ORD)\s*\(", re.IGNORECASE), "SQL function abuse"),
]


def _decode(val: str) -> str:
    try:
        return unescape(unquote_plus(val))
    except Exception:
        return val


class SQLInjectionRule(BaseRule):
    rule_id = "WAF-001"
    name = "SQL Injection"
    description = "Detects SQL injection attempts including UNION, boolean-based, time-based, and stacked queries."
    severity = "critical"
    enabled = True

    def evaluate(self, waf_request: WAFRequest) -> Optional[RuleMatch]:
        for field_name, raw_value in waf_request.all_values():
            decoded = _decode(raw_value)
            for pattern, label in PATTERNS:
                m = pattern.search(decoded)
                if m:
                    return RuleMatch(
                        rule=self,
                        matched_field=field_name,
                        matched_value=decoded[:200],
                        pattern=label,
                    )
        return None

