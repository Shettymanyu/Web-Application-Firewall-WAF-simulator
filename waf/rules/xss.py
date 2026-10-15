from __future__ import annotations
import re
from html import unescape
from urllib.parse import unquote_plus
from typing import Optional
from .base import BaseRule, RuleMatch
from waf.request_context import WAFRequest


PATTERNS = [
    (re.compile(r"<script[\s\S]*?>", re.IGNORECASE), "Script tag injection"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "JavaScript pseudo-protocol"),
    (re.compile(r"\bon\w+\s*=", re.IGNORECASE), "Event handler injection"),
    (re.compile(r"<(iframe|object|embed|applet|meta|link|base)[^>]*>", re.IGNORECASE), "Dangerous HTML tag"),
    (re.compile(r"(alert|confirm|prompt|document\.cookie|document\.write|window\.location)\s*[\(=]", re.IGNORECASE), "XSS payload function"),
    (re.compile(r"expression\s*\(", re.IGNORECASE), "CSS expression"),
    (re.compile(r"&#x?[0-9a-fA-F]+;", re.IGNORECASE), "HTML entity encoding bypass"),
    (re.compile(r"<[^>]+\s+src\s*=\s*['\"]?\s*javascript", re.IGNORECASE), "Inline JS src"),
    (re.compile(r"vbscript\s*:", re.IGNORECASE), "VBScript injection"),
    (re.compile(r"data\s*:\s*text/html", re.IGNORECASE), "Data URI XSS"),
]


def _decode(val: str) -> str:
    try:
        return unescape(unquote_plus(val))
    except Exception:
        return val


class XSSRule(BaseRule):
    rule_id = "WAF-002"
    name = "Cross-Site Scripting (XSS)"
    description = "Detects XSS payloads including script tags, event handlers, JS protocol URIs, and encoding bypasses."
    severity = "high"
    enabled = True

    def evaluate(self, waf_request: WAFRequest) -> Optional[RuleMatch]:
        scan_pairs = waf_request.all_values()
        # Also check Referer header
        referer = waf_request.headers.get("Referer", "")
        if referer:
            scan_pairs.append(("header.Referer", referer))

        for field_name, raw_value in scan_pairs:
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

