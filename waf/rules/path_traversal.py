from __future__ import annotations
import re
from urllib.parse import unquote_plus
from typing import Optional
from .base import BaseRule, RuleMatch
from waf.request_context import WAFRequest


PATTERNS = [
    (re.compile(r"\.\.[/\\]"), "Classic ../"),
    (re.compile(r"%2e%2e[%2f%5c]", re.IGNORECASE), "URL-encoded ../"),
    (re.compile(r"\.\.%c0%af", re.IGNORECASE), "Overlong UTF-8 ../"),
    (re.compile(r"%252e%252e", re.IGNORECASE), "Double URL-encoded .."),
    (re.compile(r"(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|\/proc\/self)", re.IGNORECASE), "Unix sensitive file"),
    (re.compile(r"(boot\.ini|win\.ini|system32[/\\]|autoexec\.bat)", re.IGNORECASE), "Windows sensitive file"),
    (re.compile(r"~[a-zA-Z0-9]+[/\\]", re.IGNORECASE), "Unix home directory traversal"),
    (re.compile(r"\.\.[^\w\s]", re.IGNORECASE), "Non-standard traversal"),
]


def _decode(val: str) -> str:
    try:
        return unquote_plus(val)
    except Exception:
        return val


class PathTraversalRule(BaseRule):
    rule_id = "WAF-003"
    name = "Path Traversal"
    description = "Detects directory traversal attempts using ../ sequences, URL-encoded variants, and direct sensitive file paths."
    severity = "high"
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
