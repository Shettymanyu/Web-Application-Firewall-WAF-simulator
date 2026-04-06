from __future__ import annotations
import re
from urllib.parse import unquote_plus
from typing import Optional
from .base import BaseRule, RuleMatch
from waf.request_context import WAFRequest


PATTERNS = [
    (re.compile(r"[;&|`]\s*(ls|cat|id|whoami|pwd|uname|ps|netstat|wget|curl|nc|bash|sh|python|perl|php|ruby)\b", re.IGNORECASE), "Shell command chaining"),
    (re.compile(r"\$\([^)]+\)"), "Command substitution $()"),
    (re.compile(r"`[^`]+`"), "Backtick command execution"),
    (re.compile(r"(\/bin\/|\/usr\/bin\/|\/usr\/local\/bin\/)(bash|sh|python|perl|nc|ncat|netcat)\b", re.IGNORECASE), "Absolute path to shell"),
    (re.compile(r">\s*\/dev\/(null|tcp|udp)", re.IGNORECASE), "Redirection to /dev/"),
    (re.compile(r"\|\s*(bash|sh|python|perl|ruby)\b", re.IGNORECASE), "Piped shell execution"),
    (re.compile(r"&&\s*(rm|mv|cp|chmod|chown|kill|reboot|shutdown)\b", re.IGNORECASE), "Chained destructive command"),
    (re.compile(r"(;|\|)\s*\w+\s+-rf\s+", re.IGNORECASE), "rm -rf via chaining"),
    (re.compile(r"(exec|system|passthru|shell_exec|popen)\s*\(", re.IGNORECASE), "PHP/code execution function"),
]


def _decode(val: str) -> str:
    try:
        return unquote_plus(val)
    except Exception:
        return val


class CommandInjectionRule(BaseRule):
    rule_id = "WAF-004"
    name = "Command Injection"
    description = "Detects OS command injection via shell metacharacters, command substitution, piping, and chained destructive commands."
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
