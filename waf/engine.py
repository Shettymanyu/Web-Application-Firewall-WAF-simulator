from __future__ import annotations
import uuid
import time
from dataclasses import dataclass
from typing import Optional, List

from waf.request_context import WAFRequest
from waf.store import WAFStore, LogEntry
from waf.rules.base import BaseRule, RuleMatch
from waf.rules import (
    SQLInjectionRule, XSSRule, PathTraversalRule,
    CommandInjectionRule, CSRFRule, RateLimitRule,
)


@dataclass
class WAFDecision:
    action: str           # "block" or "allow"
    rule_match: Optional[RuleMatch]


class WAFEngine:
    def __init__(self, store: WAFStore, config):
        self.store = store
        self.config = config

        csrf_rule = CSRFRule(secret_key=config.SECRET_KEY)
        rate_rule = RateLimitRule(
            capacity=config.RATE_LIMIT_MAX_REQUESTS,
            window_seconds=config.RATE_LIMIT_WINDOW_SECONDS,
            store=store,
        )

        self._rules: List[BaseRule] = [
            SQLInjectionRule(),
            XSSRule(),
            PathTraversalRule(),
            CommandInjectionRule(),
            csrf_rule,
            rate_rule,
        ]

        for rule in self._rules:
            store.register_rule(rule.rule_id, rule.enabled)

    @property
    def rules(self) -> List[BaseRule]:
        return self._rules

    def inspect(self, waf_request: WAFRequest) -> WAFDecision:
        match: Optional[RuleMatch] = None

        for rule in self._rules:
            if not self.store.is_rule_enabled(rule.rule_id):
                continue
            result = rule.evaluate(waf_request)
            if result:
                match = result
                break  # short-circuit on first match

        action = "block" if match else "allow"

        entry = LogEntry(
            id=str(uuid.uuid4())[:8],
            timestamp=time.time(),
            ip=waf_request.ip,
            method=waf_request.method,
            path=waf_request.path,
            action="BLOCKED" if action == "block" else "ALLOWED",
            rule_id=match.rule.rule_id if match else None,
            rule_name=match.rule.name if match else None,
            severity=match.rule.severity if match else None,
            matched_field=match.matched_field if match else None,
            matched_value=match.matched_value if match else None,
        )
        self.store.add_log_entry(entry)

        return WAFDecision(action=action, rule_match=match)

    def get_rules_info(self) -> list[dict]:
        rule_states = self.store.get_rule_states()
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "enabled": rule_states.get(r.rule_id, r.enabled),
            }
            for r in self._rules
        ]
