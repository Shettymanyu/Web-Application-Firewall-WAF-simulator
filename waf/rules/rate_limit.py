from __future__ import annotations
import time
from typing import Optional
from .base import BaseRule, RuleMatch
from waf.request_context import WAFRequest


class RateLimitRule(BaseRule):
    rule_id = "WAF-006"
    name = "Rate Limiting"
    description = "Token-bucket rate limiting per source IP. Blocks IPs exceeding the request threshold within the time window."
    severity = "medium"
    enabled = True

    def __init__(self, capacity: int = 30, window_seconds: int = 60, store=None):
        self.capacity = capacity
        self.refill_rate = capacity / window_seconds   # tokens per second
        self._store = store

    def evaluate(self, waf_request: WAFRequest) -> Optional[RuleMatch]:
        ip = waf_request.ip
        now = time.monotonic()

        bucket = self._store.get_bucket(ip) if self._store else None

        if bucket is None:
            bucket = {"tokens": float(self.capacity), "last_check": now}

        elapsed = now - bucket["last_check"]
        bucket["tokens"] = min(
            self.capacity,
            bucket["tokens"] + elapsed * self.refill_rate,
        )
        bucket["last_check"] = now

        if bucket["tokens"] < 1.0:
            if self._store:
                self._store.set_bucket(ip, bucket)
            return RuleMatch(
                rule=self,
                matched_field="source_ip",
                matched_value=ip,
                pattern=f"Rate limit exceeded (>{self.capacity} req/{int(self.capacity / self.refill_rate)}s)",
            )

        bucket["tokens"] -= 1.0
        if self._store:
            self._store.set_bucket(ip, bucket)
        return None

