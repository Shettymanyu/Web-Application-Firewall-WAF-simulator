from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from waf.request_context import WAFRequest


@dataclass
class RuleMatch:
    rule: "BaseRule"
    matched_field: str
    matched_value: str
    pattern: str


class BaseRule:
    rule_id: str = ""
    name: str = ""
    description: str = ""
    severity: str = "medium"
    enabled: bool = True

    def evaluate(self, waf_request: "WAFRequest") -> Optional[RuleMatch]:
        raise NotImplementedError

