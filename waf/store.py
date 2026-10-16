from __future__ import annotations
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
import uuid


@dataclass
class LogEntry:
    id: str
    timestamp: float
    ip: str
    method: str
    path: str
    action: str          # "BLOCKED" or "ALLOWED"
    rule_id: Optional[str]
    rule_name: Optional[str]
    severity: Optional[str]
    matched_field: Optional[str]
    matched_value: Optional[str]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "timestamp_str": time.strftime("%H:%M:%S", time.localtime(self.timestamp)),
            "ip": self.ip,
            "method": self.method,
            "path": self.path,
            "action": self.action,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched_field": self.matched_field,
            "matched_value": self.matched_value,
        }


class WAFStore:
    def __init__(self, max_entries: int = 500):
        self._lock = threading.Lock()
        self._log: deque[LogEntry] = deque(maxlen=max_entries)
        self._log_version = 0   # incremented on each add
        self._stats = {
            "total_requests": 0,
            "total_blocked": 0,
            "by_rule": {},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "timeseries": [],   # list of {ts, blocked, allowed}
        }
        self._rule_states: dict[str, bool] = {}
        self._rate_buckets: dict[str, dict] = {}

    # ── Log ───────────────────────────────────────────────────────────────────

    def add_log_entry(self, entry: LogEntry):
        with self._lock:
            self._log.append(entry)
            self._log_version += 1
            self._stats["total_requests"] += 1
            if entry.action == "BLOCKED":
                self._stats["total_blocked"] += 1
                if entry.rule_id:
                    self._stats["by_rule"][entry.rule_id] = (
                        self._stats["by_rule"].get(entry.rule_id, 0) + 1
                    )
                if entry.severity and entry.severity in self._stats["by_severity"]:
                    self._stats["by_severity"][entry.severity] += 1
            # Timeseries bucket (per minute)
            bucket_ts = int(entry.timestamp // 60) * 60
            ts_list = self._stats["timeseries"]
            if ts_list and ts_list[-1]["ts"] == bucket_ts:
                if entry.action == "BLOCKED":
                    ts_list[-1]["blocked"] += 1
                else:
                    ts_list[-1]["allowed"] += 1
            else:
                ts_list.append({
                    "ts": bucket_ts,
                    "blocked": 1 if entry.action == "BLOCKED" else 0,
                    "allowed": 0 if entry.action == "BLOCKED" else 1,
                })
                if len(ts_list) > 60:
                    ts_list.pop(0)

    def get_logs(self, limit: int = 100, severity_filter: str = None,
                 action_filter: str = None) -> list[dict]:
        with self._lock:
            entries = list(self._log)
        entries.reverse()
        if severity_filter:
            entries = [e for e in entries if e.severity == severity_filter]
        if action_filter:
            entries = [e for e in entries if e.action == action_filter]
        return [e.to_dict() for e in entries[:limit]]

    def get_log_version(self) -> int:
        with self._lock:
            return self._log_version

    def get_new_entries_since(self, version: int) -> tuple[list[dict], int]:
        with self._lock:
            current_version = self._log_version
            entries = list(self._log)
        entries.reverse()
        new_count = current_version - version
        if new_count <= 0:
            return [], current_version
        return [e.to_dict() for e in entries[:new_count]], current_version

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_requests": self._stats["total_requests"],
                "total_blocked": self._stats["total_blocked"],
                "total_allowed": self._stats["total_requests"] - self._stats["total_blocked"],
                "block_rate": round(
                    self._stats["total_blocked"] / max(self._stats["total_requests"], 1) * 100, 1
                ),
                "by_rule": dict(self._stats["by_rule"]),
                "by_severity": dict(self._stats["by_severity"]),
                "timeseries": list(self._stats["timeseries"]),
            }

    # ── Rule State ────────────────────────────────────────────────────────────

    def register_rule(self, rule_id: str, default_enabled: bool = True):
        with self._lock:
            if rule_id not in self._rule_states:
                self._rule_states[rule_id] = default_enabled

    def set_rule_state(self, rule_id: str, enabled: bool):
        with self._lock:
            self._rule_states[rule_id] = enabled

    def is_rule_enabled(self, rule_id: str) -> bool:
        with self._lock:
            return self._rule_states.get(rule_id, True)

    def get_rule_states(self) -> dict:
        with self._lock:
            return dict(self._rule_states)

    # ── Rate Limit Buckets ────────────────────────────────────────────────────

    def get_bucket(self, ip: str) -> dict:
        with self._lock:
            return self._rate_buckets.get(ip)

    def set_bucket(self, ip: str, bucket: dict):
        with self._lock:
            self._rate_buckets[ip] = bucket
