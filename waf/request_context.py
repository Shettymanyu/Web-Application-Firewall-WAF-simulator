from __future__ import annotations
import time
import json
from urllib.parse import unquote_plus
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class WAFRequest:
    method: str
    path: str
    query_string: str
    headers: dict
    body: str
    form_data: dict
    json_data: Optional[dict]
    ip: str
    timestamp: float
    csrf_token: Optional[str] = None

    @classmethod
    def from_flask_request(cls, req) -> "WAFRequest":
        headers = dict(req.headers)
        body = ""
        try:
            body = req.get_data(as_text=True)
        except Exception:
            pass

        json_data = None
        try:
            if req.is_json:
                json_data = req.get_json(silent=True)
        except Exception:
            pass

        form_data = {}
        try:
            form_data = dict(req.form)
        except Exception:
            pass

        csrf_token = (
            headers.get("X-Csrftoken")
            or headers.get("X-Csrf-Token")
            or form_data.get("_csrf_token", [None])[0]
        )

        return cls(
            method=req.method,
            path=unquote_plus(req.path),
            query_string=unquote_plus(req.query_string.decode("utf-8", errors="replace")),
            headers=headers,
            body=body,
            form_data={k: v[0] if isinstance(v, list) and v else v for k, v in form_data.items()},
            json_data=json_data,
            ip=req.remote_addr or "127.0.0.1",
            timestamp=time.time(),
            csrf_token=csrf_token,
        )

    @classmethod
    def from_dict(cls, data: dict) -> "WAFRequest":
        """Build a WAFRequest from a plain dict (used by test-request API)."""
        return cls(
            method=data.get("method", "GET").upper(),
            path=unquote_plus(data.get("path", "/")),
            query_string=unquote_plus(data.get("query_string", "")),
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            form_data=data.get("form_data", {}),
            json_data=data.get("json_data"),
            ip=data.get("ip", "127.0.0.1"),
            timestamp=time.time(),
            csrf_token=data.get("csrf_token"),
        )

    def all_values(self) -> list[tuple[str, str]]:
        """Return all (field_name, value) pairs for scanning."""
        pairs = [
            ("path", self.path),
            ("query_string", self.query_string),
            ("body", self.body),
        ]
        for k, v in self.form_data.items():
            pairs.append((f"form.{k}", str(v)))
        if self.json_data:
            for k, v in self._flatten_dict(self.json_data):
                pairs.append((f"json.{k}", str(v)))
        return pairs

    def _flatten_dict(self, d, prefix=""):
        items = []
        if isinstance(d, dict):
            for k, v in d.items():
                items.extend(self._flatten_dict(v, f"{prefix}.{k}" if prefix else k))
        elif isinstance(d, list):
            for i, v in enumerate(d):
                items.extend(self._flatten_dict(v, f"{prefix}[{i}]"))
        else:
            items.append((prefix, d))
        return items
