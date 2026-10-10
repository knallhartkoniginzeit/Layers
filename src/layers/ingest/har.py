from __future__ import annotations

import json
from typing import Any

from layers.config import settings
from layers.ingest.redact import redact_all
from layers.schemas import FailureCase

_IDEMPOTENT = frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"})


def _first_entry(har: dict[str, Any]) -> dict[str, Any]:
    """Return the first log entry from a HAR object."""
    try:
        entries = har["log"]["entries"]
        if not entries:
            raise ValueError("HAR contains no entries.")
        entry: dict[str, Any] = entries[0]
        return entry
    except KeyError as e:
        raise ValueError(f"Malformed HAR: missing key {e}") from e


def _headers_to_dict(header_list: list[dict[str, str]]) -> dict[str, str]:
    return {h["name"]: h["value"] for h in header_list}


def from_har(text: str) -> FailureCase:
    """
    Parse a HAR JSON string.

    Accepts either:
    - A full HAR file (``{"log": {"entries": [...]}}``).
    - A single HAR entry object (``{"request": {...}, "response": {...}}``).
    """
    try:
        data: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"HAR input is not valid JSON: {e}") from e

    if "log" in data:
        entry = _first_entry(data)
    elif "request" in data:
        entry = data
    else:
        raise ValueError(
            "Could not identify HAR format. "
            "Expected a full HAR object with 'log' key or a bare entry with 'request' key."
        )

    req: dict[str, Any] = entry.get("request", {})
    resp: dict[str, Any] = entry.get("response", {})
    timings: dict[str, Any] = entry.get("timings", {})

    method = req.get("method", "GET").upper()
    url: str = req.get("url", "")

    req_headers = _headers_to_dict(req.get("headers", []))
    resp_headers = _headers_to_dict(resp.get("headers", []))

    post_data = req.get("postData", {})
    body_text: str | None = post_data.get("text") if post_data else None

    resp_content = resp.get("content", {})
    resp_body: str | None = resp_content.get("text")

    status: int | None = resp.get("status") or None
    if status == 0:
        status = None

    elapsed_ms: float | None = None
    total = timings.get("receive", 0) + timings.get("wait", 0) + timings.get("send", 0)
    if total > 0:
        elapsed_ms = float(total)
    elif entry.get("time"):
        elapsed_ms = float(entry["time"])

    idempotent = method in _IDEMPOTENT
    has_idempotency_key = any(
        h.lower() in ("idempotency-key", "idempotency_key") for h in req_headers
    )

    error_class: str | None = entry.get("_errorText") or entry.get("error")

    clean_url, clean_req_h, clean_body = redact_all(
        url, req_headers, body_text, settings.max_body_sample
    )
    _, clean_resp_h, clean_resp_body = redact_all(
        "", resp_headers, resp_body, settings.max_body_sample
    )

    return FailureCase(
        method=method,
        url=clean_url,
        request_headers=clean_req_h,
        request_body_sample=clean_body,
        status=status,
        response_headers=clean_resp_h,
        response_body_sample=clean_resp_body,
        error_class=error_class,
        elapsed_ms=elapsed_ms,
        idempotent=idempotent,
        has_idempotency_key=has_idempotency_key,
    )
