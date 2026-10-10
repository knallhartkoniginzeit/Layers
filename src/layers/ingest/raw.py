"""
layers – ingest/raw.py
Parse raw pasted input: status + headers + body.

Input format (loosely):
    HTTP/1.1 502 Bad Gateway
    Content-Type: text/html
    Server: nginx/1.24

    <html>502 Bad Gateway</html>

Or just:
    502
    {"error": "rate limited"}
"""

from __future__ import annotations

import re

from layers.config import settings
from layers.ingest.redact import redact_all
from layers.schemas import FailureCase

_STATUS_LINE_RE = re.compile(r"^HTTP/\S+\s+(\d{3})|^(\d{3})\s", re.MULTILINE)
_HEADER_RE = re.compile(r"^([A-Za-z0-9_\-]+):\s*(.+)$", re.MULTILINE)
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")


def from_raw(
    text: str,
    method: str = "GET",
    url: str = "",
    elapsed_ms: float | None = None,
) -> FailureCase:
    """
    Build a FailureCase from raw pasted HTTP response text.

    *method* and *url* can be supplied by the caller (e.g., from CLI flags).
    If *url* is empty the parser tries to extract one from the text.
    """
    text = text.strip()

    status: int | None = None
    sm = _STATUS_LINE_RE.search(text)
    if sm:
        raw = sm.group(1) or sm.group(2)
        status = int(raw)

    resp_headers: dict[str, str] = {}
    body_start = 0
    blank = re.search(r"\n\s*\n", text)
    header_section = text[: blank.start()] if blank else text
    for m in _HEADER_RE.finditer(header_section):
        resp_headers[m.group(1).strip()] = m.group(2).strip()
    if blank:
        body_start = blank.end()

    body: str | None = None
    if blank and body_start < len(text):
        body = text[body_start:].strip() or None

    if not url:
        um = _URL_RE.search(text)
        url = um.group(0) if um else ""

    if not method:
        mm = _METHOD_RE.search(text)
        method = mm.group(1) if mm else "GET"

    method = method.upper()
    idempotent = method in {"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"}
    has_idempotency_key = any(
        h.lower() in ("idempotency-key", "idempotency_key") for h in resp_headers
    )

    clean_url, clean_headers, clean_body = redact_all(url, {}, None, settings.max_body_sample)
    _, clean_resp_h, clean_resp_body = redact_all("", resp_headers, body, settings.max_body_sample)

    return FailureCase(
        method=method,
        url=clean_url,
        request_headers=clean_headers,
        request_body_sample=clean_body,
        status=status,
        response_headers=clean_resp_h,
        response_body_sample=clean_resp_body,
        error_class=None,
        elapsed_ms=elapsed_ms,
        idempotent=idempotent,
        has_idempotency_key=has_idempotency_key,
    )
