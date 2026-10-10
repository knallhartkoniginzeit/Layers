from __future__ import annotations

import re

from layers.ingest.redact import redact_all
from layers.schemas import FailureCase

_IDEMPOTENT = frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"})

_EXCEPTION_MAP: dict[str, str] = {
    "ReadTimeout": "ReadTimeout",
    "ConnectTimeout": "ConnectTimeout",
    "ConnectionTimeout": "ConnectTimeout",
    "ConnectError": "ConnectError",
    "ConnectionError": "ConnectError",
    "SSLError": "SSLError",
    "CertificateError": "SSLError",
    "ProxyError": "ProxyError",
    "TooManyRedirects": "TooManyRedirects",
    "RemoteDisconnected": "RemoteProtocolError",
    "RemoteProtocolError": "RemoteProtocolError",
    "InvalidURL": "InvalidURL",
    "MissingSchema": "InvalidURL",
    "NameResolutionError": "ConnectError",
}

_URL_RE = re.compile(r"https?://[^\s\"',;>)]+", re.IGNORECASE)
_ELAPSED_RE = re.compile(
    r"(?:timeout\s*=\s*|timed?\s*out[^\d\n]*?|after\s*)(\d+(?:\.\d+)?)\s*(?:s|seconds?)?",
    re.IGNORECASE,
)
_STATUS_RE = re.compile(
    r"(?:HTTP\s*(?:status)?|status\s*(?:code)?)\s*[:=]?\s*(\d{3})", re.IGNORECASE
)
_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
_EXCEPTION_CLASS_RE = re.compile(
    r"(?:raise\s+)?([A-Za-z_][A-Za-z0-9_.]*(?:Error|Timeout|Exception|Warning))"
)


def from_exception(text: str) -> FailureCase:
    """
    Parse a Python traceback or exception message into a FailureCase.

    Handles output from:
    - ``requests`` (ReadTimeout, SSLError, ConnectionError, …)
    - ``httpx`` (ConnectError, ReadTimeout, …)
    - ``urllib3`` (MaxRetryError, …)
    """
    text = text.strip()

    url_matches = _URL_RE.findall(text)
    url = url_matches[0] if url_matches else ""

    method_m = _METHOD_RE.search(text)
    method = method_m.group(1) if method_m else "GET"

    error_class: str | None = None
    for m in _EXCEPTION_CLASS_RE.finditer(text):
        candidate = m.group(1).split(".")[-1]
        for fragment, canonical in _EXCEPTION_MAP.items():
            if fragment.lower() in candidate.lower():
                error_class = canonical
                break
        if error_class:
            break

    elapsed_ms: float | None = None
    el_m = _ELAPSED_RE.search(text)
    if el_m:
        elapsed_ms = float(el_m.group(1)) * 1000

    status: int | None = None
    st_m = _STATUS_RE.search(text)
    if st_m:
        candidate_status = int(st_m.group(1))
        if 100 <= candidate_status <= 599:
            status = candidate_status

    idempotent = method in _IDEMPOTENT
    has_idempotency_key = False

    clean_url, clean_headers, clean_body = redact_all(url, {}, None)

    return FailureCase(
        method=method,
        url=clean_url,
        request_headers=clean_headers,
        request_body_sample=clean_body,
        status=status,
        response_headers={},
        response_body_sample=None,
        error_class=error_class,
        elapsed_ms=elapsed_ms,
        idempotent=idempotent,
        has_idempotency_key=has_idempotency_key,
    )
