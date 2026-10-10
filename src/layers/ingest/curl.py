"""
layers – ingest/curl.py
Parse a curl command string (or the output of `curl -v`) into a FailureCase.

Supports:
  - curl -X POST https://... -H 'Header: val' -d '{"k":"v"}'
  - Output captured with: curl -sS ... 2>&1 | layers diagnose - --curl
"""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

from layers.config import settings
from layers.ingest.redact import redact_all
from layers.schemas import FailureCase

_IDEMPOTENT = frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"})

_FIXED_DURATION_RE = re.compile(
    r"(?:curl|failed|timed?\s*out)[^\n]*?(\d+(?:\.\d+)?)\s*s(?:econds?)?",
    re.IGNORECASE,
)
_STATUS_RE = re.compile(r"(?:^|\s)HTTP/\S+\s+(\d{3})", re.MULTILINE)
_HEADER_RE = re.compile(r"^<\s+([A-Za-z0-9_\-]+):\s*(.+)$", re.MULTILINE)
_ERROR_CLASS_MAP = {
    "could not resolve host": "ConnectError",
    "connection refused": "ConnectError",
    "ssl": "SSLError",
    "tls": "SSLError",
    "timed out": "ReadTimeout",
    "operation timed out": "ReadTimeout",
    "connection timed out": "ConnectTimeout",
    "empty reply from server": "RemoteProtocolError",
}


def _detect_error_class(text: str) -> str | None:
    lower = text.lower()
    for pattern, cls in _ERROR_CLASS_MAP.items():
        if pattern in lower:
            return cls
    return None


def _parse_elapsed(text: str) -> float | None:
    m = _FIXED_DURATION_RE.search(text)
    if m:
        return float(m.group(1)) * 1000
    return None


def from_curl(text: str, provider: str | None = None) -> FailureCase:  # noqa: ARG001
    """
    Parse a curl command or curl verbose output into a FailureCase.

    The *text* argument can be:
    - A bare curl command string (``curl -X POST https://...``)
    - The stderr / stdout captured when running curl with ``-v`` or ``-sS``
    """
    text = text.strip()

    is_command = text.startswith("curl ")

    method = "GET"
    url = ""
    req_headers: dict[str, str] = {}
    body: str | None = None
    status: int | None = None
    resp_headers: dict[str, str] = {}
    error_class: str | None = None
    elapsed_ms: float | None = None

    if is_command:
        try:
            tokens = shlex.split(text)
        except ValueError:
            tokens = text.split()

        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in ("-X", "--request") and i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                i += 2
            elif tok in ("-H", "--header") and i + 1 < len(tokens):
                raw_hdr = tokens[i + 1]
                if ":" in raw_hdr:
                    k, _, v = raw_hdr.partition(":")
                    req_headers[k.strip()] = v.strip()
                i += 2
            elif tok in ("-d", "--data", "--data-raw", "--data-binary") and i + 1 < len(tokens):
                body = tokens[i + 1]
                if method == "GET":
                    method = "POST"
                i += 2
            elif tok in ("--get", "-G"):
                method = "GET"
                i += 1
            elif not tok.startswith("-") and ("http://" in tok or "https://" in tok):
                url = tok
                i += 1
            else:
                i += 1
    else:
        req_line = re.search(r"^>\s+([A-Z]+)\s+(\S+)\s+HTTP/", text, re.MULTILINE)
        if req_line:
            method = req_line.group(1)
            path = req_line.group(2)
            host_m = re.search(r"^>\s+[Hh]ost:\s*(\S+)", text, re.MULTILINE)
            scheme = "https" if "* SSL" in text or "* TLS" in text else "http"
            host = host_m.group(1) if host_m else "unknown"
            url = f"{scheme}://{host}{path}"

        for line in text.splitlines():
            line = line.strip()
            if line.startswith("> ") and ":" in line:
                hdr = line[2:]
                k, _, v = hdr.partition(":")
                req_headers[k.strip()] = v.strip()

        sm = _STATUS_RE.search(text)
        if sm:
            status = int(sm.group(1))

        for k, v in _HEADER_RE.findall(text):
            resp_headers[k.strip()] = v.strip()

        error_class = _detect_error_class(text)
        elapsed_ms = _parse_elapsed(text)

    if not url:
        raise ValueError("Could not extract a URL from the curl input.")

    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url

    idempotent = method in _IDEMPOTENT
    has_idempotency_key = "idempotency-key" in {
        k.lower() for k in req_headers
    } or "idempotency_key" in {k.lower() for k in req_headers}

    clean_url, clean_headers, clean_body = redact_all(
        url, req_headers, body, settings.max_body_sample
    )
    _, clean_resp_headers, _ = redact_all("", resp_headers, None)

    return FailureCase(
        method=method,
        url=clean_url,
        request_headers=clean_headers,
        request_body_sample=clean_body,
        status=status,
        response_headers=clean_resp_headers,
        response_body_sample=None,
        error_class=error_class,
        elapsed_ms=elapsed_ms,
        idempotent=idempotent,
        has_idempotency_key=has_idempotency_key,
    )
