from __future__ import annotations

import re

from layers.config import settings

ALLOWED_METHODS = frozenset({"GET", "HEAD"})

_REDACTED = "[REDACTED]"

_HEADER_REDACT = re.compile(
    r"^(authorization|x-api-key|api[-_]?key|x-auth-token|cookie|set-cookie|"
    r"x-serpapi-key|x-goog-api-key|bearer)$",
    re.IGNORECASE,
)

_QUERY_PARAM_REDACT = re.compile(
    r"(api[_-]?key|apikey|token|access_token|secret|password|key)=([^&\s]+)",
    re.IGNORECASE,
)

_URL_CRED_REDACT = re.compile(
    r"(https?://)([^:@/]+:[^@/]+@)",
    re.IGNORECASE,
)

_BEARER_BODY = re.compile(
    r'("(?:api[_-]?key|token|secret|password|bearer)"\s*:\s*)"([^"]{4,})"',
    re.IGNORECASE,
)


class SafetyViolation(Exception):
    """Raised when a probe attempts a forbidden action."""


def assert_probe_method_allowed(method: str) -> None:
    """Raise SafetyViolation if method is not in the read-only allowlist."""
    if method.upper() not in ALLOWED_METHODS:
        raise SafetyViolation(
            f"Probe attempted forbidden HTTP method '{method}'. "
            "Only GET and HEAD are permitted. "
            "Pass --allow-replay to replay idempotent requests."
        )


def assert_replay_allowed(idempotent: bool | None) -> None:
    """Raise SafetyViolation if replay is disabled or call is non-idempotent."""
    if not settings.probe.allow_replay:
        raise SafetyViolation(
            "Replay of the original request is disabled. Pass --allow-replay to enable it."
        )
    if idempotent is False:
        raise SafetyViolation(
            "Replay refused: the original call was non-idempotent. "
            "Replaying it risks duplicate operations."
        )


def redact_url(url: str) -> str:
    """Strip credentials and sensitive query parameters from a URL."""
    url = _URL_CRED_REDACT.sub(r"\1[REDACTED]@", url)
    url = _QUERY_PARAM_REDACT.sub(lambda m: f"{m.group(1)}={_REDACTED}", url)
    return url


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with sensitive values replaced."""
    return {k: (_REDACTED if _HEADER_REDACT.match(k) else v) for k, v in headers.items()}


def redact_body(body: str | None, max_bytes: int | None = None) -> str | None:
    """Strip secrets from a body sample and truncate if needed."""
    if body is None:
        return None
    body = _BEARER_BODY.sub(r'\1"[REDACTED]"', body)
    if max_bytes and len(body) > max_bytes:
        body = body[:max_bytes] + "…[truncated]"
    return body


def redact_all(
    url: str,
    headers: dict[str, str],
    body: str | None,
    max_body: int | None = None,
) -> tuple[str, dict[str, str], str | None]:
    """Convenience wrapper: redact URL, headers and body in one call."""
    return redact_url(url), redact_headers(headers), redact_body(body, max_body)


class ProbeBudget:
    def __init__(self, max_probes: int | None = None) -> None:
        self._max = max_probes or settings.probe.max_probes
        self._used = 0
        self._host_counts: dict[str, int] = {}

    def consume(self, probe_name: str, host: str | None = None) -> None:
        """Mark one probe as consumed. Raise if over budget."""
        if self._used >= self._max:
            raise SafetyViolation(
                f"Probe budget exhausted ({self._max} probes). Increase with --max-probes."
            )
        if host:
            count = self._host_counts.get(host, 0)
            if count >= settings.probe.per_host_rate_limit:
                raise SafetyViolation(
                    f"Per-host rate limit reached for '{host}' "
                    f"({settings.probe.per_host_rate_limit} requests). "
                    "This prevents hammering a failing service."
                )
            self._host_counts[host] = count + 1
        self._used += 1

    @property
    def remaining(self) -> int:
        return max(0, self._max - self._used)

    @property
    def used(self) -> int:
        return self._used
