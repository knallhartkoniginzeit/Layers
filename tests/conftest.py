from __future__ import annotations

import pytest

from layers.schemas import FailureCase


def make_case(**kwargs) -> FailureCase:
    """Return a FailureCase with sensible defaults, overridable via kwargs."""
    defaults: dict = {
        "method": "GET",
        "url": "https://api.example.com/v1/search",
        "status": 200,
        "request_headers": {},
        "response_headers": {},
        "elapsed_ms": 120.0,
    }
    defaults.update(kwargs)
    return FailureCase(**defaults)


@pytest.fixture
def ok_case() -> FailureCase:
    """A trivially successful request (status 200)."""
    return make_case(status=200)


@pytest.fixture
def auth_401_case() -> FailureCase:
    """A 401 Unauthorized response."""
    return make_case(
        status=401,
        response_headers={"Content-Type": "application/json"},
        response_body_sample='{"error": "Unauthorized"}',
    )


@pytest.fixture
def auth_403_case() -> FailureCase:
    """A 403 Forbidden response."""
    return make_case(
        status=403,
        response_headers={"Content-Type": "application/json"},
        response_body_sample='{"error": "Forbidden"}',
    )


@pytest.fixture
def rate_limit_429_case() -> FailureCase:
    """A 429 Too Many Requests with Retry-After."""
    return make_case(
        status=429,
        response_headers={
            "Content-Type": "application/json",
            "Retry-After": "60",
            "X-RateLimit-Limit": "1000",
            "X-RateLimit-Remaining": "0",
        },
        response_body_sample='{"error": "rate_limit_exceeded"}',
    )


@pytest.fixture
def gateway_502_case() -> FailureCase:
    """An HTML 502 Bad Gateway (nginx)."""
    return make_case(
        status=502,
        response_headers={
            "Content-Type": "text/html",
            "Server": "nginx/1.24.0",
            "Via": "1.1 varnish",
        },
        response_body_sample="<html><body><h1>502 Bad Gateway</h1></body></html>",
    )


@pytest.fixture
def timeout_case() -> FailureCase:
    """A POST that timed out with no response."""
    return make_case(
        method="POST",
        url="https://api.example.com/v1/orders",
        status=None,
        elapsed_ms=30_000.0,
        error_class="ReadTimeout",
        idempotent=False,
    )


@pytest.fixture
def dns_failure_case() -> FailureCase:
    """A failure with no status — DNS resolution failed."""
    return make_case(
        url="https://nonexistent-api.example.invalid/v1/data",
        status=None,
        error_class="ConnectionError",
        elapsed_ms=5_000.0,
    )


@pytest.fixture
def tls_error_case() -> FailureCase:
    """A TLS/SSL error case."""
    return make_case(
        url="https://expired.badssl.com/v1/data",
        status=None,
        error_class="SSLError",
        elapsed_ms=200.0,
    )


@pytest.fixture
def provider_500_case() -> FailureCase:
    """A genuine provider 500 (no gateway signals)."""
    return make_case(
        status=500,
        response_headers={"Content-Type": "application/json"},
        response_body_sample='{"error": {"message": "Internal server error", "type": "api_error"}}',
    )


@pytest.fixture
def serpapi_401_case() -> FailureCase:
    """SerpApi-style 401 with invalid API key."""
    return make_case(
        url="https://serpapi.com/search.json?engine=google&q=test&api_key=[REDACTED]",
        status=401,
        response_headers={"Content-Type": "application/json"},
        response_body_sample='{"error": "Invalid API key. Your API key should be here: https://serpapi.com/manage-api-key"}',
    )
