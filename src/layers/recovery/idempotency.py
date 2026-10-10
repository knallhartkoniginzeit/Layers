from __future__ import annotations

import uuid


def suggest_idempotency_key() -> str:
    """Generate a new UUID-based idempotency key."""
    return str(uuid.uuid4())


def detect_idempotency_key(headers: dict[str, str]) -> str | None:
    """Return the idempotency key from headers, if present."""
    for k, v in headers.items():
        if k.lower() in ("idempotency-key", "idempotency_key", "x-idempotency-key"):
            return v
    return None


def recommend_idempotency_header(method: str) -> str | None:
    """
    Recommend adding an idempotency key header for non-idempotent methods.

    Returns None if the method is already idempotent.
    """
    if method.upper() in ("GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"):
        return None
    return "Idempotency-Key"
