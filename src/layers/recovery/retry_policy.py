from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RetryVerdict(StrEnum):
    SAFE_RETRY = "safe_retry"
    CHECK_THEN_RETRY = "check_then_retry"
    DO_NOT_RETRY = "do_not_retry"
    WAIT = "wait"


@dataclass
class RetryPolicy:
    """Encapsulates a retry recommendation with rationale."""

    verdict: RetryVerdict
    reason: str
    backoff_base: float = 1.0
    backoff_max: float = 60.0
    max_attempts: int = 3
    honour_retry_after: bool = True
    retry_after_value: float | None = None


def decide_retry(
    *,
    idempotent: bool | None,
    has_idempotency_key: bool,
    transient: bool,
    completion_known: bool,
    completed: bool,
    retry_after: float | None = None,
) -> RetryPolicy:
    """
    Pure function: given facts about the call, return the safest retry policy.

    Situation table (from spec):
    - Idempotent + transient             → retry_with_backoff (honour Retry-After)
    - Non-idempotent, timeout, no key    → check_then_retry (NEVER blind retry)
    - Non-idempotent, timeout, has key   → safe retry with same key
    - Bad request / permission error     → do_not_retry (fix request)
    - Provider incident open             → wait
    """
    if not transient:
        return RetryPolicy(
            verdict=RetryVerdict.DO_NOT_RETRY,
            reason="Error is not transient — fix the request or credentials first.",
        )

    if completion_known and completed:
        return RetryPolicy(
            verdict=RetryVerdict.DO_NOT_RETRY,
            reason="Operation already completed. Retrying would create a duplicate.",
        )

    if idempotent:
        return RetryPolicy(
            verdict=RetryVerdict.SAFE_RETRY,
            reason="Idempotent request with transient error — safe to retry.",
            retry_after_value=retry_after,
        )

    if has_idempotency_key:
        return RetryPolicy(
            verdict=RetryVerdict.SAFE_RETRY,
            reason="Idempotency key present — safe to retry with the same key.",
            retry_after_value=retry_after,
        )

    if completion_known and not completed:
        return RetryPolicy(
            verdict=RetryVerdict.SAFE_RETRY,
            reason="Operation confirmed not completed — safe to retry.",
            retry_after_value=retry_after,
        )

    return RetryPolicy(
        verdict=RetryVerdict.CHECK_THEN_RETRY,
        reason=(
            "Non-idempotent request with unknown completion status. "
            "Verify the operation did not complete before retrying."
        ),
        retry_after_value=retry_after,
    )
