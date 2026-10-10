from __future__ import annotations

from layers.schemas import (
    ActionKind,
    CompletionVerdict,
    FailureCase,
    Hypothesis,
    Layer,
    RecoveryAction,
)


def action_for_hypothesis(
    hypothesis: Hypothesis | None,
    case: FailureCase,
    completion: CompletionVerdict,
) -> RecoveryAction:
    """
    Determine the safest recovery action for the top hypothesis.

    Never recommends blind retry on a non-idempotent write.
    """
    if hypothesis is None:
        return RecoveryAction(
            kind=ActionKind.ESCALATE,
            safe=True,
            explanation="Could not determine the failure cause. Manual investigation needed.",
            commands=["Check application logs", "Review recent infrastructure changes"],
        )

    layer = hypothesis.layer
    hyp_id = hypothesis.id

    if hyp_id == "provider_incident":
        return RecoveryAction(
            kind=ActionKind.WAIT,
            safe=True,
            explanation=(
                "The provider's status page shows an active incident. "
                "Wait for resolution and monitor the status page."
            ),
            commands=["Check the provider status page for updates"],
        )

    if layer == Layer.REQUEST:
        return RecoveryAction(
            kind=ActionKind.FIX_REQUEST,
            safe=True,
            explanation=f"The request is malformed: {hypothesis.cause}. Fix and resend.",
        )

    if layer == Layer.CREDENTIALS:
        return RecoveryAction(
            kind=ActionKind.FIX_CREDENTIALS,
            safe=True,
            explanation=f"Credential issue: {hypothesis.cause}. Fix credentials before retrying.",
            commands=["Verify API key is active and has required permissions"],
        )

    if layer == Layer.NETWORK:
        if case.idempotent or case.idempotent is None:
            return RecoveryAction(
                kind=ActionKind.RETRY_WITH_BACKOFF,
                safe=True,
                explanation=f"Network issue: {hypothesis.cause}. Safe to retry with backoff.",
            )
        return RecoveryAction(
            kind=ActionKind.CHECK_THEN_RETRY,
            safe=True,
            explanation=(
                f"Network issue: {hypothesis.cause}. "
                "Non-idempotent call — check whether it completed before retrying."
            ),
        )

    if layer == Layer.GATEWAY:
        return _gateway_recovery(hypothesis, case, completion)

    if layer == Layer.PROVIDER:
        if hyp_id == "provider_rate_limit":
            return RecoveryAction(
                kind=ActionKind.RETRY_WITH_BACKOFF,
                safe=True,
                explanation=(
                    "Provider rate limit hit. Retry with exponential backoff, "
                    "honoring any Retry-After header."
                ),
                commands=["Check Retry-After header value"],
            )
        if case.idempotent or case.has_idempotency_key:
            return RecoveryAction(
                kind=ActionKind.RETRY_WITH_BACKOFF,
                safe=True,
                explanation=f"Provider error: {hypothesis.cause}. Safe to retry (idempotent).",
            )
        return RecoveryAction(
            kind=ActionKind.CHECK_THEN_RETRY,
            safe=True,
            explanation=(
                f"Provider error: {hypothesis.cause}. "
                "Non-idempotent call — verify completion before retrying."
            ),
        )

    return RecoveryAction(
        kind=ActionKind.ESCALATE,
        safe=True,
        explanation=f"Uncertain diagnosis: {hypothesis.cause}. Manual investigation recommended.",
    )


def _gateway_recovery(
    hypothesis: Hypothesis,
    case: FailureCase,
    completion: CompletionVerdict,
) -> RecoveryAction:
    """Recovery logic for gateway-layer failures."""
    if case.idempotent:
        return RecoveryAction(
            kind=ActionKind.RETRY_WITH_BACKOFF,
            safe=True,
            explanation=f"Gateway error: {hypothesis.cause}. Safe to retry (idempotent GET/PUT).",
        )

    if case.has_idempotency_key:
        return RecoveryAction(
            kind=ActionKind.RETRY_WITH_BACKOFF,
            safe=True,
            explanation=(
                f"Gateway error: {hypothesis.cause}. Safe to retry with the same idempotency key."
            ),
        )

    if completion == CompletionVerdict.COMPLETED:
        return RecoveryAction(
            kind=ActionKind.DO_NOT_RETRY,
            safe=True,
            explanation=(
                f"Gateway error: {hypothesis.cause}. "
                "However, the operation appears to have completed successfully. "
                "Do NOT retry — it would create a duplicate."
            ),
        )

    if completion == CompletionVerdict.NOT_COMPLETED:
        return RecoveryAction(
            kind=ActionKind.RETRY_WITH_BACKOFF,
            safe=True,
            explanation=(
                f"Gateway error: {hypothesis.cause}. The operation did not complete. Safe to retry."
            ),
        )

    return RecoveryAction(
        kind=ActionKind.CHECK_THEN_RETRY,
        safe=True,
        explanation=(
            f"Gateway error: {hypothesis.cause}. "
            "Non-idempotent call with unknown completion status. "
            "Check whether the operation completed before retrying."
        ),
        commands=["Query the API for the expected resource to check if it was created"],
    )
