from __future__ import annotations

from layers.schemas import FailureCase


class BaselinePrediction:
    def __init__(
        self, layer: str, cause: str, completion: str, action: str, confidence: float = 0.5
    ):
        self.layer = layer
        self.cause = cause
        self.completion = completion
        self.action = action
        self.confidence = confidence

def classify_baseline(case: FailureCase) -> BaselinePrediction:
    """
    Classify using status codes and simple string contains.

    Common naive assumptions:
    - 4xx -> client/request or credentials
    - 5xx -> provider
    - No status / timeout -> network (blind retry)
    - Always blindly assumes NOT_COMPLETED on 5xx/timeouts (dangerous!)
    """
    status = case.status
    error_class = case.error_class or ""
    (case.response_body_sample or "").lower()

    if status is None:
        if "connect" in error_class.lower() or "dns" in error_class.lower():
            return BaselinePrediction(
                layer="network",
                cause="network_error",
                completion="NOT_COMPLETED",
                action="retry_with_backoff",
                confidence=0.8,
            )
        return BaselinePrediction(
            layer="network",
            cause="network_timeout",
            completion="NOT_COMPLETED",
            action="retry_with_backoff",
            confidence=0.8,
        )

    if status in (400, 415, 422):
        return BaselinePrediction(
            layer="request",
            cause="malformed_request",
            completion="NOT_COMPLETED",
            action="fix_request",
            confidence=0.9,
        )

    if status in (401, 403):
        return BaselinePrediction(
            layer="credentials",
            cause="key_invalid",
            completion="NOT_COMPLETED",
            action="fix_credentials",
            confidence=0.85,
        )

    if status == 429:
        return BaselinePrediction(
            layer="provider",
            cause="rate_limit",
            completion="NOT_COMPLETED",
            action="retry_with_backoff",
            confidence=0.7,
        )

    if status in (502, 504):
        return BaselinePrediction(
            layer="provider",
            cause="server_error",
            completion="NOT_COMPLETED",
            action="retry_with_backoff",
            confidence=0.6,
        )

    if status in (500, 503):
        return BaselinePrediction(
            layer="provider",
            cause="provider_error",
            completion="NOT_COMPLETED",
            action="retry_with_backoff",
            confidence=0.8,
        )

    return BaselinePrediction(
        layer="unknown",
        cause="unknown",
        completion="UNKNOWN",
        action="escalate",
        confidence=0.3,
    )
