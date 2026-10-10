import httpx

from layers import diagnose
from layers.schemas import ActionKind, FailureCase


def resilient_api_call(url: str, payload: dict) -> dict:
    client = httpx.Client(timeout=10.0)

    try:
        response = client.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        headers = dict(getattr(getattr(exc, "response", None), "headers", {}))
        body = getattr(getattr(exc, "response", None), "text", None)

        case = FailureCase(
            method="POST",
            url=url,
            status=status,
            response_headers=headers,
            response_body_sample=body,
            error_class=type(exc).__name__,
            idempotent=False,
            has_idempotency_key=False,
        )

        diagnosis = diagnose(case)

        print(f"Call failed: {diagnosis.top.cause if diagnosis.top else 'Unknown'}")
        print(f"Diagnosed layer: {diagnosis.top.layer.value if diagnosis.top else 'Unknown'}")
        print(
            f"Recommended recovery action: {diagnosis.action.kind.value} (Safe: {diagnosis.action.safe})"
        )

        if diagnosis.action.kind == ActionKind.RETRY_WITH_BACKOFF:
            print("Action is safe to retry. Retrying with backoff...")
        elif diagnosis.action.kind == ActionKind.CHECK_THEN_RETRY:
            print(
                "CRITICAL: Non-idempotent write timed out. Checking target state first to prevent duplicate order!"
            )
        else:
            print("Action is not retryable. Escalating or fixing request/credentials.")
            raise


if __name__ == "__main__":
    try:
        resilient_api_call("https://api.example.com/orders", {"item": "widget", "qty": 1})
    except Exception as e:
        print(f"Execution finished with handled error: {e}")
