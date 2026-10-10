from layers.api import diagnose, diagnose_from_dict
from layers.schemas import ActionKind, Diagnosis, FailureCase


def test_diagnose_with_failure_case():
    case = FailureCase(
        method="POST",
        url="https://api.example.com/v1/orders",
        request_headers={"Content-Type": "application/json"},
        request_body_sample='{"item": 123}',
        status=504,
        elapsed_ms=30050,
        response_headers={"Server": "nginx/1.24", "Content-Type": "text/html"},
        response_body_sample="<html>504 Gateway Timeout</html>",
        idempotent=False,
    )
    result = diagnose(case)
    assert isinstance(result, Diagnosis)
    assert result.top is not None
    assert result.top.layer.value == "gateway"
    assert result.action.kind in (ActionKind.CHECK_THEN_RETRY, ActionKind.RETRY_WITH_BACKOFF)
    assert "gateway_fingerprint" in result.probes_run
    assert len(result.limits) > 0


def test_diagnose_from_curl_string():
    curl_input = 'curl -X POST "https://api.example.com/orders" -H "Content-Type: application/json" -d \'{"broken": }\''
    result = diagnose(curl_input, input_type="curl")
    assert isinstance(result, Diagnosis)
    assert result.top is not None
    assert result.top.layer.value == "request"
    assert result.action.kind == ActionKind.FIX_REQUEST


def test_diagnose_from_dict():
    payload = {
        "method": "GET",
        "url": "https://serpapi.com/search?q=coffee",
        "status": 401,
        "response_headers": {"Content-Type": "application/json"},
        "response_body_sample": '{"error": "Invalid API key"}',
    }
    result = diagnose_from_dict(payload, provider="serpapi")
    assert isinstance(result, Diagnosis)
    assert result.case.url == "https://serpapi.com/search?q=coffee"
