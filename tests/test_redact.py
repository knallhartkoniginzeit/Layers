from layers.safety import redact_all, redact_body, redact_headers, redact_url


def test_redact_url_query_keys():
    url = "https://serpapi.com/search?q=test&api_key=secret_123456789&engine=google"
    redacted = redact_url(url)
    assert "secret_123456789" not in redacted
    assert "api_key=[REDACTED]" in redacted
    assert "q=test" in redacted


def test_redact_url_credentials():
    url = "https://alice:my_super_password@api.example.com/data"
    redacted = redact_url(url)
    assert "my_super_password" not in redacted
    assert "alice" not in redacted
    assert "[REDACTED]@" in redacted


def test_redact_headers():
    headers = {
        "Authorization": "Bearer sk-1234567890abcdef",
        "X-Api-Key": "secret_key_val",
        "Cookie": "session_id=abc123xyz",
        "Content-Type": "application/json",
        "Accept": "*/*",
    }
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["X-Api-Key"] == "[REDACTED]"
    assert redacted["Cookie"] == "[REDACTED]"
    assert redacted["Content-Type"] == "application/json"
    assert redacted["Accept"] == "*/*"


def test_redact_body_json_tokens():
    body = '{"api_key": "secret_token_12345", "user": "alice", "action": "search"}'
    redacted = redact_body(body)
    assert "secret_token_12345" not in redacted
    assert '"[REDACTED]"' in redacted


def test_redaction_is_idempotent():
    url = "https://user:pass@api.com/v1?token=secret123"
    headers = {"Authorization": "Bearer topsecret", "Accept": "application/json"}
    body = '{"token": "my_secret_token"}'

    u1, h1, b1 = redact_all(url, headers, body)
    u2, h2, b2 = redact_all(u1, h1, b1)

    assert u1 == u2
    assert h1 == h2
    assert b1 == b2
