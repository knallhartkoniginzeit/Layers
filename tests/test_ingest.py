from layers.ingest.curl import from_curl
from layers.ingest.exception import from_exception
from layers.ingest.har import from_har
from layers.ingest.raw import from_raw


def test_curl_command_parsing():
    cmd = 'curl -X POST "https://api.example.com/items?api_key=secret123" -H "Authorization: Bearer token123" -H "Content-Type: application/json" -d \'{"name": "test"}\''
    case = from_curl(cmd)
    assert case.method == "POST"
    assert "https://api.example.com/items" in case.url
    assert "secret123" not in case.url
    assert case.request_headers["Authorization"] == "[REDACTED]"
    assert case.request_body_sample == '{"name": "test"}'
    assert case.idempotent is False


def test_curl_verbose_output_parsing():
    curl_v = """
> GET /v1/data HTTP/1.1
> Host: api.example.com
> User-Agent: curl/8.4.0
> Accept: */*
> 
< HTTP/1.1 502 Bad Gateway
< Server: nginx/1.24
< Content-Type: text/html
< 
<html>502 Bad Gateway</html>
"""
    case = from_curl(curl_v)
    assert case.method == "GET"
    assert case.url == "http://api.example.com/v1/data"
    assert case.status == 502
    assert case.response_headers["Server"] == "nginx/1.24"


def test_har_entry_parsing():
    har_json = """
    {
      "request": {
        "method": "GET",
        "url": "https://api.example.com/search?q=foo&key=secret_key",
        "headers": [
          {"name": "Authorization", "value": "Bearer sk-998877"}
        ]
      },
      "response": {
        "status": 401,
        "headers": [
          {"name": "Content-Type", "value": "application/json"}
        ],
        "content": {
          "text": "{\\"error\\": \\"Unauthorized\\"}"
        }
      },
      "timings": {"send": 10, "wait": 25, "receive": 5}
    }
    """
    case = from_har(har_json)
    assert case.method == "GET"
    assert "secret_key" not in case.url
    assert case.status == 401
    assert case.request_headers["Authorization"] == "[REDACTED]"
    assert case.elapsed_ms == 40.0


def test_exception_traceback_parsing():
    trace = """
    Traceback (most recent call last):
      File "client.py", line 12, in <module>
        response = requests.get("https://api.example.com/data", timeout=5)
      File "requests/adapters.py", line 519, in send
        raise ReadTimeout(e, request=request)
    requests.exceptions.ReadTimeout: HTTPSConnectionPool(host='api.example.com', port=443): Read timed out. (read timeout=5.0)
    """
    case = from_exception(trace)
    assert case.error_class == "ReadTimeout"
    assert case.url == "https://api.example.com/data"
    assert case.elapsed_ms == 5000.0


def test_raw_http_parsing():
    raw_text = """
HTTP/1.1 504 Gateway Time-out
Server: nginx/1.24.0
Content-Type: text/html

<html><body>504 Gateway Time-out</body></html>
    """
    case = from_raw(raw_text, method="POST", url="https://api.example.com/checkout")
    assert case.method == "POST"
    assert case.status == 504
    assert case.response_headers["Server"] == "nginx/1.24.0"
    assert "504 Gateway Time-out" in (case.response_body_sample or "")
