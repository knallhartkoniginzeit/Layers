from __future__ import annotations

from unittest.mock import MagicMock, patch

from layers.probes.dns import DnsProbe
from layers.probes.gateway_fingerprint import GatewayFingerprintProbe
from layers.probes.proxy_env import ProxyEnvProbe
from layers.probes.request_lint import RequestLintProbe
from layers.probes.tcp import TcpProbe
from layers.schemas import FailureCase


def make_case(**kw) -> FailureCase:
    defaults: dict = dict(method="GET", url="https://api.example.com/v1/data", status=200)
    defaults.update(kw)
    return FailureCase(**defaults)


class TestRequestLintProbe:
    def test_post_json_body_missing_content_type_flagged(self):
        case = make_case(
            method="POST",
            status=400,
            request_headers={},
            request_body_sample='{"key": "value"}',
        )
        result = RequestLintProbe().run(case)
        assert any("Content-Type" in ev.finding or "JSON" in ev.finding for ev in result.evidence)

    def test_clean_get_no_bad_evidence(self):
        case = make_case(method="GET", status=200, request_headers={})
        result = RequestLintProbe().run(case)
        assert result.ok is True
        assert result.evidence == []

    def test_4xx_produces_evidence(self):
        for code in (400, 422):
            case = make_case(status=code, request_headers={})
            result = RequestLintProbe().run(case)
            assert len(result.evidence) > 0

    def test_malformed_json_body_flagged(self):
        case = make_case(
            method="POST",
            status=400,
            request_headers={"Content-Type": "application/json"},
            request_body_sample="{bad json!!}",
        )
        result = RequestLintProbe().run(case)
        assert any("malformed_request" in ev.supports for ev in result.evidence)


class TestProxyEnvProbe:
    def test_no_proxy_env_returns_clean(self, monkeypatch):
        for var in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "NO_PROXY",
            "no_proxy",
        ):
            monkeypatch.delenv(var, raising=False)
        case = make_case(url="https://api.example.com/data")
        result = ProxyEnvProbe().run(case)
        assert result.ok is True

    def test_valid_proxy_generates_observation(self, monkeypatch):
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example.com:3128")
        case = make_case(url="https://api.example.com/data")
        result = ProxyEnvProbe().run(case)
        assert len(result.evidence) > 0

    def test_invalid_proxy_url_flagged(self, monkeypatch):
        monkeypatch.setenv("HTTPS_PROXY", "not-a-valid-url")
        case = make_case(url="https://api.example.com/data")
        result = ProxyEnvProbe().run(case)
        assert any(
            "proxy_misconfigured" in (ev.supports or []) or "invalid" in ev.finding.lower()
            for ev in result.evidence
        )


class TestGatewayFingerprintProbe:
    def test_html_body_on_json_api_flagged(self):
        case = make_case(
            status=502,
            response_headers={"Content-Type": "text/html", "Server": "nginx/1.24"},
            response_body_sample="<html><body>502 Bad Gateway</body></html>",
        )
        result = GatewayFingerprintProbe().run(case)
        gateway_evidence = [e for e in result.evidence if "gateway" in str(e.supports)]
        assert len(gateway_evidence) > 0

    def test_json_api_response_not_gateway(self):
        case = make_case(
            status=500,
            response_headers={"Content-Type": "application/json"},
            response_body_sample='{"error": "internal_error"}',
        )
        result = GatewayFingerprintProbe().run(case)
        against_gateway = [e for e in result.evidence if "gateway" in str(e.contradicts)]
        assert len(against_gateway) > 0

    def test_504_with_html_flagged(self):
        case = make_case(
            status=504,
            elapsed_ms=30_000.0,
            response_headers={"Server": "cloudflare"},
            response_body_sample="<html>Gateway Timeout</html>",
        )
        result = GatewayFingerprintProbe().run(case)
        assert len(result.evidence) > 0


class TestDnsProbe:
    def test_successful_resolution_contradicts_dns_failure(self):
        mock_answer = MagicMock()
        ip_record = MagicMock()
        ip_record.__str__ = lambda s: "93.184.216.34"
        mock_answer.__iter__ = MagicMock(return_value=iter([ip_record]))
        with patch("dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.return_value = mock_answer
            case = make_case(url="https://api.example.com/v1/data", status=None)
            result = DnsProbe().run(case)
        assert any("dns_failure" in ev.contradicts for ev in result.evidence)

    def test_nxdomain_supports_dns_failure(self):
        import dns.resolver

        with patch("dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
            case = make_case(
                url="https://nonexistent.invalid/v1/data",
                status=None,
                error_class="ConnectionError",
            )
            result = DnsProbe().run(case)
        assert any("dns_failure" in ev.supports for ev in result.evidence)

    def test_timeout_produces_evidence(self):
        import dns.exception

        with patch("dns.resolver.Resolver") as MockResolver:
            MockResolver.return_value.resolve.side_effect = dns.exception.Timeout()
            case = make_case(url="https://api.example.com/data", status=None)
            result = DnsProbe().run(case)
        assert len(result.evidence) > 0


class TestTcpProbe:
    def test_successful_connect_contradicts_network_failure(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("socket.create_connection", return_value=mock_sock):
            case = make_case(url="https://api.example.com/data", status=None)
            result = TcpProbe().run(case)
        assert any(
            "tcp_failure" in ev.contradicts or "connection_refused" in ev.contradicts
            for ev in result.evidence
        )

    def test_connection_refused_supports_failure(self):
        with patch(
            "socket.create_connection",
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            case = make_case(url="https://api.example.com/data", status=None)
            result = TcpProbe().run(case)
        assert any(
            "connection_refused" in ev.supports or "tcp_failure" in ev.supports
            for ev in result.evidence
        )

    def test_timeout_supports_network_failure(self):
        with patch(
            "socket.create_connection",
            side_effect=TimeoutError("timed out"),
        ):
            case = make_case(url="https://api.example.com/data", status=None)
            result = TcpProbe().run(case)
        assert len(result.evidence) > 0
