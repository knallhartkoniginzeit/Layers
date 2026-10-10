from __future__ import annotations

import re

from layers.probes.base import BaseProbe, make_evidence
from layers.schemas import FailureCase, ProbeResult

_GATEWAY_SERVERS = re.compile(
    r"(nginx|cloudflare|cloudfront|akamai|varnish|haproxy|envoy|"
    r"fastly|squid|traefik|kong|istio)",
    re.IGNORECASE,
)

_HTML_MARKER = re.compile(r"<\s*html|<!DOCTYPE\s+html", re.IGNORECASE)

_FIXED_CUTOFFS_MS = [
    10_000,
    15_000,
    30_000,
    60_000,
    90_000,
    100_000,
    120_000,
    300_000,
]
_TOLERANCE = 0.05


def _near_fixed_cutoff(elapsed_ms: float) -> int | None:
    """Return the fixed cutoff in seconds if elapsed_ms is within tolerance."""
    for cutoff in _FIXED_CUTOFFS_MS:
        low = cutoff * (1 - _TOLERANCE)
        high = cutoff * (1 + _TOLERANCE)
        if low <= elapsed_ms <= high:
            return cutoff // 1000
    return None


class GatewayFingerprintProbe(BaseProbe):
    name = "gateway_fingerprint"

    def _run(self, case: FailureCase) -> ProbeResult:
        evidence = []

        if case.status is not None:
            evidence.append(
                make_evidence(
                    self.name,
                    "gateway",
                    f"HTTP response status {case.status} was received — transport (DNS/TCP) succeeded",
                    contradicts=["dns_failure", "connection_refused", "tcp_unreachable"],
                    strength=0.95,
                    raw={"status": case.status},
                )
            )

        resp_ct = case.response_headers.get("Content-Type", "").lower()
        body = case.response_body_sample or ""
        is_html = "text/html" in resp_ct or bool(_HTML_MARKER.search(body))
        req_accepts_json = "json" in case.request_headers.get("Accept", "").lower()

        if is_html and (req_accepts_json or "json" in resp_ct):
            evidence.append(
                make_evidence(
                    self.name,
                    "gateway",
                    "Response is HTML but client expected JSON — likely a gateway error page",
                    supports=["gateway_error_page", "gateway_timeout"],
                    strength=0.8,
                    raw={"response_ct": resp_ct, "html_detected": True},
                )
            )
        elif is_html and case.status and case.status in (502, 503, 504):
            evidence.append(
                make_evidence(
                    self.name,
                    "gateway",
                    f"HTML body with HTTP {case.status} — gateway error page",
                    supports=["gateway_error_page"],
                    strength=0.85,
                    raw={"status": case.status, "html_detected": True},
                )
            )

        server = case.response_headers.get("Server", "")
        via = case.response_headers.get("Via", "")
        combined = f"{server} {via}"

        gw_match = _GATEWAY_SERVERS.search(combined)
        if gw_match:
            evidence.append(
                make_evidence(
                    self.name,
                    "gateway",
                    f"Server/Via header reveals gateway: {gw_match.group(0)}",
                    supports=["gateway_error_page", "gateway_timeout"],
                    strength=0.4,
                    raw={"server": server, "via": via, "match": gw_match.group(0)},
                )
            )

        if case.elapsed_ms:
            cutoff = _near_fixed_cutoff(case.elapsed_ms)
            if cutoff:
                evidence.append(
                    make_evidence(
                        self.name,
                        "gateway",
                        f"Failure time ({case.elapsed_ms:.0f} ms) clusters near "
                        f"the {cutoff}s fixed-duration cutoff — likely a proxy/LB timeout",
                        supports=["gateway_timeout"],
                        strength=0.7,
                        raw={"elapsed_ms": case.elapsed_ms, "cutoff_s": cutoff},
                    )
                )

        if case.status == 429 and not any(
            k in body.lower() for k in ("quota", "searches", "run out", "insufficient_quota")
        ):
            has_retry_after = "retry-after" in {k.lower() for k in case.response_headers}
            has_edge_hdr = (
                any(k.lower() in ("cf-ray", "via", "x-cache") for k in case.response_headers)
                or bool(gw_match)
                or is_html
            )
            if has_retry_after or has_edge_hdr:
                evidence.append(
                    make_evidence(
                        self.name,
                        "gateway",
                        "HTTP 429 with Retry-After or gateway/edge headers — Gateway limit",
                        supports=["gateway_rate_limit"],
                        contradicts=["provider_rate_limit"],
                        strength=0.9,
                    )
                )
            else:
                evidence.append(
                    make_evidence(
                        self.name,
                        "provider",
                        "HTTP 429 without gateway edge headers — Provider limit",
                        supports=["provider_rate_limit"],
                        contradicts=["gateway_rate_limit"],
                        strength=0.9,
                    )
                )

        if case.status == 500 and not is_html:
            evidence.append(
                make_evidence(
                    self.name,
                    "provider",
                    "HTTP 500 internal server error returned by provider",
                    supports=["provider_error"],
                    contradicts=["gateway_error_page", "gateway_timeout"],
                    strength=0.85,
                    raw={"status": 500},
                )
            )

        provider_req_id = any(
            "request-id" in k.lower() or "x-request-id" in k.lower() for k in case.response_headers
        )

        if case.status in (502, 503, 504) and not provider_req_id:
            evidence.append(
                make_evidence(
                    self.name,
                    "gateway",
                    f"HTTP {case.status} with no provider request-id header",
                    supports=["gateway_error_page"],
                    contradicts=["provider_error"],
                    strength=0.7,
                    raw={"status": case.status, "provider_req_id": False},
                )
            )
        elif provider_req_id:
            evidence.append(
                make_evidence(
                    self.name,
                    "provider",
                    "Provider request-id present — provider received the request",
                    supports=["provider_error"],
                    contradicts=["gateway_error_page"],
                    strength=0.7,
                    raw={"provider_req_id": True},
                )
            )

        if case.status == 502 and case.elapsed_ms and case.elapsed_ms < 500:
            evidence.append(
                make_evidence(
                    self.name,
                    "gateway",
                    f"502 returned in {case.elapsed_ms:.0f} ms — "
                    "gateway could not connect to upstream",
                    supports=["gateway_upstream_down"],
                    strength=0.8,
                    raw={"elapsed_ms": case.elapsed_ms},
                )
            )

        return ProbeResult(
            probe=self.name,
            ok=all(not e.supports for e in evidence),
            evidence=evidence,
        )
