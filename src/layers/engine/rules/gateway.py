"""
layers – engine/rules/gateway.py
Rules for gateway / CDN / load-balancer errors.
"""

from layers.engine.hypotheses import Rule
from layers.schemas import Layer

GATEWAY_RULES = [
    Rule(
        id="gateway_error_page",
        layer=Layer.GATEWAY,
        cause="Error came from a gateway/CDN, not the API provider (HTML error page or edge headers)",
        requires=["gateway_fingerprint"],
        contradicted_by=["provider_request_id_present"],
        base_confidence=0.6,
    ),
    Rule(
        id="gateway_timeout",
        layer=Layer.GATEWAY,
        cause="Gateway/proxy timeout — request reached the gateway but upstream did not respond in time",
        requires=["gateway_fingerprint"],
        contradicted_by=["provider_request_id_present"],
        base_confidence=0.6,
    ),
    Rule(
        id="gateway_upstream_down",
        layer=Layer.GATEWAY,
        cause="Gateway could not connect to upstream — 502 returned within milliseconds",
        requires=["gateway_fingerprint"],
        contradicted_by=["provider_request_id_present"],
        base_confidence=0.6,
    ),
]
