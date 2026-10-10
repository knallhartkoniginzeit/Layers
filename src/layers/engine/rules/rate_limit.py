"""
layers – engine/rules/rate_limit.py
Rules distinguishing gateway 429 from provider 429.
"""

from layers.engine.hypotheses import Rule
from layers.schemas import Layer

RATE_LIMIT_RULES = [
    Rule(
        id="gateway_rate_limit",
        layer=Layer.GATEWAY,
        cause="Rate limited by a gateway/CDN (429 with Retry-After or gateway rate-limit headers)",
        requires=["gateway_fingerprint"],
        contradicted_by=["provider_request_id_present"],
        base_confidence=0.5,
    ),
    Rule(
        id="provider_rate_limit",
        layer=Layer.PROVIDER,
        cause="Rate limited by the API provider (429 without gateway headers, provider error JSON present)",
        requires=["gateway_fingerprint"],
        contradicted_by=["gateway_rate_limit"],
        base_confidence=0.5,
    ),
]
