"""
layers – engine/rules/timeout.py
Rules for various timeout scenarios.
"""

from layers.engine.hypotheses import Rule
from layers.schemas import Layer

TIMEOUT_RULES = [
    Rule(
        id="network_timeout",
        layer=Layer.NETWORK,
        cause="Network-level timeout — no HTTP response was received",
        requires=["tcp", "dns"],
        contradicted_by=["gateway_fingerprint.provider_request_id"],
        base_confidence=0.5,
    ),
    Rule(
        id="read_timeout",
        layer=Layer.GATEWAY,
        cause="Read timeout — connection established but response took too long",
        requires=["gateway_fingerprint"],
        contradicted_by=["dns_failure", "connection_refused"],
        base_confidence=0.5,
    ),
]
