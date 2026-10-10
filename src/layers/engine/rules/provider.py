"""
layers – engine/rules/provider.py
Rules for provider-side errors.
"""

from layers.engine.hypotheses import Rule
from layers.schemas import Layer

PROVIDER_RULES = [
    Rule(
        id="provider_error",
        layer=Layer.PROVIDER,
        cause="Provider returned an error (5xx) — server-side issue",
        requires=["gateway_fingerprint"],
        contradicted_by=["gateway_error_page", "gateway_timeout"],
        base_confidence=0.5,
    ),
    Rule(
        id="provider_incident",
        layer=Layer.PROVIDER,
        cause="Provider status page shows an active incident",
        requires=["provider_status"],
        contradicted_by=[],
        base_confidence=0.6,
    ),
    Rule(
        id="operation_completed",
        layer=Layer.PROVIDER,
        cause="The operation actually completed despite the client seeing an error",
        requires=["completion"],
        contradicted_by=[],
        base_confidence=0.4,
    ),
]
