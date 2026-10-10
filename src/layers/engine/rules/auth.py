"""
layers – engine/rules/auth.py
Rules for authentication and authorization failures.
"""

from layers.engine.hypotheses import Rule
from layers.schemas import Layer

AUTH_RULES = [
    Rule(
        id="key_invalid",
        layer=Layer.CREDENTIALS,
        cause="API key is invalid or has been revoked",
        requires=["credentials"],
        contradicted_by=["credentials.read_only_get_succeeded"],
        base_confidence=0.6,
    ),
    Rule(
        id="key_expired",
        layer=Layer.CREDENTIALS,
        cause="API key has expired",
        requires=["credentials"],
        contradicted_by=["credentials.read_only_get_succeeded"],
        base_confidence=0.6,
    ),
    Rule(
        id="missing_permission",
        layer=Layer.CREDENTIALS,
        cause="Key is valid but lacks permission for this operation (read OK, write denied)",
        requires=["credentials"],
        contradicted_by=["key_invalid", "key_expired"],
        base_confidence=0.5,
    ),
    Rule(
        id="quota_exhausted",
        layer=Layer.CREDENTIALS,
        cause="API quota or plan limit has been exceeded",
        requires=["credentials"],
        contradicted_by=[],
        base_confidence=0.5,
    ),
    Rule(
        id="malformed_request",
        layer=Layer.REQUEST,
        cause="Request itself is malformed (bad JSON, wrong Content-Type, missing fields)",
        requires=["request_lint"],
        contradicted_by=[],
        base_confidence=0.5,
    ),
]
