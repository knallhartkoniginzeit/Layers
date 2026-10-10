"""
layers – packs/openai_compat/rules.py
OpenAI-compatible specific rules, including the gateway vs provider 429 distinction.
"""

from layers.engine.hypotheses import Rule
from layers.schemas import Layer

OPENAI_RULES = [
    Rule(
        id="openai_provider_429",
        layer=Layer.PROVIDER,
        cause="OpenAI provider rate limit / quota exceeded (returned JSON with type: requests/tokens/insufficient_quota)",
        requires=["openai_error.provider_rate_limit"],
        contradicted_by=["gateway_fingerprint.html_body"],
        base_confidence=0.85,
    ),
    Rule(
        id="openai_gateway_429",
        layer=Layer.GATEWAY,
        cause="Cloudflare / edge gateway rate limit before reaching OpenAI servers",
        requires=["openai_error.gateway_rate_limit"],
        contradicted_by=["openai_error.provider_rate_limit"],
        base_confidence=0.8,
    ),
    Rule(
        id="openai_model_overloaded",
        layer=Layer.PROVIDER,
        cause="OpenAI engine overloaded or temporarily unavailable for requested model",
        requires=["openai_error.model_overloaded"],
        contradicted_by=[],
        base_confidence=0.75,
    ),
    Rule(
        id="openai_context_length_exceeded",
        layer=Layer.REQUEST,
        cause="Request token count exceeded the model maximum context window length",
        requires=["openai_error.context_length"],
        contradicted_by=[],
        base_confidence=0.9,
    ),
]
