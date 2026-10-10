"""layers engine rules package — one file per layer."""

from layers.engine.rules.auth import AUTH_RULES
from layers.engine.rules.gateway import GATEWAY_RULES
from layers.engine.rules.network import NETWORK_RULES
from layers.engine.rules.provider import PROVIDER_RULES
from layers.engine.rules.rate_limit import RATE_LIMIT_RULES
from layers.engine.rules.timeout import TIMEOUT_RULES

ALL_RULES = (
    NETWORK_RULES + GATEWAY_RULES + AUTH_RULES + RATE_LIMIT_RULES + PROVIDER_RULES + TIMEOUT_RULES
)

__all__ = [
    "ALL_RULES",
    "NETWORK_RULES",
    "GATEWAY_RULES",
    "AUTH_RULES",
    "RATE_LIMIT_RULES",
    "PROVIDER_RULES",
    "TIMEOUT_RULES",
]
