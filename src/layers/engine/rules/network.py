"""
layers – engine/rules/network.py
Rules for DNS, TCP, TLS and proxy failures.
"""

from layers.engine.hypotheses import Rule
from layers.schemas import Layer

NETWORK_RULES = [
    Rule(
        id="dns_failure",
        layer=Layer.NETWORK,
        cause="DNS resolution failed — hostname does not resolve",
        requires=["dns"],
        contradicted_by=["tcp.connected", "tls.handshake_succeeded"],
        base_confidence=0.7,
    ),
    Rule(
        id="connection_refused",
        layer=Layer.NETWORK,
        cause="TCP connection refused — service is not listening on that port",
        requires=["tcp"],
        contradicted_by=["tls.handshake_succeeded"],
        base_confidence=0.7,
    ),
    Rule(
        id="tcp_unreachable",
        layer=Layer.NETWORK,
        cause="TCP connection timed out — host is unreachable or port is filtered",
        requires=["tcp"],
        contradicted_by=["tls.handshake_succeeded"],
        base_confidence=0.6,
    ),
    Rule(
        id="tls_expired",
        layer=Layer.NETWORK,
        cause="TLS certificate has expired",
        requires=["tls"],
        contradicted_by=[],
        base_confidence=0.7,
    ),
    Rule(
        id="tls_hostname_mismatch",
        layer=Layer.NETWORK,
        cause="TLS hostname mismatch — certificate does not cover this domain",
        requires=["tls"],
        contradicted_by=[],
        base_confidence=0.7,
    ),
    Rule(
        id="tls_broken_chain",
        layer=Layer.NETWORK,
        cause="TLS chain verification failed — missing intermediate or self-signed cert",
        requires=["tls"],
        contradicted_by=[],
        base_confidence=0.6,
    ),
    Rule(
        id="bad_proxy_env",
        layer=Layer.NETWORK,
        cause="Proxy environment variables are misconfigured",
        requires=["proxy_env"],
        contradicted_by=[],
        base_confidence=0.5,
    ),
]
