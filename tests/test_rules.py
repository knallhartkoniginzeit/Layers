from layers.engine.hypotheses import RuleEngine
from layers.engine.rules.auth import AUTH_RULES
from layers.engine.rules.gateway import GATEWAY_RULES
from layers.engine.rules.network import NETWORK_RULES
from layers.engine.rules.rate_limit import RATE_LIMIT_RULES
from layers.schemas import Evidence, Layer


def test_gateway_timeout_positive():
    engine = RuleEngine(rules=list(GATEWAY_RULES))
    evidence = [
        Evidence(
            probe="gateway_fingerprint",
            layer=Layer.GATEWAY,
            finding="Response is HTML error page",
            supports=["gateway_timeout"],
            strength=0.8,
        ),
        Evidence(
            probe="gateway_fingerprint",
            layer=Layer.GATEWAY,
            finding="Failure time near 30s cutoff",
            supports=["gateway_timeout"],
            strength=0.7,
        ),
    ]
    hypotheses = engine.evaluate(evidence)
    assert any(h.id == "gateway_timeout" for h in hypotheses)
    top = hypotheses[0]
    assert top.id == "gateway_timeout"
    assert top.confidence >= 0.7


def test_gateway_timeout_contradicted_by_provider_request_id():
    engine = RuleEngine(rules=list(GATEWAY_RULES))
    evidence = [
        Evidence(
            probe="gateway_fingerprint",
            layer=Layer.GATEWAY,
            finding="Response is HTML error page",
            supports=["gateway_timeout"],
            strength=0.8,
        ),
        Evidence(
            probe="gateway_fingerprint",
            layer=Layer.PROVIDER,
            finding="Provider request-id present",
            contradicts=["gateway_timeout"],
            strength=0.9,
        ),
    ]
    hypotheses = engine.evaluate(evidence)
    gw = next((h for h in hypotheses if h.id == "gateway_timeout"), None)
    assert gw is not None
    assert gw.confidence < 0.8


def test_dns_failure_positive():
    engine = RuleEngine(rules=list(NETWORK_RULES))
    evidence = [
        Evidence(
            probe="dns",
            layer=Layer.NETWORK,
            finding="DNS: host does not exist (NXDOMAIN)",
            supports=["dns_failure"],
            strength=1.0,
        )
    ]
    hypotheses = engine.evaluate(evidence)
    assert any(h.id == "dns_failure" for h in hypotheses)
    assert hypotheses[0].id == "dns_failure"


def test_auth_read_vs_write_scope():
    engine = RuleEngine(rules=list(AUTH_RULES))
    evidence = [
        Evidence(
            probe="credentials",
            layer=Layer.CREDENTIALS,
            finding="Read-only GET succeeded but original returned 403",
            supports=["missing_permission"],
            contradicts=["key_invalid", "key_expired"],
            strength=0.85,
        )
    ]
    hypotheses = engine.evaluate(evidence)
    top = hypotheses[0]
    assert top.id == "missing_permission"


def test_rate_limit_gateway_vs_provider():
    engine = RuleEngine(rules=list(RATE_LIMIT_RULES))
    evidence = [
        Evidence(
            probe="gateway_fingerprint",
            layer=Layer.GATEWAY,
            finding="Rate limited with Retry-After and Cloudflare Server",
            supports=["gateway_rate_limit"],
            contradicts=["provider_rate_limit"],
            strength=0.9,
        )
    ]
    hypotheses = engine.evaluate(evidence)
    assert hypotheses[0].id == "gateway_rate_limit"
