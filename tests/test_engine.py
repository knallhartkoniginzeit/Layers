from hypothesis import given
from hypothesis import strategies as st

from layers.engine.hypotheses import Rule, RuleEngine, _compute_confidence
from layers.schemas import Evidence, Layer


@given(
    base=st.floats(min_value=0.0, max_value=1.0),
    matched=st.integers(min_value=0, max_value=10),
    total=st.integers(min_value=0, max_value=10),
    sup_count=st.integers(min_value=0, max_value=5),
    con_count=st.integers(min_value=0, max_value=5),
)
def test_confidence_always_between_zero_and_one(base, matched, total, sup_count, con_count):
    if matched > total:
        matched, total = total, matched

    supporting = [
        Evidence(probe="p", layer=Layer.GATEWAY, finding="f", strength=0.8)
        for _ in range(sup_count)
    ]
    contradicting = [
        Evidence(probe="p", layer=Layer.GATEWAY, finding="f", strength=0.8)
        for _ in range(con_count)
    ]

    conf = _compute_confidence(
        base,
        matched_requires=matched,
        total_requires=total,
        supporting=supporting,
        contradicting=contradicting,
    )
    assert 0.0 <= conf <= 1.0


def test_contradiction_never_increases_confidence():
    rule = Rule(
        id="test_rule",
        layer=Layer.GATEWAY,
        cause="test cause",
        requires=["test_probe"],
        base_confidence=0.6,
    )
    engine = RuleEngine(rules=[rule])

    sup_evidence = [
        Evidence(
            probe="test_probe",
            layer=Layer.GATEWAY,
            finding="finding 1",
            supports=["test_rule"],
            strength=0.8,
        )
    ]
    conf_without_contradiction = engine.evaluate(sup_evidence)[0].confidence

    sup_and_con_evidence = [
        Evidence(
            probe="test_probe",
            layer=Layer.GATEWAY,
            finding="finding 1",
            supports=["test_rule"],
            strength=0.8,
        ),
        Evidence(
            probe="test_probe",
            layer=Layer.GATEWAY,
            finding="finding 2",
            contradicts=["test_rule"],
            strength=0.9,
        ),
    ]
    conf_with_contradiction = engine.evaluate(sup_and_con_evidence)[0].confidence

    assert conf_with_contradiction <= conf_without_contradiction
