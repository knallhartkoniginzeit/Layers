from __future__ import annotations

from dataclasses import dataclass, field

from layers.schemas import ConfidenceBand, Evidence, Hypothesis, Layer


@dataclass
class Rule:
    """Declarative rule: what evidence supports / contradicts a hypothesis."""

    id: str
    layer: Layer
    cause: str
    requires: list[str] = field(default_factory=list)
    contradicted_by: list[str] = field(default_factory=list)
    base_confidence: float = 0.5

    def __hash__(self) -> int:
        return hash(self.id)


class RuleEngine:
    """Score hypotheses against collected evidence."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules: list[Rule] = rules or []

    def add_rules(self, rules: list[Rule]) -> None:
        self._rules.extend(rules)

    def evaluate(self, evidence: list[Evidence]) -> list[Hypothesis]:
        """
        Evaluate all rules against the evidence and return ranked hypotheses.

        Returns hypotheses sorted by confidence (descending).
        """
        evidence_tags: set[str] = set()
        supporting: dict[str, list[Evidence]] = {}
        contradicting: dict[str, list[Evidence]] = {}

        for ev in evidence:
            tag = _evidence_tag(ev)
            evidence_tags.add(tag)
            for hyp_id in ev.supports:
                supporting.setdefault(hyp_id, []).append(ev)
            for hyp_id in ev.contradicts:
                contradicting.setdefault(hyp_id, []).append(ev)

        hypotheses: list[Hypothesis] = []

        for rule in self._rules:
            sup = supporting.get(rule.id, [])
            if not sup:
                continue

            matched_requires = sum(1 for req in rule.requires if _tag_matches(req, evidence_tags))

            con = contradicting.get(rule.id, [])

            confidence = _compute_confidence(
                rule.base_confidence,
                matched_requires=matched_requires,
                total_requires=len(rule.requires),
                supporting=sup,
                contradicting=con,
            )

            band = _confidence_band(confidence)

            hypotheses.append(
                Hypothesis(
                    id=rule.id,
                    layer=rule.layer,
                    cause=rule.cause,
                    confidence=confidence,
                    band=band,
                    evidence=sup,
                )
            )

        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses


def _evidence_tag(ev: Evidence) -> str:
    """
    Create a matchable tag from evidence.

    Format: ``probe_name.finding_fragment``
    e.g. ``gateway_fingerprint.html_body``
    """
    return f"{ev.probe}.{ev.finding[:40].lower().replace(' ', '_')}"


def _tag_matches(required: str, tags: set[str]) -> bool:
    """Check if a required tag is present (prefix match)."""
    return any(tag.startswith(required) or required in tag for tag in tags)


def _compute_confidence(
    base: float,
    *,
    matched_requires: int,
    total_requires: int,
    supporting: list[Evidence],
    contradicting: list[Evidence],
) -> float:
    """
    Transparent confidence formula:
    - Start with base_confidence
    - Add weighted support from matching evidence
    - Subtract weighted contradiction
    - Clamp to [0.0, 1.0]

    Property guarantee: more contradicting evidence NEVER raises confidence.
    """
    conf = base

    if total_requires > 0:
        coverage = matched_requires / total_requires
        conf += 0.2 * coverage

    for ev in supporting:
        conf += ev.strength * 0.15

    for ev in contradicting:
        conf -= ev.strength * 0.2

    return max(0.0, min(1.0, conf))


def _confidence_band(confidence: float) -> ConfidenceBand:
    """Map numeric confidence to a named band."""
    if confidence >= 0.75:
        return ConfidenceBand.HIGH
    if confidence >= 0.45:
        return ConfidenceBand.MED
    if confidence >= 0.35:
        return ConfidenceBand.LOW
    return ConfidenceBand.INCONCLUSIVE
