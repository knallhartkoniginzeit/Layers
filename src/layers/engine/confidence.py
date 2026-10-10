from __future__ import annotations

from layers.schemas import ConfidenceBand, Evidence


def confidence_band(confidence: float) -> ConfidenceBand:
    """Map numeric confidence to a named band."""
    if confidence >= 0.75:
        return ConfidenceBand.HIGH
    if confidence >= 0.45:
        return ConfidenceBand.MED
    if confidence >= 0.35:
        return ConfidenceBand.LOW
    return ConfidenceBand.INCONCLUSIVE


def aggregate_strength(evidence: list[Evidence]) -> float:
    """Aggregate evidence strengths into a single [0, 1] value."""
    if not evidence:
        return 0.0
    total = sum(e.strength for e in evidence)
    return min(1.0, total / len(evidence))


def missing_evidence_penalty(
    probes_skipped: list[str],
    critical_probes: list[str] | None = None,
) -> float:
    """
    Calculate a confidence penalty for skipped probes.

    Critical skipped probes incur a larger penalty.
    """
    critical = set(critical_probes or [])
    penalty = 0.0
    for name in probes_skipped:
        if name in critical:
            penalty += 0.15
        else:
            penalty += 0.05
    return min(0.5, penalty)
