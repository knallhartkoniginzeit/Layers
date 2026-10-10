from __future__ import annotations

from typing import Protocol, runtime_checkable

from layers.schemas import Evidence, FailureCase, ProbeResult


@runtime_checkable
class Probe(Protocol):
    """Protocol that every probe must implement."""

    name: str

    def run(self, case: FailureCase) -> ProbeResult:
        """
        Collect evidence from *case* and return a ProbeResult.

        Must not mutate *case*.
        Must not raise – instead return a ProbeResult with ok=False
        and populate the skipped / skip_reason fields as appropriate.
        """
        ...


class BaseProbe:
    """
    Convenience base class for probes.

    Subclasses override :meth:`_run` and get consistent
    error handling / budget tracking for free.
    """

    name: str = "base"

    def run(self, case: FailureCase) -> ProbeResult:
        try:
            return self._run(case)
        except Exception as exc:  # noqa: BLE001
            return ProbeResult(
                probe=self.name,
                ok=False,
                skipped=True,
                skip_reason=f"probe error: {exc}",
            )

    def _run(self, case: FailureCase) -> ProbeResult:  # noqa: ARG002
        raise NotImplementedError


def make_evidence(
    probe: str,
    layer: str,
    finding: str,
    *,
    supports: list[str] | None = None,
    contradicts: list[str] | None = None,
    strength: float = 0.5,
    raw: dict[str, object] | None = None,
) -> Evidence:
    """Convenience factory used inside probe implementations."""
    from layers.schemas import Layer

    return Evidence(
        probe=probe,
        layer=Layer(layer),
        finding=finding,
        supports=supports or [],
        contradicts=contradicts or [],
        strength=strength,
        raw=raw,
    )
