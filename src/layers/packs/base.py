from __future__ import annotations

from typing import Protocol, runtime_checkable

from layers.engine.hypotheses import Rule
from layers.probes.base import Probe
from layers.schemas import FailureCase


@runtime_checkable
class ProviderPack(Protocol):
    """Protocol for provider-specific plugins."""

    name: str
    hosts: list[str]

    def error_map(self) -> dict[int | str, str]:
        """Map status / body patterns → documented meaning."""
        ...

    def status_probe(self) -> Probe:
        """Return a probe that checks the provider status page."""
        ...

    def auth_probe(self, case: FailureCase) -> Probe:
        """Return a safe, read-only probe that tests key validity."""
        ...

    def completion_probe(self, case: FailureCase) -> Probe | None:
        """Return a probe to check whether the operation completed, or None."""
        ...

    def rules(self) -> list[Rule]:
        """Return provider-specific rules."""
        ...

    def matches(self, url: str) -> bool:
        """Return True if this pack claims the given URL."""
        ...
