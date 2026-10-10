from __future__ import annotations

import pathlib
from typing import Any
from urllib.parse import urlparse

import yaml

from layers.engine.hypotheses import Rule
from layers.packs.base import ProviderPack
from layers.packs.serpapi.probes import SerpApiAccountProbe, SerpApiArchiveProbe
from layers.packs.serpapi.rules import SERPAPI_RULES
from layers.probes.base import Probe
from layers.probes.provider_status import ProviderStatusProbe
from layers.schemas import FailureCase


class SerpApiPack(ProviderPack):
    name: str = "serpapi"
    hosts: list[str] = ["serpapi.com", "www.serpapi.com"]

    def __init__(self) -> None:
        self._yaml_path = pathlib.Path(__file__).parent / "pack.yaml"
        self._meta: dict[str, Any] = {}
        if self._yaml_path.exists():
            with open(self._yaml_path, encoding="utf-8") as f:
                self._meta = yaml.safe_load(f) or {}

    def matches(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        return any(
            host.lower() == h.lower() or host.lower().endswith(f".{h.lower()}") for h in self.hosts
        )

    def error_map(self) -> dict[int | str, str]:
        codes = self._meta.get("error_codes", {})
        return {int(k) if str(k).isdigit() else k: v for k, v in codes.items()}

    def status_probe(self) -> Probe:
        status_url = self._meta.get("status_url", "https://serpapi.com/status")
        return ProviderStatusProbe(status_url=status_url)

    def auth_probe(self, case: FailureCase) -> Probe:
        return SerpApiAccountProbe()

    def completion_probe(self, case: FailureCase) -> Probe | None:
        return SerpApiArchiveProbe()

    def rules(self) -> list[Rule]:
        return list(SERPAPI_RULES)


pack = SerpApiPack()
