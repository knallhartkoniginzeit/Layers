from __future__ import annotations

import pathlib
from typing import Any
from urllib.parse import urlparse

import yaml

from layers.engine.hypotheses import Rule
from layers.packs.base import ProviderPack
from layers.packs.openai_compat.probes import OpenAIModelsAuthProbe
from layers.packs.openai_compat.rules import OPENAI_RULES
from layers.probes.base import Probe
from layers.probes.provider_status import ProviderStatusProbe
from layers.schemas import FailureCase


class OpenAICompatPack(ProviderPack):
    name: str = "openai_compat"
    hosts: list[str] = [
        "api.openai.com",
        "api.groq.com",
        "api.together.xyz",
        "openrouter.ai",
    ]

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
        status_url = self._meta.get("status_url", "https://status.openai.com/api/v2/summary.json")
        return ProviderStatusProbe(status_url=status_url)

    def auth_probe(self, case: FailureCase) -> Probe:
        return OpenAIModelsAuthProbe()

    def completion_probe(self, case: FailureCase) -> Probe | None:
        return None

    def rules(self) -> list[Rule]:
        return list(OPENAI_RULES)


pack = OpenAICompatPack()
