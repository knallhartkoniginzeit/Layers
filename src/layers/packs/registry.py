from __future__ import annotations

from layers.packs.base import ProviderPack
from layers.packs.openai_compat import pack as openai_pack
from layers.packs.serpapi import pack as serpapi_pack

_PACKS: dict[str, ProviderPack] = {
    "serpapi": serpapi_pack,
    "openai_compat": openai_pack,
}


def list_packs() -> list[str]:
    """Return names of all available packs."""
    return sorted(_PACKS.keys())


def get_pack(name: str) -> ProviderPack | None:
    """Retrieve pack by name."""
    return _PACKS.get(name.lower())


def find_pack_for_url(url: str) -> ProviderPack | None:
    """Find the first pack matching the target URL."""
    for p in _PACKS.values():
        if p.matches(url):
            return p
    return None
