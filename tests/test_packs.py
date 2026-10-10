from layers.packs.base import ProviderPack
from layers.packs.openai_compat import pack as openai_pack
from layers.packs.serpapi import pack as serpapi_pack
from layers.schemas import FailureCase


def assert_pack_contract(pack: ProviderPack):
    assert isinstance(pack.name, str) and pack.name
    assert isinstance(pack.hosts, list) and len(pack.hosts) > 0

    err_map = pack.error_map()
    assert isinstance(err_map, dict) and len(err_map) > 0

    rules = pack.rules()
    assert isinstance(rules, list) and len(rules) > 0

    dummy_case = FailureCase(method="GET", url="https://example.com/test")
    status_p = pack.status_probe()
    assert status_p is not None and hasattr(status_p, "run")

    auth_p = pack.auth_probe(dummy_case)
    assert auth_p is not None and hasattr(auth_p, "run")


def test_serpapi_pack_contract():
    assert_pack_contract(serpapi_pack)
    assert serpapi_pack.matches("https://serpapi.com/search.json")
    assert serpapi_pack.matches("https://www.serpapi.com/search.json")
    assert not serpapi_pack.matches("https://api.openai.com/v1/chat")


def test_openai_compat_pack_contract():
    assert_pack_contract(openai_pack)
    assert openai_pack.matches("https://api.openai.com/v1/chat/completions")
    assert openai_pack.matches("https://openrouter.ai/api/v1/chat/completions")
    assert not openai_pack.matches("https://serpapi.com/search.json")
