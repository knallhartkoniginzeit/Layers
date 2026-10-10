# Writing a Provider Pack
Provider packs extend `layers` with domain-specific knowledge about a particular API provider and this is specifically made for SerpApi. This can also be used for other api providers
# 1. Directory Structure
A provider pack lives in `src/layers/packs/<provider_name>/`:
src/layers/packs/myprovider/
├── __init__.py      # Exports pack instance implementing ProviderPack protocol
├── pack.yaml        # Hostnames, status URLs, and error mapping dictionary
├── probes.py        # Safe read-only auth and completion probes
└── rules.py         # Provider-specific hypothesis rules

# 2. The ProviderPack Protocol
Every pack must implement the `ProviderPack` protocol defined in `layers.packs.base`:
from typing import Protocol
from layers.engine.hypotheses import Rule
from layers.probes.base import Probe
from layers.schemas import FailureCase
class ProviderPack(Protocol):
    name: str
    hosts: list[str]
    def matches(self, url: str) -> bool: ...
    def error_map(self) -> dict[int | str, str]: ...
    def status_probe(self) -> Probe: ...
    def auth_probe(self, case: FailureCase) -> Probe: ...
    def completion_probe(self, case: FailureCase) -> Probe | None: ...
    def rules(self) -> list[Rule]: ...

# 3. Implementing Probes
# Status Probe
Checks the provider's status page (e.g. Atlassian Statuspage format). Must be read-only and unauthenticated.
# Auth Probe
Performs a lightweight, read-only GET request to test key validity.
- Example: `GET /v1/account` or `GET /v1/models`
-  Must check permissions without mutating resources or consuming user search/computation quotas where possible.
- Must verify that `assert_probe_method_allowed("GET")` is respected.
# Completion Probe
Determines if an operation succeeded despite the client receiving an error:
- Must inspect response headers or body for resource IDs.
- If a resource ID is not present (such as after an early timeout) and the provider requires one to check status, return UNKNOWN honestly. Never guess `NOT_COMPLETED`.
# 4. Declaring Rules
Rules map evidence signals to hypotheses:
python
from layers.engine.hypotheses import Rule
from layers.schemas import Layer
MYPROVIDER_RULES = [
    Rule(
        id="myprovider_quota_exhausted",
        layer=Layer.CREDENTIALS,
        cause="Account quota exhausted",
        requires=["myprovider_account.quota_exhausted"],
        contradicted_by=["myprovider_account.quota_available"],
        base_confidence=0.85,
    )
]

# 5. Registering and Testing Your Pack
1. Register your pack in `src/layers/packs/registry.py`.
2. Add a contract test in `tests/test_packs.py`:
python
from layers.packs.myprovider import pack as my_pack
from tests.test_packs import assert_pack_contract
def test_myprovider_contract():
    assert_pack_contract(my_pack)
