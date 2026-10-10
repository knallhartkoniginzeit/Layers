"""
layers – packs/serpapi/rules.py
SerpApi-specific hypothesis rules.
"""

from layers.engine.hypotheses import Rule
from layers.schemas import Layer

SERPAPI_RULES = [
    Rule(
        id="serpapi_quota_exhausted",
        layer=Layer.CREDENTIALS,
        cause="SerpApi account has exhausted its total searches / monthly quota",
        requires=["serpapi_account"],
        contradicted_by=["serpapi_account.quota_available"],
        base_confidence=0.85,
    ),
    Rule(
        id="serpapi_invalid_key",
        layer=Layer.CREDENTIALS,
        cause="SerpApi key is invalid, unverified, or revoked",
        requires=["serpapi_account"],
        contradicted_by=["serpapi_account.valid_key"],
        base_confidence=0.85,
    ),
    Rule(
        id="serpapi_archive_completed",
        layer=Layer.PROVIDER,
        cause="Search was successfully completed and processed into SerpApi archive",
        requires=["serpapi_archive.completed"],
        contradicted_by=["serpapi_archive.not_found"],
        base_confidence=0.9,
    ),
    Rule(
        id="serpapi_upstream_engine_down",
        layer=Layer.PROVIDER,
        cause="Target search engine (Google, Bing, etc.) upstream is blocking or unavailable",
        requires=["serpapi_error.engine_down"],
        contradicted_by=[],
        base_confidence=0.7,
    ),
]
