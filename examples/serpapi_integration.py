from __future__ import annotations

import os

import httpx

from layers import diagnose
from layers.packs.registry import get_pack
from layers.schemas import ActionKind, FailureCase

SERPAPI_KEY = os.getenv("SERPAPI_KEY", "your_api_key_here")


def serpapi_search(query: str, engine: str = "google") -> dict:
    """
    Perform a SerpApi search with layers-backed error handling.

    If the call fails, layers diagnoses the root cause using the
    SerpApi provider pack (which knows about quota errors, invalid engines,
    CAPTCHA loops, etc.) and returns a structured diagnosis instead of
    raising a plain exception.
    """
    url = "https://serpapi.com/search.json"
    params = {"engine": engine, "q": query, "api_key": SERPAPI_KEY}

    try:
        response = httpx.get(url, params=params, timeout=15.0)
        response.raise_for_status()
        return response.json()

    except httpx.HTTPStatusError as exc:
        resp = exc.response
        case = FailureCase(
            method="GET",
            url=str(exc.request.url),
            status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body_sample=resp.text[:2048],
            error_class=type(exc).__name__,
        )
    except httpx.TimeoutException:
        case = FailureCase(
            method="GET",
            url=url,
            status=None,
            error_class="ReadTimeout",
            elapsed_ms=15_000.0,
        )
    except httpx.RequestError as exc:
        case = FailureCase(
            method="GET",
            url=url,
            status=None,
            error_class=type(exc).__name__,
        )

    pack = get_pack("serpapi")

    diagnosis = diagnose(case, pack=pack)

    top = diagnosis.top
    action = diagnosis.action

    print("\n── layers Diagnosis ─────────────────────────────────────")
    if top:
        print(f"  Layer       : {top.layer.value.upper()}")
        print(f"  Cause       : {top.cause}")
        print(f"  Confidence  : {int(top.confidence * 100)}% ({top.band.value})")
    else:
        print("  Verdict     : Inconclusive")
    print(f"  Action      : {action.kind.value}")
    print(f"  Safe        : {action.safe}")
    print(f"  Explanation : {action.explanation}")
    print("────────────────────────────────────────────────────────────\n")

    if action.kind == ActionKind.FIX_CREDENTIALS:
        raise RuntimeError(
            f"SerpApi credential error: {top.cause if top else 'Unknown'}. "
            "Regenerate or verify your API key at https://serpapi.com/manage-api-key"
        )
    elif action.kind == ActionKind.DO_NOT_RETRY:
        raise RuntimeError(f"Non-retryable SerpApi error: {top.cause if top else 'Unknown'}")
    elif action.kind == ActionKind.RETRY_WITH_BACKOFF:
        import time

        print("Transient error — retrying in 5 seconds...")
        time.sleep(5)
        return serpapi_search(query, engine)
    else:
        raise RuntimeError(f"SerpApi request failed: {top.cause if top else 'Unknown'}")


if __name__ == "__main__":
    print("SerpApi + layers integration demo")
    print("Attempting search (will trigger a 401 if key is invalid)...\n")
    try:
        results = serpapi_search("coffee shops near me")
        print(f"Search succeeded — got {len(results.get('organic_results', []))} organic results")
    except RuntimeError as e:
        print(f"Handled error: {e}")
