from __future__ import annotations

from typing import Any

from layers.engine.hypotheses import RuleEngine
from layers.engine.rules import ALL_RULES
from layers.ingest.curl import from_curl
from layers.ingest.exception import from_exception
from layers.ingest.har import from_har
from layers.ingest.raw import from_raw
from layers.packs.registry import find_pack_for_url, get_pack
from layers.recovery.actions import action_for_hypothesis
from layers.recovery.patches import (
    patch_add_idempotency_key,
    patch_add_timeout,
    patch_unset_proxy,
)
from layers.runner import ProbeRunner
from layers.schemas import Diagnosis, FailureCase, Hypothesis


def diagnose(
    input_data: str | FailureCase,
    *,
    input_type: str = "auto",
    provider: str | None = None,
    probe_auth: bool = False,
    allow_replay: bool = False,
    max_probes: int | None = None,
) -> Diagnosis:
    """
    Main entry point: probe each layer of a failed API call and return an evidence-backed Diagnosis.

    input_data: curl string, HAR json string, exception traceback, raw HTTP text, or FailureCase
    input_type: "curl" | "har" | "exception" | "raw" | "auto"
    provider: explicit pack name (e.g., "serpapi", "openai_compat") or auto-detected by URL
    probe_auth: whether to permit authenticated read-only key verification
    allow_replay: whether to permit idempotent request replay
    """
    if isinstance(input_data, FailureCase):
        case = input_data
    else:
        case = _parse_input(input_data, input_type)

    pack = None
    if provider:
        pack = get_pack(provider)
    if not pack and case.url:
        pack = find_pack_for_url(case.url)

    runner = ProbeRunner(
        pack=pack,
        probe_auth=probe_auth,
        allow_replay=allow_replay,
        max_probes=max_probes,
    )
    run_result = runner.run(case)

    engine = RuleEngine()
    engine.add_rules(list(ALL_RULES))
    if pack:
        engine.add_rules(pack.rules())

    hypotheses = engine.evaluate(run_result.evidence)

    top: Hypothesis | None = hypotheses[0] if hypotheses else None
    alternatives: list[Hypothesis] = hypotheses[1:4] if len(hypotheses) > 1 else []

    action = action_for_hypothesis(top, case, run_result.completion)

    if top:
        if top.id == "bad_proxy_env":
            action.patch = patch_unset_proxy()
        elif top.id in ("gateway_timeout", "network_timeout", "read_timeout"):
            if not case.idempotent and not case.has_idempotency_key:
                action.patch = patch_add_idempotency_key(method=case.method, url=case.url)
            else:
                action.patch = patch_add_timeout(timeout_s=30)
        elif top.id == "malformed_request" and not case.has_idempotency_key and not case.idempotent:
            action.patch = patch_add_idempotency_key(method=case.method, url=case.url)

    return Diagnosis(
        case=case,
        top=top,
        alternatives=alternatives,
        completion=run_result.completion,
        action=action,
        probes_run=run_result.probes_run,
        probes_skipped=run_result.probes_skipped,
        limits=run_result.limits,
    )


def diagnose_from_dict(d: dict[str, Any], **kwargs: Any) -> Diagnosis:
    """Convenience helper to diagnose from a dictionary representing a FailureCase."""
    case = FailureCase.model_validate(d)
    return diagnose(case, **kwargs)


def _parse_input(text: str, input_type: str) -> FailureCase:
    text = text.strip()
    if input_type == "curl" or (
        input_type == "auto" and (text.startswith("curl ") or "> GET " in text or "> POST " in text)
    ):
        return from_curl(text)

    if input_type == "har" or (input_type == "auto" and ('"log":' in text or '"request":' in text)):
        try:
            return from_har(text)
        except Exception:
            pass

    if input_type == "exception" or (
        input_type == "auto" and ("Traceback" in text or "Error:" in text or "raise " in text)
    ):
        return from_exception(text)

    return from_raw(text)
