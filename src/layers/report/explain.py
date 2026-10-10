from __future__ import annotations

import os

from layers.schemas import Diagnosis


def generate_explanation(diagnosis: Diagnosis) -> str:
    """
    Generate an evidence-backed narrative summary.

    If an LLM API key (OPENAI_API_KEY) is present, use it with a strict,
    evidence-constrained system prompt.
    Otherwise, produce a clean template-based natural language narrative.
    """
    case = diagnosis.case
    top = diagnosis.top
    action = diagnosis.action

    if not top:
        return (
            "The diagnosis concluded as inconclusive. None of the investigated failure layers "
            "(request, network, gateway, credentials, provider) produced sufficient evidence "
            "to reach the minimum confidence threshold."
        )

    evidence_items = [
        f"- [{e.layer.value.upper()}] {e.finding} (strength: {int(e.strength * 100)}%)"
        for e in top.evidence
    ]
    evidence_text = (
        "\n".join(evidence_items) if evidence_items else "No supporting evidence items recorded."
    )

    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key:
        try:
            import openai  # type: ignore[import-not-found]

            client = openai.OpenAI(api_key=api_key)
            prompt = (
                f"You are layers's explanation renderer. Your job is to describe the following API failure "
                f"diagnosis in clear, direct technical language. Do not invent any facts, server-side states, "
                f"or network events not explicitly present in the evidence below.\n\n"
                f"HTTP Method: {case.method}\n"
                f"URL (Redacted): {case.url}\n"
                f"Reported Status/Error: {case.status or case.error_class}\n"
                f"Attributed Layer: {top.layer.value}\n"
                f"Attributed Cause: {top.cause}\n"
                f"Confidence Band: {top.band.value} ({int(top.confidence * 100)}%)\n"
                f"Operation Completion Status: {diagnosis.completion.value}\n"
                f"Recommended Recovery Action: {action.kind.value} (Safe: {action.safe})\n"
                f"Action Rationale: {action.explanation}\n"
                f"Supporting Evidence:\n{evidence_text}\n\n"
                f"Write a concise 2-3 paragraph explanation of what happened, why this layer was determined "
                f"to be at fault based on the evidence, and what the developer should do next."
            )
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an accurate, strictly evidence-bound diagnostic explainer.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=300,
            )
            llm_text: str | None = response.choices[0].message.content
            if llm_text:
                return llm_text.strip()
        except Exception:
            pass

    parts = [
        f"API call `{case.method} {case.url}` failed with {f'HTTP {case.status}' if case.status else case.error_class or 'an unhandled error'}.",
        f"Based on probe analysis, the failure is attributed to the **{top.layer.value.upper()}** layer: {top.cause} (confidence: {top.band.value}, {int(top.confidence * 100)}%).",
        f"The primary supporting observations include: {'; '.join(e.finding for e in top.evidence[:2]) if top.evidence else 'rule match from response patterns'}.",
        f"Completion check status is **{diagnosis.completion.value}**. "
        + (f"Recommended action: `{action.kind.value}` — {action.explanation}" if action else ""),
    ]
    return " ".join(parts)
