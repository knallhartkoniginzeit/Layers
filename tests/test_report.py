from __future__ import annotations

import json

import pytest

from layers.report.json_out import render_json
from layers.report.markdown import render_markdown
from layers.schemas import (
    ActionKind,
    CompletionVerdict,
    ConfidenceBand,
    Diagnosis,
    Evidence,
    FailureCase,
    Hypothesis,
    Layer,
    RecoveryAction,
)


def _make_diagnosis() -> Diagnosis:
    case = FailureCase(
        method="GET",
        url="https://api.example.com/v1/search",
        status=401,
        response_headers={"Content-Type": "application/json"},
        response_body_sample='{"error": "Unauthorized"}',
    )
    evidence = [
        Evidence(
            probe="request_lint",
            layer=Layer.REQUEST,
            finding="HTTP 401 Unauthorized received",
            supports=["key_invalid"],
            strength=0.9,
        ),
        Evidence(
            probe="credentials",
            layer=Layer.CREDENTIALS,
            finding="Read-only probe also returned 401",
            supports=["key_invalid"],
            strength=0.8,
        ),
    ]
    hyp = Hypothesis(
        id="key_invalid",
        layer=Layer.CREDENTIALS,
        cause="The API key is invalid or has been revoked.",
        confidence=0.85,
        band=ConfidenceBand.HIGH,
        evidence=evidence,
    )
    action = RecoveryAction(
        kind=ActionKind.FIX_CREDENTIALS,
        safe=True,
        explanation="Regenerate the API key from your provider dashboard.",
        commands=["# Visit https://dashboard.example.com/api-keys"],
    )
    return Diagnosis(
        case=case,
        top=hyp,
        alternatives=[],
        completion=CompletionVerdict.NOT_COMPLETED,
        action=action,
        probes_run=["request_lint", "credentials"],
    )


class TestJsonOutput:
    def test_produces_valid_json(self):
        diag = _make_diagnosis()
        output = render_json(diag)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_json_contains_case(self):
        diag = _make_diagnosis()
        output = render_json(diag)
        parsed = json.loads(output)
        assert "case" in parsed
        assert parsed["case"]["status"] == 401

    def test_json_contains_top_hypothesis(self):
        diag = _make_diagnosis()
        output = render_json(diag)
        parsed = json.loads(output)
        assert parsed["top"]["id"] == "key_invalid"
        assert parsed["top"]["confidence"] == pytest.approx(0.85)

    def test_json_contains_action(self):
        diag = _make_diagnosis()
        output = render_json(diag)
        parsed = json.loads(output)
        assert "action" in parsed
        assert parsed["action"]["kind"] == "fix_credentials"

    def test_json_contains_probes_run(self):
        diag = _make_diagnosis()
        output = render_json(diag)
        parsed = json.loads(output)
        assert "request_lint" in parsed["probes_run"]


class TestMarkdownOutput:
    def test_produces_non_empty_string(self):
        diag = _make_diagnosis()
        md = render_markdown(diag)
        assert isinstance(md, str)
        assert len(md) > 50

    def test_markdown_contains_url(self):
        diag = _make_diagnosis()
        md = render_markdown(diag)
        assert "api.example.com" in md

    def test_markdown_contains_verdict_section(self):
        diag = _make_diagnosis()
        md = render_markdown(diag)
        assert "Verdict" in md

    def test_markdown_contains_cause(self):
        diag = _make_diagnosis()
        md = render_markdown(diag)
        assert "invalid or has been revoked" in md

    def test_markdown_contains_recovery(self):
        diag = _make_diagnosis()
        md = render_markdown(diag)
        assert "Recovery" in md or "Regenerate" in md

    def test_markdown_contains_evidence_table(self):
        diag = _make_diagnosis()
        md = render_markdown(diag)
        assert "Evidence" in md
        assert "request_lint" in md
