from __future__ import annotations

import json
from urllib.parse import urlparse

import httpx

from layers.config import settings
from layers.probes.base import BaseProbe, make_evidence
from layers.safety import assert_probe_method_allowed
from layers.schemas import FailureCase, ProbeResult


class OpenAIModelsAuthProbe(BaseProbe):
    name = "openai_auth_models"

    def _run(self, case: FailureCase) -> ProbeResult:
        auth_hdr = case.request_headers.get("Authorization") or case.request_headers.get(
            "authorization"
        )
        if not auth_hdr or auth_hdr == "[REDACTED]":
            return ProbeResult(
                probe=self.name,
                ok=False,
                skipped=True,
                skip_reason="No unredacted Authorization header available for /v1/models probe",
            )

        parsed = urlparse(case.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        url = f"{base}/v1/models"

        assert_probe_method_allowed("GET")

        try:
            resp = httpx.get(
                url,
                headers={"Authorization": auth_hdr},
                timeout=settings.probe.http_timeout,
            )
        except Exception as exc:
            return ProbeResult(
                probe=self.name,
                ok=False,
                skipped=True,
                skip_reason=f"OpenAI models GET failed: {exc}",
            )

        evidence = []
        if resp.status_code == 200:
            evidence.append(
                make_evidence(
                    self.name,
                    "credentials",
                    "GET /v1/models returned 200: API key is valid and has active read permissions",
                    contradicts=["key_invalid", "key_expired"],
                    strength=0.9,
                )
            )
            return ProbeResult(probe=self.name, ok=True, evidence=evidence)

        if resp.status_code == 401:
            evidence.append(
                make_evidence(
                    self.name,
                    "credentials",
                    "GET /v1/models returned 401 Unauthorized: API key is invalid or revoked",
                    supports=["key_invalid", "key_expired"],
                    strength=0.95,
                )
            )
            return ProbeResult(probe=self.name, ok=False, evidence=evidence)

        if resp.status_code == 429:
            evidence.append(
                make_evidence(
                    self.name,
                    "provider",
                    "GET /v1/models returned 429: API key has hit rate limits or zero credit balance",
                    supports=["openai_provider_429", "quota_exhausted"],
                    strength=0.9,
                )
            )
            return ProbeResult(probe=self.name, ok=False, evidence=evidence)

        return ProbeResult(probe=self.name, ok=True, evidence=evidence)


class OpenAIErrorClassifierProbe(BaseProbe):
    name = "openai_error_classifier"

    def _run(self, case: FailureCase) -> ProbeResult:
        evidence = []
        body = case.response_body_sample or ""
        status = case.status

        if status == 429:
            is_json = False
            error_type = None
            try:
                data = json.loads(body)
                is_json = True
                err = data.get("error", {})
                if isinstance(err, dict):
                    error_type = err.get("type") or err.get("code")
            except Exception:
                is_json = False

            has_cf = any(
                "cloudflare" in v.lower() or "cf-ray" in k.lower()
                for k, v in case.response_headers.items()
            )
            has_retry_after = "retry-after" in {k.lower() for k in case.response_headers}

            if is_json and error_type:
                evidence.append(
                    make_evidence(
                        self.name,
                        "provider",
                        f"HTTP 429 with OpenAI provider JSON error payload (type='{error_type}') — Provider-level limit",
                        supports=["openai_provider_429", "provider_rate_limit"],
                        contradicts=["openai_gateway_429", "gateway_rate_limit"],
                        strength=0.9,
                        raw={"error_type": error_type},
                    )
                )
            elif has_retry_after or has_cf or "<html>" in body.lower():
                evidence.append(
                    make_evidence(
                        self.name,
                        "gateway",
                        "HTTP 429 with edge headers / HTML body — Gateway / Cloudflare rate limit",
                        supports=["openai_gateway_429", "gateway_rate_limit"],
                        contradicts=["openai_provider_429", "provider_rate_limit"],
                        strength=0.85,
                    )
                )

        if "maximum context length" in body.lower() or "context_length_exceeded" in body.lower():
            evidence.append(
                make_evidence(
                    self.name,
                    "request",
                    "Prompt tokens exceeded the model's maximum context length window",
                    supports=["openai_context_length_exceeded", "malformed_request"],
                    strength=0.95,
                )
            )

        return ProbeResult(probe=self.name, ok=True, evidence=evidence)
