"""
layers – probes/credentials.py
Credentialed probe (opt-in): safe read-only GET to test key validity.

Safety rules:
- Only runs if --probe-auth is passed.
- Only makes GET requests.
- Compares read vs write to distinguish "bad key" from "missing permission".
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from layers.config import settings
from layers.probes.base import BaseProbe, make_evidence
from layers.safety import assert_probe_method_allowed
from layers.schemas import FailureCase, ProbeResult


class CredentialsProbe(BaseProbe):
    name = "credentials"

    def _run(self, case: FailureCase) -> ProbeResult:
        evidence = []
        body = (case.response_body_sample or "").lower()

        if case.status == 401:
            if any(k in body for k in ("expired", "token_expired")):
                evidence.append(
                    make_evidence(
                        self.name,
                        "credentials",
                        "HTTP 401 response specifies token has expired",
                        supports=["key_expired"],
                        strength=0.9,
                        raw={"status": 401, "body_hint": "expired"},
                    )
                )
            elif any(k in body for k in ("invalid", "unauthorized", "api_key", "invalid api key")):
                evidence.append(
                    make_evidence(
                        self.name,
                        "credentials",
                        "HTTP 401 response specifies API key is invalid",
                        supports=["key_invalid"],
                        strength=0.9,
                        raw={"status": 401, "body_hint": "invalid"},
                    )
                )
            else:
                evidence.append(
                    make_evidence(
                        self.name,
                        "credentials",
                        "HTTP 401 Unauthorized returned by endpoint",
                        supports=["key_invalid", "key_expired"],
                        strength=0.8,
                        raw={"status": 401},
                    )
                )

        elif case.status == 403:
            if any(k in body for k in ("scope", "permission", "forbidden")):
                evidence.append(
                    make_evidence(
                        self.name,
                        "credentials",
                        "HTTP 403 Forbidden indicates missing scope or permissions",
                        supports=["missing_permission"],
                        strength=0.9,
                        raw={"status": 403, "body_hint": "permission"},
                    )
                )
            else:
                evidence.append(
                    make_evidence(
                        self.name,
                        "credentials",
                        "HTTP 403 Forbidden returned by endpoint",
                        supports=["missing_permission", "key_invalid"],
                        strength=0.75,
                    )
                )

        elif case.status == 429 and any(k in body for k in ("quota", "searches", "run out")):
            evidence.append(
                make_evidence(
                    self.name,
                    "credentials",
                    "HTTP 429 specifies account search quota is exhausted",
                    supports=["quota_exhausted", "serpapi_quota_exhausted"],
                    strength=0.95,
                    raw={"status": 429, "body_hint": "quota_exhausted"},
                )
            )

        if not settings.probe.probe_auth:
            return ProbeResult(
                probe=self.name,
                ok=len(evidence) == 0,
                evidence=evidence,
                skipped=bool(not evidence),
                skip_reason="Live credential probe requires --probe-auth flag"
                if not evidence
                else None,
            )
        parsed = urlparse(case.url)
        base_url = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            base_url += f":{parsed.port}"

        auth_headers = {}
        for k, v in case.request_headers.items():
            if k.lower() in ("authorization", "x-api-key", "api-key") and v != "[REDACTED]":
                auth_headers[k] = v

        if not auth_headers:
            return ProbeResult(
                probe=self.name,
                ok=True,
                skipped=True,
                skip_reason="No usable auth headers found (all redacted or missing)",
            )

        assert_probe_method_allowed("GET")

        try:
            resp = httpx.get(
                base_url + "/",
                headers=auth_headers,
                timeout=settings.probe.http_timeout,
                follow_redirects=True,
            )
        except httpx.HTTPError as exc:
            evidence.append(
                make_evidence(
                    self.name,
                    "credentials",
                    f"Credential check request failed: {exc}",
                    strength=0.3,
                )
            )
            return ProbeResult(probe=self.name, ok=False, evidence=evidence)

        if resp.status_code in (401, 403):
            evidence.append(
                make_evidence(
                    self.name,
                    "credentials",
                    f"Read-only GET with auth returned {resp.status_code} — "
                    "key is likely invalid or expired",
                    supports=["key_invalid", "key_expired"],
                    strength=0.85,
                    raw={"status": resp.status_code},
                )
            )
        elif resp.status_code < 400:
            if case.status in (401, 403):
                evidence.append(
                    make_evidence(
                        self.name,
                        "credentials",
                        "Read-only GET succeeded but original call returned "
                        f"{case.status} — likely missing permission, not a bad key",
                        supports=["missing_permission"],
                        contradicts=["key_invalid", "key_expired"],
                        strength=0.8,
                        raw={"read_status": resp.status_code, "original_status": case.status},
                    )
                )
            else:
                evidence.append(
                    make_evidence(
                        self.name,
                        "credentials",
                        "Read-only GET with auth succeeded — key is valid",
                        contradicts=["key_invalid", "key_expired"],
                        strength=0.7,
                        raw={"status": resp.status_code},
                    )
                )

        return ProbeResult(
            probe=self.name,
            ok=all(not e.supports for e in evidence),
            evidence=evidence,
        )
