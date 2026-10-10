from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

import httpx

from layers.config import settings
from layers.probes.base import BaseProbe, make_evidence
from layers.safety import assert_probe_method_allowed
from layers.schemas import CompletionVerdict, FailureCase, ProbeResult


def _extract_api_key(case: FailureCase) -> str | None:
    for k, v in case.request_headers.items():
        if k.lower() in ("x-serpapi-key", "api-key", "authorization") and v and v != "[REDACTED]":
            return v.replace("Bearer ", "").strip()
    parsed = urlparse(case.url)
    qs = parse_qs(parsed.query)
    if "api_key" in qs and qs["api_key"]:
        val = qs["api_key"][0]
        if val != "[REDACTED]":
            return val
    return None


def _extract_search_id(case: FailureCase) -> str | None:
    for k, v in case.response_headers.items():
        if "search" in k.lower() and "id" in k.lower():
            return v
    if case.response_body_sample:
        m = re.search(r'"(?:search_)?id"\s*:\s*"([a-f0-9]+)"', case.response_body_sample)
        if m:
            return m.group(1)
    return None


class SerpApiAccountProbe(BaseProbe):
    name = "serpapi_account"

    def _run(self, case: FailureCase) -> ProbeResult:
        evidence = []
        body = (case.response_body_sample or "").lower()

        if case.status == 429 and any(k in body for k in ("run out", "searches", "quota")):
            evidence.append(
                make_evidence(
                    self.name,
                    "credentials",
                    "SerpApi error specifies account has run out of searches",
                    supports=["serpapi_quota_exhausted", "quota_exhausted"],
                    strength=0.95,
                    raw={"status": 429},
                )
            )
            return ProbeResult(probe=self.name, ok=False, evidence=evidence)

        if case.status == 401:
            evidence.append(
                make_evidence(
                    self.name,
                    "credentials",
                    "SerpApi returned 401: Invalid API key",
                    supports=["serpapi_invalid_key", "key_invalid"],
                    strength=0.95,
                    raw={"status": 401},
                )
            )
            return ProbeResult(probe=self.name, ok=False, evidence=evidence)

        api_key = _extract_api_key(case)

        if not api_key:
            return ProbeResult(
                probe=self.name,
                ok=False,
                skipped=True,
                skip_reason="No unredacted api_key available for SerpApi account probe",
            )

        assert_probe_method_allowed("GET")

        try:
            resp = httpx.get(
                "https://serpapi.com/account",
                params={"api_key": api_key},
                timeout=settings.probe.http_timeout,
            )
        except Exception as exc:
            return ProbeResult(
                probe=self.name,
                ok=False,
                skipped=True,
                skip_reason=f"Account API connection failed: {exc}",
            )

        if resp.status_code == 401 or "Invalid API key" in resp.text:
            evidence.append(
                make_evidence(
                    self.name,
                    "credentials",
                    "SerpApi /account rejected API key: 401 Invalid API key",
                    supports=["serpapi_invalid_key", "key_invalid"],
                    strength=0.95,
                    raw={"status": resp.status_code},
                )
            )
            return ProbeResult(probe=self.name, ok=False, evidence=evidence)

        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                data = {}

            total_left = data.get("total_searches_left", -1)
            plan_left = data.get("plan_searches_left", -1)
            account_email = data.get("account_email", "verified")

            if total_left == 0 or plan_left == 0:
                evidence.append(
                    make_evidence(
                        self.name,
                        "credentials",
                        f"SerpApi key is valid ({account_email}) but search quota is exhausted (0 searches left)",
                        supports=["serpapi_quota_exhausted", "quota_exhausted"],
                        contradicts=["serpapi_invalid_key", "key_invalid"],
                        strength=0.95,
                        raw={"total_searches_left": total_left, "plan_searches_left": plan_left},
                    )
                )
            else:
                evidence.append(
                    make_evidence(
                        self.name,
                        "credentials",
                        f"SerpApi key is active and has searches remaining (left: {total_left})",
                        supports=["serpapi_account.quota_available"],
                        contradicts=[
                            "serpapi_invalid_key",
                            "serpapi_quota_exhausted",
                            "key_invalid",
                        ],
                        strength=0.85,
                        raw={"total_searches_left": total_left},
                    )
                )

        return ProbeResult(probe=self.name, ok=True, evidence=evidence)


class SerpApiArchiveProbe(BaseProbe):
    name = "serpapi_archive"

    def _run(self, case: FailureCase) -> ProbeResult:
        if case.method in ("GET", "HEAD", "OPTIONS"):
            return ProbeResult(
                probe=self.name,
                ok=True,
                raw={"completion_verdict": CompletionVerdict.NOT_APPLICABLE.value},
            )

        search_id = _extract_search_id(case)
        api_key = _extract_api_key(case)

        if not search_id:
            return ProbeResult(
                probe=self.name,
                ok=True,
                skipped=True,
                skip_reason="No SerpApi search_id captured in failure case; cannot query Search Archive without ID",
                raw={"completion_verdict": CompletionVerdict.UNKNOWN.value},
            )

        if not api_key:
            return ProbeResult(
                probe=self.name,
                ok=False,
                skipped=True,
                skip_reason="Search ID found but no API key to query SerpApi Archive",
                raw={"completion_verdict": CompletionVerdict.UNKNOWN.value},
            )

        assert_probe_method_allowed("GET")

        try:
            resp = httpx.get(
                f"https://serpapi.com/searches/{search_id}.json",
                params={"api_key": api_key},
                timeout=settings.probe.http_timeout,
            )
        except Exception as exc:
            return ProbeResult(
                probe=self.name,
                ok=False,
                skipped=True,
                skip_reason=f"Archive lookup failed: {exc}",
                raw={"completion_verdict": CompletionVerdict.UNKNOWN.value},
            )

        evidence = []
        if resp.status_code == 200:
            evidence.append(
                make_evidence(
                    self.name,
                    "provider",
                    f"Search {search_id} was found in SerpApi archive and completed successfully",
                    supports=["serpapi_archive_completed", "operation_completed"],
                    strength=0.95,
                    raw={"search_id": search_id, "status": "Success"},
                )
            )
            return ProbeResult(
                probe=self.name,
                ok=True,
                evidence=evidence,
                raw={"completion_verdict": CompletionVerdict.COMPLETED.value},
            )

        if resp.status_code == 404:
            evidence.append(
                make_evidence(
                    self.name,
                    "provider",
                    f"Search {search_id} was not found in SerpApi archive (never processed)",
                    supports=["serpapi_archive.not_found"],
                    strength=0.85,
                    raw={"search_id": search_id, "status": "Not Found"},
                )
            )
            return ProbeResult(
                probe=self.name,
                ok=True,
                evidence=evidence,
                raw={"completion_verdict": CompletionVerdict.NOT_COMPLETED.value},
            )

        return ProbeResult(
            probe=self.name,
            ok=False,
            raw={"completion_verdict": CompletionVerdict.UNKNOWN.value},
        )
