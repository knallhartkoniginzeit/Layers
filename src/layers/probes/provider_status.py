from __future__ import annotations

from urllib.parse import urlparse

import httpx

from layers.config import settings
from layers.probes.base import BaseProbe, make_evidence
from layers.schemas import FailureCase, ProbeResult

_KNOWN_STATUS_PAGES: dict[str, str] = {
    "serpapi.com": "https://serpapi.com",
    "api.openai.com": "https://status.openai.com/api/v2/summary.json",
    "api.anthropic.com": "https://status.anthropic.com/api/v2/summary.json",
}


class ProviderStatusProbe(BaseProbe):
    name = "provider_status"

    def __init__(self, status_url: str | None = None) -> None:
        self._status_url = status_url

    def _run(self, case: FailureCase) -> ProbeResult:
        evidence = []
        body = (case.response_body_sample or "").lower()

        if any(
            marker in body
            for marker in (
                "major service outage",
                '"indicator": "major"',
                "statuspage",
                "incident",
                "investigating",
            )
        ):
            evidence.append(
                make_evidence(
                    self.name,
                    "provider",
                    "Status report reveals active incident or major outage",
                    supports=["provider_incident"],
                    strength=0.9,
                )
            )
            return ProbeResult(probe=self.name, ok=False, evidence=evidence)

        host = urlparse(case.url).hostname or ""
        status_url = self._status_url

        if not status_url:
            for pattern, url in _KNOWN_STATUS_PAGES.items():
                if host.endswith(pattern):
                    status_url = url
                    break

        if not status_url:
            return ProbeResult(
                probe=self.name,
                ok=True,
                skipped=True,
                skip_reason=f"No known status page for {host}",
            )

        evidence = []

        try:
            resp = httpx.get(
                status_url,
                timeout=settings.probe.http_timeout,
                follow_redirects=True,
            )
            data = resp.json()

            status = data.get("status", {})
            indicator = status.get("indicator", "none")
            description = status.get("description", "")

            incidents = data.get("incidents", [])
            open_incidents = [
                i for i in incidents if i.get("status") not in ("resolved", "postmortem")
            ]

            if indicator in ("major", "critical"):
                evidence.append(
                    make_evidence(
                        self.name,
                        "provider",
                        f"Provider status page reports major incident: {description}",
                        supports=["provider_incident"],
                        strength=0.9,
                        raw={"indicator": indicator, "open_incidents": len(open_incidents)},
                    )
                )
            elif indicator != "none" or open_incidents:
                inc_summaries = [i.get("name", "?") for i in open_incidents[:3]]
                evidence.append(
                    make_evidence(
                        self.name,
                        "provider",
                        f"Provider status page reports minor advisory: {description}. ({', '.join(inc_summaries)})",
                        supports=["provider_incident"],
                        strength=0.3,
                        raw={"indicator": indicator, "open_incidents": len(open_incidents)},
                    )
                )
            else:
                evidence.append(
                    make_evidence(
                        self.name,
                        "provider",
                        "Provider status page reports all systems operational",
                        contradicts=["provider_incident"],
                        strength=0.5,
                        raw={"indicator": indicator},
                    )
                )

        except (httpx.HTTPError, ValueError, KeyError) as exc:
            evidence.append(
                make_evidence(
                    self.name,
                    "provider",
                    f"Could not check provider status page: {exc}",
                    strength=0.1,
                    raw={"error": str(exc)},
                )
            )

        return ProbeResult(
            probe=self.name,
            ok=all(not e.supports for e in evidence),
            evidence=evidence,
        )
