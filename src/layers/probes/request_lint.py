from __future__ import annotations

import json

from layers.probes.base import BaseProbe, make_evidence
from layers.schemas import FailureCase, ProbeResult


class RequestLintProbe(BaseProbe):
    name = "request_lint"

    def _run(self, case: FailureCase) -> ProbeResult:
        evidence = []

        ct = case.request_headers.get("Content-Type", "").lower()
        if case.request_body_sample:
            if "json" in ct:
                try:
                    json.loads(case.request_body_sample)
                except (json.JSONDecodeError, ValueError):
                    evidence.append(
                        make_evidence(
                            self.name,
                            "request",
                            "Content-Type is application/json but body is not valid JSON",
                            supports=["malformed_request"],
                            strength=0.95,
                        )
                    )
            elif ("text" in ct or not ct) and case.request_body_sample.strip().startswith(
                ("{", "[")
            ):
                evidence.append(
                    make_evidence(
                        self.name,
                        "request",
                        f"Payload is JSON but Content-Type is '{ct or 'missing'}'",
                        supports=["malformed_request"],
                        strength=0.9,
                    )
                )
            elif not ct and case.method in ("POST", "PUT", "PATCH"):
                evidence.append(
                    make_evidence(
                        self.name,
                        "request",
                        "POST/PUT/PATCH with a body but no Content-Type header",
                        supports=["malformed_request"],
                        strength=0.7,
                    )
                )

        if (
            case.method in ("POST", "PUT", "PATCH")
            and not case.request_body_sample
            and case.status
            and case.status in (400, 415, 422)
        ):
            evidence.append(
                make_evidence(
                    self.name,
                    "request",
                    f"{case.method} request has no body and server returned {case.status}",
                    supports=["malformed_request", "missing_body"],
                    strength=0.85,
                )
            )

        if case.status in (400, 405, 406, 411, 413, 415, 422):
            evidence.append(
                make_evidence(
                    self.name,
                    "request",
                    f"HTTP {case.status} indicates a client request validation or formatting error",
                    supports=["malformed_request"],
                    strength=0.9,
                    raw={"status": case.status},
                )
            )

        return ProbeResult(
            probe=self.name,
            ok=len(evidence) == 0,
            evidence=evidence,
        )
