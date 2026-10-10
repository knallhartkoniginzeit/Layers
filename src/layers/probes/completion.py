from __future__ import annotations

from layers.probes.base import BaseProbe, make_evidence
from layers.schemas import CompletionVerdict, FailureCase, ProbeResult


class CompletionProbe(BaseProbe):
    name = "completion"

    def _run(self, case: FailureCase) -> ProbeResult:
        evidence = []

        if case.method in ("GET", "HEAD", "OPTIONS"):
            verdict = CompletionVerdict.NOT_APPLICABLE
            evidence.append(
                make_evidence(
                    self.name,
                    "provider",
                    f"{case.method} is read-only; completion check not applicable",
                    strength=1.0,
                )
            )
            return ProbeResult(
                probe=self.name,
                ok=True,
                evidence=evidence,
                raw={"completion_verdict": verdict.value},
            )

        if case.status is not None and (400 <= case.status < 500 or case.status == 500):
            body = case.response_body_sample or ""
            if not any(
                marker in body.lower() for marker in ('"id":', '"resource_id":', '"search_id":')
            ):
                verdict = CompletionVerdict.NOT_COMPLETED
                evidence.append(
                    make_evidence(
                        self.name,
                        "provider",
                        f"HTTP {case.status} indicates operation did not commit",
                        supports=["malformed_request", "key_invalid", "missing_permission"],
                        strength=0.9,
                    )
                )
                return ProbeResult(
                    probe=self.name,
                    ok=True,
                    evidence=evidence,
                    raw={"completion_verdict": verdict.value},
                )

        body = case.response_body_sample or ""
        if any(marker in body.lower() for marker in ('"id":', '"resource_id":', '"search_id":')):
            evidence.append(
                make_evidence(
                    self.name,
                    "provider",
                    "Response body contains a resource ID — operation likely committed",
                    supports=["operation_completed"],
                    strength=0.9,
                    raw={"body_has_id": True},
                )
            )
            verdict = CompletionVerdict.COMPLETED
            return ProbeResult(
                probe=self.name,
                ok=True,
                evidence=evidence,
                raw={"completion_verdict": verdict.value},
            )

        if case.status and 200 <= case.status < 300:
            verdict = CompletionVerdict.COMPLETED
            return ProbeResult(
                probe=self.name,
                ok=True,
                evidence=evidence,
                raw={"completion_verdict": verdict.value},
            )

        verdict = CompletionVerdict.UNKNOWN
        evidence.append(
            make_evidence(
                self.name,
                "unknown",
                "Non-idempotent operation failed without confirmed commit — completion unknown",
                strength=0.7,
            )
        )

        return ProbeResult(
            probe=self.name,
            ok=True,
            evidence=evidence,
            raw={"completion_verdict": verdict.value},
        )
