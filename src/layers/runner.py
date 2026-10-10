from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

from layers.probes.completion import CompletionProbe
from layers.probes.credentials import CredentialsProbe
from layers.probes.dns import DnsProbe
from layers.probes.gateway_fingerprint import GatewayFingerprintProbe
from layers.probes.provider_status import ProviderStatusProbe
from layers.probes.proxy_env import ProxyEnvProbe
from layers.probes.request_lint import RequestLintProbe
from layers.probes.tcp import TcpProbe
from layers.probes.tls import TlsProbe
from layers.safety import ProbeBudget
from layers.schemas import CompletionVerdict, Evidence, FailureCase, ProbeResult

if TYPE_CHECKING:
    from layers.packs.base import ProviderPack


class ProbeRunnerResult:
    def __init__(self) -> None:
        self.evidence: list[Evidence] = []
        self.probes_run: list[str] = []
        self.probes_skipped: list[str] = []
        self.limits: list[str] = []
        self.completion: CompletionVerdict = CompletionVerdict.UNKNOWN


class ProbeRunner:
    def __init__(
        self,
        pack: ProviderPack | None = None,
        probe_auth: bool = False,
        allow_replay: bool = False,
        max_probes: int | None = None,
    ) -> None:
        self.pack = pack
        self.probe_auth = probe_auth
        self.allow_replay = allow_replay
        self.budget = ProbeBudget(max_probes=max_probes)

    def run(self, case: FailureCase) -> ProbeRunnerResult:
        result = ProbeRunnerResult()
        parsed = urlparse(case.url)
        host = parsed.hostname or ""

        result.limits.append(
            "Client-side perspective only: no server-side internal logs or packet captures inspected."
        )
        if not self.probe_auth:
            result.limits.append(
                "Credential verification probe disabled (use --probe-auth to test credentials)."
            )
        if not self.allow_replay:
            result.limits.append(
                "Live request replay disabled (use --allow-replay for idempotent replay)."
            )

        self._execute_probe(RequestLintProbe(), case, "", result)
        lint_fatal = any(
            e.strength >= 0.9 and "malformed_request" in e.supports for e in result.evidence
        )
        if lint_fatal:
            result.probes_skipped.append("network.*: skipped because request is fatally malformed")
            result.probes_skipped.append(
                "credentials: skipped because request is fatally malformed"
            )
            return result

        dns_res = self._execute_probe(DnsProbe(), case, "", result)
        dns_failed = any(
            "dns_failure" in e.supports and e.strength >= 0.9
            for e in (dns_res.evidence if dns_res else [])
        )
        if dns_failed and case.status is None:
            result.probes_skipped.append("tcp: skipped due to DNS resolution failure")
            result.probes_skipped.append("tls: skipped due to DNS resolution failure")
            result.probes_skipped.append(
                "gateway_fingerprint: skipped due to DNS resolution failure"
            )
            result.probes_skipped.append("credentials: skipped due to DNS resolution failure")
            result.limits.append(
                f"Hostname {host} does not resolve; network transport probes stopped."
            )
            return result

        tcp_res = self._execute_probe(TcpProbe(), case, host, result)
        tcp_failed = any(
            ("connection_refused" in e.supports or "tcp_unreachable" in e.supports)
            and e.strength >= 0.9
            for e in (tcp_res.evidence if tcp_res else [])
        )
        if tcp_failed and case.status is None:
            result.probes_skipped.append("tls: skipped due to TCP connection failure")
            result.probes_skipped.append(
                "gateway_fingerprint: skipped due to TCP connection failure"
            )
            result.probes_skipped.append("credentials: skipped due to TCP connection failure")
            result.limits.append(
                f"TCP socket could not connect to {host}; TLS and application probes stopped."
            )
            return result

        if parsed.scheme == "https":
            tls_res = self._execute_probe(TlsProbe(), case, host, result)
            tls_failed = any(
                (
                    "tls_expired" in e.supports
                    or "tls_hostname_mismatch" in e.supports
                    or "tls_broken_chain" in e.supports
                )
                and e.strength >= 0.9
                for e in (tls_res.evidence if tls_res else [])
            )
            if tls_failed and case.status is None:
                result.probes_skipped.append(
                    "gateway_fingerprint: skipped due to TLS verification failure"
                )
                result.probes_skipped.append("credentials: skipped due to TLS verification failure")
                result.limits.append(
                    f"TLS handshake failed for {host}; higher-level probes stopped."
                )
                return result
        else:
            result.probes_skipped.append("tls: skipped (non-HTTPS URL)")

        self._execute_probe(ProxyEnvProbe(), case, "", result)

        self._execute_probe(GatewayFingerprintProbe(), case, "", result)

        if self.pack:
            try:
                status_probe = self.pack.status_probe()
                self._execute_probe(status_probe, case, "", result)
            except Exception as e:
                result.probes_skipped.append(
                    f"provider_status: failed to run pack status probe ({e})"
                )
        else:
            self._execute_probe(ProviderStatusProbe(), case, "", result)

        auth_probe = None
        if self.pack:
            try:
                auth_probe = self.pack.auth_probe(case)
            except Exception:
                auth_probe = None
        if auth_probe is None:
            auth_probe = CredentialsProbe()

        self._execute_probe(auth_probe, case, host if self.probe_auth else "", result)
        if not self.probe_auth:
            result.probes_skipped.append(
                "credentials (live): requires explicit --probe-auth flag and valid key"
            )

        comp_probe = None
        if self.pack:
            try:
                comp_probe = self.pack.completion_probe(case)
            except Exception:
                comp_probe = None

        if comp_probe is None:
            comp_probe = CompletionProbe()

        comp_res = self._execute_probe(comp_probe, case, "", result)
        if comp_res and comp_res.raw and "completion_verdict" in comp_res.raw:
            try:
                result.completion = CompletionVerdict(comp_res.raw["completion_verdict"])
            except ValueError:
                result.completion = CompletionVerdict.UNKNOWN
        else:
            result.completion = CompletionVerdict.UNKNOWN

        return result

    def _execute_probe(
        self,
        probe: object,
        case: FailureCase,
        host: str,
        result: ProbeRunnerResult,
    ) -> ProbeResult | None:
        probe_name = getattr(probe, "name", str(probe))
        try:
            self.budget.consume(probe_name, host=host if host else None)
        except Exception as e:
            result.probes_skipped.append(f"{probe_name}: budget exhausted or rate limit hit ({e})")
            return None

        try:
            run_fn = getattr(probe, "run", None)
            if not callable(run_fn):
                result.probes_skipped.append(f"{probe_name}: probe object is not runnable")
                return None
            res: ProbeResult = run_fn(case)
            if res.skipped:
                result.probes_skipped.append(f"{probe_name}: {res.skip_reason or 'skipped'}")
            else:
                result.probes_run.append(probe_name)
                result.evidence.extend(res.evidence)
            return res
        except Exception as exc:
            result.probes_skipped.append(f"{probe_name}: crashed ({exc})")
            return None
