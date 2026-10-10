from __future__ import annotations

from urllib.parse import urlparse

import dns.exception
import dns.resolver

from layers.config import settings
from layers.probes.base import BaseProbe, make_evidence
from layers.schemas import FailureCase, ProbeResult


class DnsProbe(BaseProbe):
    name = "dns"

    def _run(self, case: FailureCase) -> ProbeResult:
        host = urlparse(case.url).hostname or ""

        if case.status is not None:
            return ProbeResult(
                probe=self.name,
                ok=True,
                evidence=[
                    make_evidence(
                        self.name,
                        "network",
                        f"HTTP {case.status} response was received — DNS resolution succeeded for this call",
                        contradicts=["dns_failure"],
                        strength=0.95,
                        raw={"host": host, "status": case.status},
                    )
                ],
            )

        evidence = []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = settings.probe.dns_timeout

        try:
            answers = resolver.resolve(host, "A")
            ips = [str(r) for r in answers]
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"DNS resolved {host} -> {', '.join(ips)}",
                    contradicts=["dns_failure"],
                    strength=0.8,
                    raw={"host": host, "ips": ips},
                )
            )
        except dns.resolver.NXDOMAIN:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"DNS: {host} does not exist (NXDOMAIN)",
                    supports=["dns_failure"],
                    strength=1.0,
                    raw={"host": host, "error": "NXDOMAIN"},
                )
            )
        except dns.resolver.NoNameservers:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"DNS: no nameservers available for {host}",
                    supports=["dns_failure"],
                    strength=0.9,
                    raw={"host": host, "error": "NoNameservers"},
                )
            )
        except dns.exception.Timeout:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"DNS lookup for {host} timed out",
                    supports=["dns_failure", "network_timeout"],
                    strength=0.7,
                    raw={"host": host, "error": "Timeout"},
                )
            )
        except dns.resolver.NoAnswer:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"DNS: no A records for {host} (NoAnswer)",
                    supports=["dns_failure"],
                    strength=0.8,
                    raw={"host": host, "error": "NoAnswer"},
                )
            )

        return ProbeResult(
            probe=self.name,
            ok=all(not e.supports for e in evidence),
            evidence=evidence,
        )
