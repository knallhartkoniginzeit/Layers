from __future__ import annotations

import socket
from urllib.parse import urlparse

from layers.config import settings
from layers.probes.base import BaseProbe, make_evidence
from layers.schemas import FailureCase, ProbeResult

_DEFAULT_PORTS = {"https": 443, "http": 80}


class TcpProbe(BaseProbe):
    name = "tcp"

    def _run(self, case: FailureCase) -> ProbeResult:
        parsed = urlparse(case.url)
        host = parsed.hostname
        port = parsed.port or _DEFAULT_PORTS.get(parsed.scheme, 443)

        if case.status is not None:
            return ProbeResult(
                probe=self.name,
                ok=True,
                evidence=[
                    make_evidence(
                        self.name,
                        "network",
                        f"HTTP {case.status} response was received — TCP connection succeeded for this call",
                        contradicts=["connection_refused", "tcp_unreachable"],
                        strength=0.95,
                        raw={"host": host, "port": port, "status": case.status},
                    )
                ],
            )

        if not host:
            return ProbeResult(
                probe=self.name,
                ok=False,
                skipped=True,
                skip_reason="No hostname could be extracted from the URL",
            )

        evidence = []
        timeout = settings.probe.tcp_timeout

        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"TCP connection to {host}:{port} succeeded",
                    contradicts=["connection_refused", "tcp_unreachable"],
                    strength=0.8,
                    raw={"host": host, "port": port, "connected": True},
                )
            )
        except ConnectionRefusedError:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"TCP connection to {host}:{port} refused",
                    supports=["connection_refused"],
                    strength=1.0,
                    raw={"host": host, "port": port, "error": "ConnectionRefused"},
                )
            )
        except TimeoutError:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"TCP connection to {host}:{port} timed out after {timeout}s",
                    supports=["tcp_unreachable", "network_timeout"],
                    strength=0.8,
                    raw={"host": host, "port": port, "error": "Timeout"},
                )
            )
        except OSError as exc:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"TCP connection to {host}:{port} failed: {exc}",
                    supports=["tcp_unreachable"],
                    strength=0.7,
                    raw={"host": host, "port": port, "error": str(exc)},
                )
            )

        return ProbeResult(
            probe=self.name,
            ok=all(not e.supports for e in evidence),
            evidence=evidence,
        )
