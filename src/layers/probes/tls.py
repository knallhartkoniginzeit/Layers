from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any, cast
from urllib.parse import urlparse

from layers.config import settings
from layers.probes.base import BaseProbe, make_evidence
from layers.schemas import FailureCase, ProbeResult


class TlsProbe(BaseProbe):
    name = "tls"

    def _run(self, case: FailureCase) -> ProbeResult:
        if case.status is not None:
            return ProbeResult(
                probe=self.name,
                ok=True,
                evidence=[
                    make_evidence(
                        self.name,
                        "network",
                        f"HTTP {case.status} response was received — TLS handshake succeeded for this call",
                        contradicts=["tls_expired", "tls_hostname_mismatch", "tls_broken_chain"],
                        strength=0.95,
                        raw={"status": case.status},
                    )
                ],
            )

        parsed = urlparse(case.url)
        if parsed.scheme != "https":
            return ProbeResult(
                probe=self.name,
                ok=True,
                skipped=True,
                skip_reason="Not an HTTPS URL; TLS probe not applicable",
            )

        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return ProbeResult(
                probe=self.name,
                ok=False,
                skipped=True,
                skip_reason="No hostname in URL",
            )

        evidence = []
        timeout = settings.probe.tls_timeout

        ctx = ssl.create_default_context()

        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=host) as ssock,
            ):
                cert = ssock.getpeercert()
                if cert:
                    not_after_str = str(cert.get("notAfter", ""))
                    if not_after_str:
                        not_after = datetime.datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                        )
                        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
                        days_left = (not_after - now).days

                        if days_left < 0:
                            evidence.append(
                                make_evidence(
                                    self.name,
                                    "network",
                                    f"TLS certificate for {host} expired {abs(days_left)} days ago",
                                    supports=["tls_expired"],
                                    strength=1.0,
                                    raw={"not_after": not_after_str, "days_left": days_left},
                                )
                            )
                        elif days_left < 7:
                            evidence.append(
                                make_evidence(
                                    self.name,
                                    "network",
                                    f"TLS certificate for {host} expires in {days_left} days",
                                    supports=["tls_expiring_soon"],
                                    strength=0.3,
                                    raw={"not_after": not_after_str, "days_left": days_left},
                                )
                            )
                        else:
                            evidence.append(
                                make_evidence(
                                    self.name,
                                    "network",
                                    f"TLS certificate for {host} valid ({days_left} days remaining)",
                                    contradicts=["tls_expired"],
                                    strength=0.8,
                                    raw={"not_after": not_after_str, "days_left": days_left},
                                )
                            )

                    raw_sans = cast(list[tuple[Any, Any]], cert.get("subjectAltName", []))
                    sans = [str(v) for typ, v in raw_sans if str(typ) == "DNS"]
                    evidence.append(
                        make_evidence(
                            self.name,
                            "network",
                            f"TLS handshake succeeded, SANs: {', '.join(sans[:5])}",
                            contradicts=["tls_hostname_mismatch", "tls_broken_chain"],
                            strength=0.8,
                            raw={"sans": sans},
                        )
                    )
        except ssl.SSLCertVerificationError as exc:
            msg = str(exc)
            if "hostname mismatch" in msg.lower():
                evidence.append(
                    make_evidence(
                        self.name,
                        "network",
                        f"TLS hostname mismatch for {host}: {msg}",
                        supports=["tls_hostname_mismatch"],
                        strength=1.0,
                        raw={"error": msg},
                    )
                )
            elif "certificate has expired" in msg.lower() or "expired" in msg.lower():
                evidence.append(
                    make_evidence(
                        self.name,
                        "network",
                        f"TLS certificate expired for {host}: {msg}",
                        supports=["tls_expired"],
                        strength=1.0,
                        raw={"error": msg},
                    )
                )
            else:
                evidence.append(
                    make_evidence(
                        self.name,
                        "network",
                        f"TLS verification failed for {host}: {msg}",
                        supports=["tls_broken_chain"],
                        strength=0.9,
                        raw={"error": msg},
                    )
                )
        except ssl.SSLError as exc:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"TLS error connecting to {host}: {exc}",
                    supports=["tls_broken_chain"],
                    strength=0.8,
                    raw={"error": str(exc)},
                )
            )
        except (TimeoutError, OSError) as exc:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"Could not complete TLS handshake with {host}:{port}: {exc}",
                    supports=["tls_broken_chain", "network_timeout"],
                    strength=0.6,
                    raw={"error": str(exc)},
                )
            )

        return ProbeResult(
            probe=self.name,
            ok=all(not e.supports for e in evidence),
            evidence=evidence,
        )
