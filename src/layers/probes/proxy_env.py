from __future__ import annotations

import os
from urllib.parse import urlparse

from layers.probes.base import BaseProbe, make_evidence
from layers.schemas import FailureCase, ProbeResult

_PROXY_VARS = (
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)


class ProxyEnvProbe(BaseProbe):
    name = "proxy_env"

    def _run(self, case: FailureCase) -> ProbeResult:
        evidence = []
        proxies_found: dict[str, str] = {}

        for var in _PROXY_VARS:
            val = os.environ.get(var)
            if val:
                proxies_found[var] = val

        if not proxies_found:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    "No proxy environment variables are set",
                    contradicts=["bad_proxy_env"],
                    strength=0.5,
                )
            )
            return ProbeResult(probe=self.name, ok=True, evidence=evidence)

        host = urlparse(case.url).hostname or ""
        no_proxy = os.environ.get("NO_PROXY", os.environ.get("no_proxy", ""))
        no_proxy_list = [h.strip().lower() for h in no_proxy.split(",") if h.strip()]

        host_bypassed = (
            any(host.lower().endswith(np.lstrip(".")) for np in no_proxy_list) if host else False
        )

        for var, val in proxies_found.items():
            if var.upper() in ("NO_PROXY",):
                continue
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"Proxy variable {var}={val} is set",
                    supports=["bad_proxy_env"] if not host_bypassed else [],
                    strength=0.4,
                    raw={"var": var, "val": val, "host_bypassed": host_bypassed},
                )
            )

        if host_bypassed:
            evidence.append(
                make_evidence(
                    self.name,
                    "network",
                    f"Host {host} is in NO_PROXY ({no_proxy}); proxy should be bypassed",
                    contradicts=["bad_proxy_env"],
                    strength=0.6,
                )
            )

        for var, val in proxies_found.items():
            if var.upper() == "NO_PROXY":
                continue
            parsed = urlparse(val)
            if not parsed.hostname:
                evidence.append(
                    make_evidence(
                        self.name,
                        "network",
                        f"Proxy variable {var} has an invalid URL: {val}",
                        supports=["bad_proxy_env"],
                        strength=0.8,
                        raw={"var": var, "val": val},
                    )
                )

        return ProbeResult(
            probe=self.name,
            ok=all(not e.supports for e in evidence),
            evidence=evidence,
        )
