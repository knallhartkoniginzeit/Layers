from __future__ import annotations

import difflib


def _make_diff(original: list[str], modified: list[str], filename: str = "app.py") -> str:
    """Generate a unified diff string."""
    return "".join(
        difflib.unified_diff(
            original,
            modified,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="\n",
        )
    )


def patch_add_idempotency_key(
    library: str = "requests",
    method: str = "POST",
    url: str = "https://api.example.com/resource",
) -> str:
    """Generate a diff that adds an idempotency key header."""
    if library == "requests":
        original = [
            "import requests\n",
            "\n",
            f"response = requests.{method.lower()}(\n",
            f'    "{url}",\n',
            '    headers={"Content-Type": "application/json"},\n',
            "    json=payload,\n",
            ")\n",
        ]
        modified = [
            "import requests\n",
            "import uuid\n",
            "\n",
            f"response = requests.{method.lower()}(\n",
            f'    "{url}",\n',
            "    headers={\n",
            '        "Content-Type": "application/json",\n',
            '        "Idempotency-Key": str(uuid.uuid4()),\n',
            "    },\n",
            "    json=payload,\n",
            ")\n",
        ]
        return _make_diff(original, modified)
    elif library == "httpx":
        original = [
            "import httpx\n",
            "\n",
            f"response = httpx.{method.lower()}(\n",
            f'    "{url}",\n',
            '    headers={"Content-Type": "application/json"},\n',
            "    json=payload,\n",
            ")\n",
        ]
        modified = [
            "import httpx\n",
            "import uuid\n",
            "\n",
            f"response = httpx.{method.lower()}(\n",
            f'    "{url}",\n',
            "    headers={\n",
            '        "Content-Type": "application/json",\n',
            '        "Idempotency-Key": str(uuid.uuid4()),\n',
            "    },\n",
            "    json=payload,\n",
            ")\n",
        ]
        return _make_diff(original, modified)
    return ""


def patch_add_timeout(
    library: str = "requests",
    timeout_s: int = 30,
) -> str:
    """Generate a diff that adds an explicit timeout."""
    if library == "requests":
        original = [
            "response = requests.get(url)\n",
        ]
        modified = [
            f"response = requests.get(url, timeout={timeout_s})\n",
        ]
        return _make_diff(original, modified)
    elif library == "httpx":
        original = [
            "response = httpx.get(url)\n",
        ]
        modified = [
            f"response = httpx.get(url, timeout={timeout_s})\n",
        ]
        return _make_diff(original, modified)
    return ""


def patch_add_retry_with_backoff(library: str = "requests") -> str:
    """Generate a diff adding retry-with-backoff logic."""
    if library == "requests":
        original = [
            "import requests\n",
            "\n",
            "response = requests.get(url)\n",
        ]
        modified = [
            "import requests\n",
            "from requests.adapters import HTTPAdapter\n",
            "from urllib3.util.retry import Retry\n",
            "\n",
            "session = requests.Session()\n",
            "retries = Retry(\n",
            "    total=3,\n",
            "    backoff_factor=1,\n",
            "    status_forcelist=[429, 500, 502, 503, 504],\n",
            "    respect_retry_after_header=True,\n",
            ")\n",
            'session.mount("https://", HTTPAdapter(max_retries=retries))\n',
            'session.mount("http://", HTTPAdapter(max_retries=retries))\n',
            "\n",
            "response = session.get(url)\n",
        ]
        return _make_diff(original, modified)
    return ""


def patch_unset_proxy(var_name: str = "HTTPS_PROXY") -> str:
    """Generate a shell command diff to unset a bad proxy variable."""
    original = [
        f"# {var_name} is currently set and causing connection failures\n",
    ]
    modified = [
        "# Unset the problematic proxy variable:\n",
        f"# bash:    unset {var_name}\n",
        f"# fish:    set -e {var_name}\n",
        f"# PowerShell: Remove-Item Env:{var_name}\n",
    ]
    return _make_diff(original, modified, filename="env_fix.sh")
