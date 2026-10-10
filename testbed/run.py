from __future__ import annotations

import pathlib
import sys

import yaml
from rich.console import Console
from rich.table import Table

from layers.api import diagnose
from layers.schemas import FailureCase

console = Console()


def run_testbed_scenarios(scenario_filter: str | None = None) -> None:
    scenario_dir = pathlib.Path(__file__).parent / "scenarios"
    files = sorted(scenario_dir.glob("*.yaml"))

    if scenario_filter:
        files = [f for f in files if scenario_filter.lower() in f.name.lower()]

    if not files:
        console.print(f"[bold yellow]No scenarios found matching '{scenario_filter}'[/bold yellow]")
        return

    table = Table(title="Testbed Scenarios Run", show_header=True)
    table.add_column("Scenario", style="cyan")
    table.add_column("Expected Layer", width=14)
    table.add_column("Diagnosed Layer", width=14)
    table.add_column("Confidence", justify="right", width=12)
    table.add_column("Result", justify="center", width=8)

    passed = 0
    total = len(files)

    for f in files:
        with open(f, encoding="utf-8") as fp:
            data = yaml.safe_load(fp)

        sc_id = data.get("id", f.stem)
        req = data.get("request", {})
        resp = data.get("response", {})
        exp = data.get("expected", {})

        headers = {k: v for k, v in req.get("headers", {}).items()}
        resp_headers = {k: v for k, v in resp.get("headers", {}).items()}

        case = FailureCase(
            method=req.get("method", "GET"),
            url=req.get("url", "https://api.example.com/"),
            request_headers=headers,
            request_body_sample=req.get("body"),
            status=resp.get("status"),
            response_headers=resp_headers,
            response_body_sample=resp.get("body"),
            error_class=resp.get("error_class"),
            elapsed_ms=float(resp.get("elapsed_ms")) if resp.get("elapsed_ms") else None,
            idempotent=req.get("method", "GET") in ("GET", "HEAD", "PUT", "DELETE"),
            has_idempotency_key="idempotency-key" in {k.lower() for k in headers},
        )

        diagnosis = diagnose(case)
        diag_layer = diagnosis.top.layer.value if diagnosis.top else "unknown"
        exp_layer = exp.get("layer", "unknown")

        ok = diag_layer.lower() == exp_layer.lower()
        if ok:
            passed += 1

        conf_str = f"{int((diagnosis.top.confidence if diagnosis.top else 0) * 100)}%"
        status_badge = "[bold green]PASS[/bold green]" if ok else "[bold red]FAIL[/bold red]"
        table.add_row(sc_id, exp_layer, diag_layer, conf_str, status_badge)

    console.print(table)
    console.print(
        f"\n[bold]Summary:[/bold] {passed}/{total} scenarios matched expected layer ({passed / total * 100:.1f}%)"
    )


if __name__ == "__main__":
    filter_arg = sys.argv[1] if len(sys.argv) > 1 else None
    run_testbed_scenarios(filter_arg)
