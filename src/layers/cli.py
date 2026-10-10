from __future__ import annotations

import pathlib
import sys
from typing import Annotated

import typer
from rich.console import Console

from layers.api import diagnose
from layers.packs.registry import get_pack, list_packs
from layers.report.explain import generate_explanation
from layers.report.json_out import render_json
from layers.report.terminal import render_terminal
from layers.schemas import ConfidenceBand, FailureCase

app = typer.Typer(
    name="layers",
    help="Probe each layer of a failed API call and return an evidence-backed diagnosis.",
    no_args_is_help=True,
)
packs_app = typer.Typer(name="packs", help="Manage and inspect provider packs.")
testbed_app = typer.Typer(name="testbed", help="Local fault-injection testbed commands.")
app.add_typer(packs_app)
app.add_typer(testbed_app)

console = Console()
err_console = Console(stderr=True)


@app.command(name="diagnose")
def diagnose_cmd(
    target: Annotated[
        str,
        typer.Argument(help="Path to input file, inline string (curl/HAR/trace), or '-' for stdin"),
    ],
    har: Annotated[bool, typer.Option("--har", help="Parse as HAR input")] = False,
    curl: Annotated[
        bool, typer.Option("--curl", help="Parse as curl command or verbose output")
    ] = False,
    exception: Annotated[
        bool, typer.Option("--exception", help="Parse as Python exception traceback")
    ] = False,
    raw: Annotated[
        bool, typer.Option("--raw", help="Parse as raw HTTP status/headers/body")
    ] = False,
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="Provider pack (e.g., serpapi, openai_compat)"),
    ] = None,
    probe_auth: Annotated[
        bool, typer.Option("--probe-auth", help="Permit authenticated read-only key probes")
    ] = False,
    allow_replay: Annotated[
        bool, typer.Option("--allow-replay", help="Permit live replay of idempotent requests")
    ] = False,
    max_probes: Annotated[int, typer.Option("--max-probes", help="Maximum probes to run")] = 20,
    json_output: Annotated[bool, typer.Option("--json", help="Emit raw JSON report")] = False,
    explain: Annotated[
        bool, typer.Option("--explain", help="Include evidence-backed narrative explanation")
    ] = False,
) -> None:
    """Diagnose a failed API call from curl, HAR, exception trace, or raw HTTP."""
    try:
        if target == "-":
            content = sys.stdin.read()
        else:
            is_file = False
            try:
                p = pathlib.Path(target)
                if p.is_file():
                    is_file = True
                    content = p.read_text(encoding="utf-8-sig")
            except OSError:
                is_file = False
            if not is_file:
                content = target
    except Exception as exc:
        err_console.print(f"[bold red]Failed to read input:[/bold red] {exc}")
        raise typer.Exit(code=2) from None

    input_type = "auto"
    if har:
        input_type = "har"
    elif curl:
        input_type = "curl"
    elif exception:
        input_type = "exception"
    elif raw:
        input_type = "raw"

    try:
        result = diagnose(
            content,
            input_type=input_type,
            provider=provider,
            probe_auth=probe_auth,
            allow_replay=allow_replay,
            max_probes=max_probes,
        )
    except Exception as exc:
        err_console.print(f"[bold red]Diagnosis failed with error:[/bold red] {exc}")
        raise typer.Exit(code=2) from None

    if json_output:
        print(render_json(result))
    else:
        render_terminal(result, console=console)
        if explain:
            console.print("\n[bold cyan]Evidence-Backed Narrative Explanation:[/bold cyan]")
            explanation_text = generate_explanation(result)
            console.print(explanation_text)

    if result.top and result.top.band == ConfidenceBand.HIGH:
        raise typer.Exit(code=0)
    raise typer.Exit(code=1)


@app.command(name="probe")
def probe_cmd(
    probe_name: Annotated[
        str, typer.Argument(help="Probe name (dns, tcp, tls, gateway, proxy_env, lint)")
    ],
    url: Annotated[str, typer.Argument(help="Target URL to probe")],
) -> None:
    """Run a single probe in isolation against a URL."""
    from layers.probes.dns import DnsProbe
    from layers.probes.gateway_fingerprint import GatewayFingerprintProbe
    from layers.probes.proxy_env import ProxyEnvProbe
    from layers.probes.request_lint import RequestLintProbe
    from layers.probes.tcp import TcpProbe
    from layers.probes.tls import TlsProbe

    probe_map = {
        "dns": DnsProbe,
        "tcp": TcpProbe,
        "tls": TlsProbe,
        "gateway": GatewayFingerprintProbe,
        "gateway_fingerprint": GatewayFingerprintProbe,
        "proxy_env": ProxyEnvProbe,
        "lint": RequestLintProbe,
    }

    cls = probe_map.get(probe_name.lower())
    if not cls:
        err_console.print(
            f"[bold red]Unknown probe:[/bold red] {probe_name}. Available: {list(probe_map.keys())}"
        )
        raise typer.Exit(code=2)

    probe_instance = cls()
    dummy_case = FailureCase(method="GET", url=url)
    res = probe_instance.run(dummy_case)

    console.print(f"[bold]Probe:[/bold] {probe_instance.name}")
    console.print(f"[bold]OK:[/bold] {res.ok}")
    if res.skipped:
        console.print(f"[yellow]Skipped:[/yellow] {res.skip_reason}")
    for ev in res.evidence:
        console.print(
            f"- [{ev.layer.value.upper()}] {ev.finding} (strength: {int(ev.strength * 100)}%)"
        )


@packs_app.command(name="list")
def packs_list() -> None:
    """List all registered provider packs."""
    packs = list_packs()
    console.print("[bold cyan]Available Provider Packs:[/bold cyan]")
    for p in packs:
        pack_obj = get_pack(p)
        hosts = ", ".join(pack_obj.hosts) if pack_obj else ""
        console.print(f"- [bold white]{p}[/bold white] (hosts: {hosts})")


@packs_app.command(name="show")
def packs_show(name: Annotated[str, typer.Argument(help="Pack name")]) -> None:
    """Show detailed metadata and rules for a provider pack."""
    pack_obj = get_pack(name)
    if not pack_obj:
        err_console.print(f"[bold red]Pack '{name}' not found.[/bold red]")
        raise typer.Exit(code=2)

    console.print(f"[bold cyan]Pack:[/bold cyan] {pack_obj.name}")
    console.print(f"[bold]Hosts:[/bold] {', '.join(pack_obj.hosts)}")
    console.print("\n[bold]Documented Error Codes:[/bold]")
    for code, desc in pack_obj.error_map().items():
        console.print(f"  {code}: {desc}")
    console.print("\n[bold]Rules Provided:[/bold]")
    for r in pack_obj.rules():
        console.print(f"  - [{r.layer.value.upper()}] {r.id}: {r.cause}")


@app.command(name="eval")
def eval_cmd(
    report_dir: Annotated[
        str | None, typer.Option("--report", help="Directory to save evaluation reports")
    ] = None,
) -> None:
    """Run evaluation benchmark comparing layers against status-code baseline."""
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from eval.run_eval import run_evaluation

    run_evaluation(report_dir=report_dir)


@testbed_app.command(name="up")
def testbed_up() -> None:
    """Start the testbed services via docker compose."""
    import subprocess

    cmd = ["docker", "compose", "-f", "testbed/docker-compose.yml", "up", "-d"]
    console.print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=False)


@testbed_app.command(name="down")
def testbed_down() -> None:
    """Stop the testbed services."""
    import subprocess

    cmd = ["docker", "compose", "-f", "testbed/docker-compose.yml", "down"]
    console.print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=False)


@testbed_app.command(name="run")
def testbed_run(
    scenario: Annotated[
        str | None, typer.Option("--scenario", help="Run specific scenario ID")
    ] = None,
) -> None:
    """Run testbed scenarios."""
    root = pathlib.Path(__file__).resolve().parent.parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from testbed.run import run_testbed_scenarios

    run_testbed_scenarios(scenario_filter=scenario)


if __name__ == "__main__":
    app()
