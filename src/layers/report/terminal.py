from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from layers.schemas import ConfidenceBand, Diagnosis


def render_terminal(diagnosis: Diagnosis, console: Console | None = None) -> None:
    if console is None:
        console = Console()

    case = diagnosis.case
    top = diagnosis.top

    method_color = (
        "green" if case.method == "GET" else "yellow" if case.method in ("POST", "PUT") else "cyan"
    )
    status_str = f"HTTP {case.status}" if case.status else (case.error_class or "No Response")
    status_style = (
        "bold red" if (case.status and case.status >= 400) or case.error_class else "bold green"
    )

    title_text = Text.assemble(
        ("layers diagnosis: ", "bold cyan"),
        (f"{case.method} ", f"bold {method_color}"),
        (f"{case.url} ", "white"),
        (f"[{status_str}]", status_style),
    )
    console.print(Panel(title_text, border_style="blue", padding=(0, 1)))

    if top:
        band_colors = {
            ConfidenceBand.HIGH: "bold green",
            ConfidenceBand.MED: "bold yellow",
            ConfidenceBand.LOW: "bold red",
            ConfidenceBand.INCONCLUSIVE: "dim red",
        }
        band_color = band_colors.get(top.band, "white")
        conf_pct = int(top.confidence * 100)

        verdict_text = Text()
        verdict_text.append("Layer: ", style="bold dim")
        verdict_text.append(f"{top.layer.value.upper()}\n", style="bold cyan")
        verdict_text.append("Cause: ", style="bold dim")
        verdict_text.append(f"{top.cause}\n", style="bold white")
        verdict_text.append("Confidence: ", style="bold dim")
        verdict_text.append(f"{conf_pct}% [{top.band.value}]", style=band_color)
        verdict_text.append("  |  Operation Completion: ", style="bold dim")
        verdict_text.append(f"{diagnosis.completion.value}\n", style="bold magenta")

        console.print(
            Panel(
                verdict_text,
                title="[bold]Verdict (Most likely, with evidence)[/bold]",
                border_style="green" if top.band == ConfidenceBand.HIGH else "yellow",
            )
        )
    else:
        console.print(
            Panel(
                "[bold red]Inconclusive diagnosis — no strong hypothesis supported by evidence.[/bold red]",
                border_style="red",
            )
        )

    action = diagnosis.action
    action_table = Table(show_header=False, box=None, padding=(0, 1))
    action_table.add_column("Key", style="bold dim", width=14)
    action_table.add_column("Value")
    action_table.add_row(
        "Recommended:",
        f"[bold cyan]{action.kind.value}[/bold cyan] ({'SAFE' if action.safe else 'CAUTION'})",
    )
    action_table.add_row("Rationale:", action.explanation)
    if action.commands:
        cmds_str = "\n".join(f"[bold green]$[/bold green] {cmd}" for cmd in action.commands)
        action_table.add_row("Inspect:", cmds_str)

    console.print(Panel(action_table, title="[bold]Recovery Action[/bold]", border_style="cyan"))

    if action.patch:
        console.print("[bold cyan]Suggested Patch (review before applying):[/bold cyan]")
        syntax = Syntax(action.patch, "diff", theme="monokai", line_numbers=True)
        console.print(Panel(syntax, border_style="dim"))

    if top and top.evidence:
        ev_table = Table(title="Supporting Evidence", show_header=True, header_style="bold magenta")
        ev_table.add_column("Probe", style="dim", width=18)
        ev_table.add_column("Layer", width=10)
        ev_table.add_column("Finding")
        ev_table.add_column("Weight", justify="right", width=8)

        for ev in top.evidence:
            weight_str = f"{int(ev.strength * 100)}%"
            ev_table.add_row(ev.probe, ev.layer.value, ev.finding, weight_str)
        console.print(ev_table)

    if diagnosis.alternatives:
        alt_table = Table(
            title="Ruled Out / Alternative Hypotheses", show_header=True, header_style="bold dim"
        )
        alt_table.add_column("ID", width=22)
        alt_table.add_column("Layer", width=12)
        alt_table.add_column("Cause")
        alt_table.add_column("Confidence", justify="right", width=12)

        for alt in diagnosis.alternatives[:3]:
            alt_table.add_row(
                alt.id,
                alt.layer.value,
                alt.cause,
                f"{int(alt.confidence * 100)}% ({alt.band.value})",
            )
        console.print(alt_table)

    honesty_table = Table(
        title="Honesty & Limits (What was checked vs skipped)",
        show_header=True,
        header_style="bold yellow",
    )
    honesty_table.add_column("Category", width=16)
    honesty_table.add_column("Details")

    probes_run_str = ", ".join(diagnosis.probes_run) or "None"
    honesty_table.add_row("[green]Probes Run[/green]", probes_run_str)

    if diagnosis.probes_skipped:
        skipped_str = "\n".join(f"- {s}" for s in diagnosis.probes_skipped)
        honesty_table.add_row("[yellow]Probes Skipped[/yellow]", skipped_str)

    if diagnosis.limits:
        limits_str = "\n".join(f"- {item}" for item in diagnosis.limits)
        honesty_table.add_row("[red]Known Limits[/red]", limits_str)

    console.print(honesty_table)
