from __future__ import annotations

from layers.schemas import Diagnosis


def render_markdown(diagnosis: Diagnosis) -> str:
    case = diagnosis.case
    top = diagnosis.top
    action = diagnosis.action

    status_str = f"HTTP {case.status}" if case.status else (case.error_class or "No Response")
    conf_pct = int(top.confidence * 100) if top else 0
    band_str = top.band.value if top else "N/A"

    lines: list[str] = [
        f"# layers Diagnosis: `{case.method} {case.url}`",
        "",
        f"**Status / Error**: `{status_str}` | **Time**: `{case.elapsed_ms or 0:.0f} ms`",
        "",
        "## Verdict (Most likely, with evidence)",
        "",
        f"- **Layer**: `{top.layer.value.upper() if top else 'UNKNOWN'}`",
        f"- **Cause**: {top.cause if top else 'Inconclusive'}",
        f"- **Confidence**: `{conf_pct}%` ({band_str})",
        f"- **Completion Status**: `{diagnosis.completion.value}`",
        "",
        "## Safe Recovery Action",
        "",
        f"- **Action**: `{action.kind.value}` ({'SAFE' if action.safe else 'CAUTION'})",
        f"- **Rationale**: {action.explanation}",
    ]

    if action.commands:
        lines.append("")
        lines.append("### Diagnostic Commands")
        lines.append("```bash")
        for cmd in action.commands:
            lines.append(cmd)
        lines.append("```")

    if action.patch:
        lines.append("")
        lines.append("### Suggested Patch (Review Before Applying)")
        lines.append("```diff")
        lines.append(action.patch.strip())
        lines.append("```")

    if top and top.evidence:
        lines.append("")
        lines.append("## Supporting Evidence")
        lines.append("")
        lines.append("| Probe | Layer | Finding | Strength |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for ev in top.evidence:
            lines.append(
                f"| `{ev.probe}` | `{ev.layer.value}` | {ev.finding} | {int(ev.strength * 100)}% |"
            )

    if diagnosis.alternatives:
        lines.append("")
        lines.append("## Alternative Hypotheses Considered")
        lines.append("")
        lines.append("| ID | Layer | Cause | Confidence |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for alt in diagnosis.alternatives[:3]:
            lines.append(
                f"| `{alt.id}` | `{alt.layer.value}` | {alt.cause} | {int(alt.confidence * 100)}% |"
            )

    lines.append("")
    lines.append("## Honesty & Known Limits")
    lines.append("")
    lines.append(f"- **Probes Run**: {', '.join(f'`{p}`' for p in diagnosis.probes_run) or 'None'}")
    if diagnosis.probes_skipped:
        lines.append("- **Probes Skipped**:")
        for s in diagnosis.probes_skipped:
            lines.append(f"  - {s}")
    if diagnosis.limits:
        lines.append("- **Limits**:")
        for item in diagnosis.limits:
            lines.append(f"  - {item}")

    return "\n".join(lines)
