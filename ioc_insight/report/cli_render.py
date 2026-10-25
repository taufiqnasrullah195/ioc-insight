"""Rich terminal rendering for one-shot CLI mode. TRD §9 report/cli_render."""
from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import LookupResult, Verdict

_VERDICT_COLOR = {
    Verdict.MALICIOUS: "red",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.CLEAN: "green",
    Verdict.UNKNOWN: "white",
}


def render_result(console: Console, result) -> None:
    """Full one-shot output: verdict panel, sources table, ticket report."""
    ioc = result.ioc
    ai = result.ai
    verdict = ai.verdict if ai else None
    color = _VERDICT_COLOR.get(verdict, "white") if verdict else "white"

    # --- verdict panel ---
    head = Text()
    if verdict:
        head.append(f"■ {verdict.value}", style=f"bold {color}")
        head.append(f"  confidence {ai.confidence}%", style="dim")
        head.append(f"   score {result.risk_score}/100", style=f"bold {color}")
    else:
        head.append(f"score {result.risk_score}/100", style="bold")
    body = Text()
    if ai:
        body.append(f"\n⛨ Action: ", style="dim")
        body.append(f"{ai.recommended_action.value}", style=f"bold {color}")
        body.append(f"\n{ai.explanation}", style="")
    console.print(Panel(body, title=f"[bold]{ioc.value}[/] ({ioc.type})",
                        subtitle=head, border_style=color, padding=(0, 1)))

    # --- sources table ---
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Source", style="cyan")
    table.add_column("Result")
    table.add_column("Status", justify="right")
    table.add_column("Fresh", justify="right")
    for r in result.analyzer_results:
        if r.success:
            if r.source == "whois_age":
                res = f"age {r.malicious_votes}d"
            elif r.source == "abuseipdb":
                res = f"{r.reputation_score:.0f}% · {r.malicious_votes} reports"
            elif r.source == "otx":
                res = f"{r.malicious_votes} pulses"
            else:
                res = f"{r.malicious_votes}/{r.total_engines} engines"
            status = "[green]ok[/]"
        else:
            res = f"[dim]{r.error or 'unavailable'}[/]"
            status = "[dim]skipped[/]" if "skipped" in (r.error or "") else "[red]error[/]"
        fresh = "[dim]cached[/]" if r.from_cache else "live"
        table.add_row(r.source, res, status, fresh)
    console.print(table)

    # --- ticket report ---
    if ai and ai.report_markdown:
        console.print(Panel(Markdown(ai.report_markdown), title="📋 Ticket Report",
                            border_style="dim", padding=(0, 1)))
    if result.mitre:
        console.print("[bold]MITRE ATT&CK:[/] " + "  ".join(
            f"[cyan]{t['id']}[/] {t['name']}" for t in result.mitre))
    console.print(
        f"[dim]lookup took {result.duration_ms}ms"
        + (f" · ai: {ai.model} · {ai.lang}" if ai else " · ai: off")
        + "[/]"
    )
