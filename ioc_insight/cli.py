"""CLI entry — one-shot mode (typer). TRD §9.

`iocinsight <ioc>`           one-shot lookup, rich output
`iocinsight`                 interactive TUI (added in S7b)
`iocinsight --file iocs.txt` bulk lookup
"""
from __future__ import annotations

import asyncio
import json
import sys

import typer
from rich.console import Console

from .config import load_config
from .normalizer import InvalidIOCError
from .pipeline import Pipeline
from .report.cli_render import render_result

app = typer.Typer(add_completion=False, no_args_is_help=False,
                  help="IOC Insight — AI-powered IOC triage for SOC L1.")
console = Console()
err_console = Console(stderr=True)


def _run(coro):
    return asyncio.run(coro)


async def _lookup_once(raw: str, lang: str | None, use_ai: bool,
                       use_cache: bool, as_json: bool, copy: bool):
    config = load_config()
    pipe = Pipeline(config)
    try:
        result = await pipe.lookup(raw, use_cache=use_cache, use_ai=use_ai, lang=lang)
    except InvalidIOCError as e:
        err = {"error": str(e), "input": raw}
        if as_json:
            console.print(json.dumps(err))
        else:
            err_console.print(f"[red]invalid IOC:[/] {e}")
        raise typer.Exit(code=2)
    finally:
        await pipe.close()

    if as_json:
        print(result.model_dump_json())  # plain stdout — pipe-safe, no rich wrapping
        return

    render_result(console, result)
    if copy:
        if result.ai and result.ai.report_markdown:
            _copy_to_clipboard(result.ai.report_markdown)
            console.print("[dim]report copied to clipboard ✓[/]")
        else:
            err_console.print("[yellow]nothing to copy (no AI report)[/]")


def _copy_to_clipboard(text: str) -> None:
    """Best-effort clipboard: wl-copy, xclip, pbcopy — silent no-op if absent."""
    import shutil
    import subprocess
    for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["pbcopy"]):
        if shutil.which(cmd[0]):
            subprocess.run(cmd, input=text.encode(), check=False)
            return


@app.command()
def main(
    ioc: str = typer.Argument(None, help="IOC to look up (IP, domain, URL, hash). "
                                          "Defanged forms OK: hxxp://, [.]."),
    file: str = typer.Option(None, "--file", "-f", help="Bulk lookup: file with one IOC per line."),
    lang: str = typer.Option(None, "--lang", "-l", help="Report language: en | de | id."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI layer; heuristic score only."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass result cache."),
    copy: bool = typer.Option(False, "--copy", help="Copy ticket report to clipboard."),
):
    if file:
        _bulk(file, lang, no_ai, no_cache, json_out)
        return
    if ioc is None:
        from .tui import run_tui
        run_tui()
        return
    _run(_lookup_once(ioc, lang, not no_ai, not no_cache, json_out, copy))


def _bulk(path: str, lang, no_ai, no_cache, json_out):
    try:
        with open(path, encoding="utf-8") as f:
            iocs = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except OSError as e:
        err_console.print(f"[red]cannot read file:[/] {e}")
        raise typer.Exit(code=2)

    async def run_all():
        config = load_config()
        pipe = Pipeline(config)
        results = []
        try:
            for raw in iocs:
                try:
                    r = await pipe.lookup(raw, use_cache=not no_cache,
                                          use_ai=not no_ai, lang=lang)
                    results.append(r)
                except InvalidIOCError as e:
                    err_console.print(f"[yellow]skip {raw!r}: {e}[/]")
        finally:
            await pipe.close()
        return results

    results = _run(run_all())
    if json_out:
        print(json.dumps([r.model_dump(mode="json") for r in results], default=str))
    else:
        console.print(f"\n[bold]Bulk complete:[/] {len(results)}/{len(iocs)} lookups succeeded")
        for r in results:
            verdict = r.ai.verdict.value if r.ai else "—"
            console.print(f"  {r.ioc.value:<40} {r.risk_score:>3}/100  {verdict}")


if __name__ == "__main__":
    app()
