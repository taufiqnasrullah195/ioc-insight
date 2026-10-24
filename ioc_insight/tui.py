"""Interactive TUI control panel (textual). TRD §9 — mockup cli-interactive.png.

Screens: main menu → quick lookup → result actions. Settings/history land in S9.
"""
from __future__ import annotations

import asyncio

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Footer, Header, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from .config import load_config
from .models import LookupResult, Verdict
from .normalizer import InvalidIOCError, refang
from .pipeline import Pipeline

_BANNER = """\
 ██╗ ██████╗  ██████╗    ██╗███╗   ██╗███████╗██╗ ██████╗ ██╗  ██╗████████╗
 ██║██╔═══██╗██╔════╝    ██║████╗  ██║██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
 ██║██║   ██║██║         ██║██╔██╗ ██║███████╗██║██║  ███╗███████║   ██║
 ██║██║   ██║██║         ██║██║╚██╗██║╚════██║██║██║   ██║██╔══██║   ██║
 ██║╚██████╔╝╚██████╗    ██║██║ ╚████║███████║██║╚██████╔╝██║  ██║   ██║
 ╚═╝ ╚═════╝  ╚═════╝    ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝"""

_MENU = [
    ("Quick Lookup — paste IOC, get verdict", "lookup"),
    ("History — past lookups", "history"),
    ("Analyzer Status — quotas & health (S10)", "status"),
    ("Settings — language, AI model, cache (S10)", "settings"),
    ("Quit", "quit"),
]

_VCOLOR = {Verdict.MALICIOUS: "red", Verdict.SUSPICIOUS: "yellow",
           Verdict.CLEAN: "green", Verdict.UNKNOWN: "white"}


class IOCInsightApp(App):
    CSS = """
    #banner { color: $accent; text-style: bold; }
    #status { color: $text-muted; }
    #verdict { padding: 1 2; border: round $primary; }
    .malicious { border: round red; }
    .suspicious { border: round yellow; }
    .clean { border: round green; }
    #report { border: round $surface-lighten-2; padding: 1 2; }
    """
    BINDINGS = [Binding("q", "quit", "Quit"), Binding("escape", "back", "Back")]

    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.pipeline: Pipeline | None = None
        self.last_result: LookupResult | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(_BANNER, id="banner")
        yield Static(
            f"v0.1 · SOC L1 IOC Triage · ai: {self.config.ai.model} · "
            f"lang: {self.config.defaults.lang}",
            id="status",
        )
        yield OptionList(*[Option(label, id=key) for label, key in _MENU], id="menu")
        yield Input(placeholder="IOC ❯ (hxxp://, [.] defanged OK)", id="ioc_input")
        yield Static("", id="verdict")
        yield Static("", id="report")
        yield OptionList(id="actions")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#ioc_input").display = False
        self.query_one("#actions").display = False
        self.query_one("#verdict").display = False
        self.query_one("#report").display = False
        self.query_one("#menu").focus()

    async def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "menu":
            await self._menu_select(event.option.id)
        elif event.option_list.id == "actions":
            await self._action_select(event.option.id)

    async def _menu_select(self, key: str | None) -> None:
        if key == "quit":
            self.exit()
        elif key == "lookup":
            self.query_one("#menu").display = False
            inp = self.query_one("#ioc_input")
            inp.display = True
            inp.focus()
        elif key == "history":
            self._show_history()
        else:
            self.query_one("#status").update(
                f"[{key}] arrives in S10 — pick Quick Lookup or History for now")

    def _show_history(self) -> None:
        if self.pipeline is None:
            self.pipeline = Pipeline(self.config)
        data = self.pipeline.history.list(limit=30)
        report = self.query_one("#report")
        report.display = True
        if not data["items"]:
            report.update("History is empty — run a lookup first.")
        else:
            lines = [f"History — {data['total']} lookups (newest first)", ""]
            for it in data["items"]:
                verdict = it["verdict"] or "—"
                lines.append(
                    f"  #{it['id']:<4} {it['ioc_value']:<32} "
                    f"{it['risk_score']:>3}/100  {verdict:<10} {it['lang'] or '—'}"
                )
            report.update("\n".join(lines))
        self.query_one("#status").update("esc to go back")
        menu = self.query_one("#menu")
        menu.display = False

    def action_back(self) -> None:
        self._show_menu()
        self.query_one("#status").update(
            f"v0.1 · SOC L1 IOC Triage · ai: {self.config.ai.model} · "
            f"lang: {self.config.defaults.lang}")

    @on(Input.Submitted, "#ioc_input")
    def on_ioc_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        if not raw:
            return
        event.input.display = False
        self.query_one("#status").update(f"⠿ enriching… ({refang(raw)})")
        self._do_lookup(raw)

    @work(exclusive=True)
    async def _do_lookup(self, raw: str) -> None:
        if self.pipeline is None:
            self.pipeline = Pipeline(self.config)
        try:
            result = await self.pipeline.lookup(raw)
        except InvalidIOCError as e:
            self.query_one("#status").update(f"invalid IOC: {e}")
            self._show_menu()
            return
        self.last_result = result
        self._render_result(result)

    def _render_result(self, r: LookupResult) -> None:
        ai = r.ai
        verdict = ai.verdict if ai else None
        vwidget = self.query_one("#verdict")
        vwidget.display = True
        color = _VCOLOR.get(verdict, "white") if verdict else "white"
        text = (
            f"■ {verdict.value}  confidence {ai.confidence}%   score {r.risk_score}/100\n"
            f"Action: {ai.recommended_action.value}\n\n{ai.explanation}"
        ) if ai else f"score {r.risk_score}/100 (no AI)"
        vwidget.update(text)
        vwidget.set_class(verdict == Verdict.MALICIOUS, "malicious")
        vwidget.set_class(verdict == Verdict.SUSPICIOUS, "suspicious")
        vwidget.set_class(verdict == Verdict.CLEAN, "clean")

        lines = []
        for res in r.analyzer_results:
            if r and r.success and r.source == "whois_age":
                lines.append(f"  {res.source:<11} age {res.malicious_votes}d")
            elif res.success:
                lines.append(f"  {res.source:<11} votes={res.malicious_votes} "
                             f"score={res.reputation_score}")
            else:
                lines.append(f"  {res.source:<11} {res.error}")
        self.query_one("#report").display = True
        self.query_one("#report").update("Sources:\n" + "\n".join(lines))

        actions = self.query_one("#actions")
        actions.display = True
        actions.clear_options()
        actions.add_options([
            Option("Copy ticket report", id="copy"),
            Option("View raw JSON", id="json"),
            Option("New lookup", id="new"),
            Option("Main menu", id="menu"),
        ])
        actions.focus()
        self.query_one("#status").update(f"done in {r.duration_ms}ms")

    async def _action_select(self, key: str | None) -> None:
        if key == "new":
            self._reset_to_input()
        elif key == "menu":
            self._show_menu()
        elif key == "copy" and self.last_result and self.last_result.ai:
            from .cli import _copy_to_clipboard
            _copy_to_clipboard(self.last_result.ai.report_markdown)
            self.query_one("#status").update("report copied ✓")
        elif key == "json" and self.last_result:
            self.query_one("#report").update(
                self.last_result.model_dump_json(indent=2))

    def _reset_to_input(self) -> None:
        for sel in ("#verdict", "#report", "#actions"):
            self.query_one(sel).display = False
        inp = self.query_one("#ioc_input")
        inp.value = ""
        inp.display = True
        inp.focus()

    def _show_menu(self) -> None:
        for sel in ("#verdict", "#report", "#actions", "#ioc_input"):
            self.query_one(sel).display = False
        menu = self.query_one("#menu")
        menu.display = True
        menu.focus()

    async def on_unmount(self) -> None:
        if self.pipeline:
            await self.pipeline.close()


def run_tui() -> None:
    IOCInsightApp().run()
