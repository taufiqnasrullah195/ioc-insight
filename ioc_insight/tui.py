"""Interactive TUI control panel (textual). TRD §9 — mockup cli-interactive.png.

Simple run: `iocinsight` (no args) → full menu. All menus functional:
Quick Lookup, Bulk Lookup, History, Analyzer Status, Settings, Quit.
"""
from __future__ import annotations

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, Input, OptionList, Static
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
    ("Bulk Lookup — file with one IOC per line", "bulk"),
    ("History — past lookups", "history"),
    ("Ask AI — question over lookup history", "ask"),
    ("Analyzer Status — quotas & health", "status"),
    ("Settings — language, cache", "settings"),
    ("Quit", "quit"),
]

_SETTINGS_MENU = [
    ("Language: {lang}  (toggle en → de → id)", "lang"),
    ("Clear cache", "clear_cache"),
    ("Back", "back"),
]

_ACTION_MENU = [
    ("Copy ticket report", "copy"),
    ("View raw JSON", "json"),
    ("New lookup", "new"),
    ("Main menu", "menu"),
]

_LANGS = ["en", "de", "id"]

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
        self.mode: str = "lookup"  # lookup | ask

    # ---------- layout ----------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(_BANNER, id="banner")
        yield Static(self._status_line(), id="status")
        yield OptionList(*[Option(label, id=key) for label, key in _MENU], id="menu")
        yield Input(placeholder="IOC ❯ (hxxp://, [.] defanged OK)", id="ioc_input")
        yield Static("", id="verdict")
        yield Static("", id="report")
        yield OptionList(id="actions")
        yield Footer()

    def on_mount(self) -> None:
        for sel in ("#ioc_input", "#actions", "#verdict", "#report"):
            self.query_one(sel).display = False
        self.query_one("#menu").focus()

    def _status_line(self) -> str:
        return (f"v0.1 · built by TheWiseParadise · ai: {self.config.ai.model} · "
                f"lang: {self.config.defaults.lang}")

    def _ensure_pipeline(self) -> Pipeline:
        if self.pipeline is None:
            self.pipeline = Pipeline(self.config)
        return self.pipeline

    def _hide_all(self) -> None:
        for sel in ("#menu", "#ioc_input", "#verdict", "#report", "#actions"):
            self.query_one(sel).display = False

    def _show_menu(self) -> None:
        self._hide_all()
        menu = self.query_one("#menu")
        menu.display = True
        menu.focus()
        self.query_one("#status").update(self._status_line())

    def action_back(self) -> None:
        self._show_menu()

    # ---------- main menu ----------

    async def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        lid = event.option_list.id
        if lid == "menu":
            await self._menu_select(event.option.id)
        elif lid == "actions":
            await self._action_select(event.option.id)
        elif lid == "settings_menu":
            await self._settings_select(event.option.id)

    async def _menu_select(self, key: str | None) -> None:
        if key == "quit":
            self.exit()
        elif key == "lookup":
            self.mode = "lookup"
            self._hide_all()
            inp = self.query_one("#ioc_input")
            inp.placeholder = "IOC ❯ (hxxp://, [.] defanged OK)"
            inp.display = True
            inp.focus()
        elif key == "bulk":
            self._run_bulk()
        elif key == "history":
            self._show_history()
        elif key == "ask":
            self._show_ask()
        elif key == "status":
            self._show_status()
        elif key == "settings":
            self._show_settings()

    # ---------- quick lookup ----------

    @on(Input.Submitted, "#ioc_input")
    def on_ioc_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        if not raw:
            return
        event.input.display = False
        if self.mode == "ask":
            self._do_ask(raw)
        else:
            self.query_one("#status").update(f"⠿ enriching… ({refang(raw)})")
            self._do_lookup(raw)

    @work(exclusive=True)
    async def _do_lookup(self, raw: str) -> None:
        pipe = self._ensure_pipeline()
        try:
            result = await pipe.lookup(raw)
        except InvalidIOCError as e:
            self.query_one("#status").update(f"invalid IOC: {e}")
            self._show_menu()
            return
        self.last_result = result
        self._render_result(result)

    def _render_result(self, r: LookupResult) -> None:
        self._hide_all()
        ai = r.ai
        verdict = ai.verdict if ai else None
        vwidget = self.query_one("#verdict")
        vwidget.display = True
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
            if res.success and res.source == "whois_age":
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
        actions.add_options([Option(label, id=key) for label, key in _ACTION_MENU])
        actions.focus()
        self.query_one("#status").update(f"done in {r.duration_ms}ms")

    async def _action_select(self, key: str | None) -> None:
        if key == "new":
            self._hide_all()
            inp = self.query_one("#ioc_input")
            inp.value = ""
            inp.display = True
            inp.focus()
        elif key == "menu":
            self._show_menu()
        elif key == "copy" and self.last_result and self.last_result.ai:
            from .cli import _copy_to_clipboard
            _copy_to_clipboard(self.last_result.ai.report_markdown)
            self.query_one("#status").update("report copied ✓")
        elif key == "json" and self.last_result:
            self.query_one("#report").update(
                self.last_result.model_dump_json(indent=2))

    # ---------- bulk ----------

    @work(exclusive=True)
    async def _run_bulk(self) -> None:
        pipe = self._ensure_pipeline()
        self.query_one("#status").update("⠿ bulk: reading iocs.txt…")
        try:
            with open("iocs.txt", encoding="utf-8") as f:
                iocs = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        except OSError:
            self.query_one("#status").update(
                "bulk: create iocs.txt (one IOC per line) in the project dir first")
            return
        report = self.query_one("#report")
        self._hide_all()
        report.display = True
        lines = [f"Bulk lookup — {len(iocs)} IOCs", ""]
        for raw in iocs:
            try:
                r = await pipe.lookup(raw)
                verdict = r.ai.verdict.value if r.ai else "—"
                lines.append(f"  {r.ioc.value:<36} {r.risk_score:>3}/100  {verdict}")
                report.update("\n".join(lines))
            except InvalidIOCError:
                lines.append(f"  {raw:<36}  — invalid, skipped")
                report.update("\n".join(lines))
        lines.append("")
        lines.append("esc to go back")
        report.update("\n".join(lines))
        self.query_one("#status").update(f"bulk complete: {len(iocs)} processed")

    # ---------- history ----------

    def _show_history(self) -> None:
        pipe = self._ensure_pipeline()
        data = pipe.history.list(limit=30)
        self._hide_all()
        report = self.query_one("#report")
        report.display = True
        if not data["items"]:
            report.update("History is empty — run a lookup first.\n\nesc to go back")
        else:
            lines = [f"History — {data['total']} lookups (newest first)", ""]
            for it in data["items"]:
                verdict = it["verdict"] or "—"
                lines.append(
                    f"  #{it['id']:<4} {it['ioc_value']:<32} "
                    f"{it['risk_score']:>3}/100  {verdict:<10} {it['lang'] or '—'}"
                )
            lines += ["", "esc to go back"]
            report.update("\n".join(lines))
        self.query_one("#status").update("history")

    def _show_ask(self) -> None:
        self.mode = "ask"
        self._hide_all()
        inp = self.query_one("#ioc_input")
        inp.placeholder = "Ask AI about your lookup history…"
        inp.value = ""
        inp.display = True
        inp.focus()
        self.query_one("#status").update("ask mode — submit to query AI over history")

    @work(exclusive=True)
    async def _do_ask(self, question: str) -> None:
        from .ai.client import AIClient
        pipe = self._ensure_pipeline()
        items = pipe.history.list(limit=50)["items"]
        self.query_one("#status").update(f"⠿ asking AI over {len(items)} items…")
        try:
            answer = await AIClient(self.config.ai).ask(
                question, items, self.config.defaults.lang)
        except Exception as e:
            self.query_one("#status").update(f"AI unavailable: {type(e).__name__}")
            return
        self._hide_all()
        report = self.query_one("#report")
        report.display = True
        report.update(f"Q: {question}\n\n{answer}\n\nesc to go back")
        self.query_one("#status").update("ask complete")

    # ---------- analyzer status ----------

    def _show_status(self) -> None:
        pipe = self._ensure_pipeline()
        self._hide_all()
        report = self.query_one("#report")
        report.display = True
        lines = ["Analyzer status", ""]
        for a in pipe.analyzers:
            ready = "● ready" if a.is_ready() else "○ not ready"
            reason = ""
            if not a.config.enabled:
                reason = "(disabled in config)"
            elif a.requires_key and not a.config.resolved_key():
                reason = "(missing API key)"
            types = ", ".join(sorted(a.supported_types))
            lines.append(f"  {ready:<14} {a.name:<12} [{types}] {reason}")
        lines += ["", f"AI: {self.config.ai.model} @ {self.config.ai.base_url}",
                  "", "esc to go back"]
        report.update("\n".join(lines))
        self.query_one("#status").update("analyzer status")

    # ---------- settings ----------

    def _show_settings(self) -> None:
        self._hide_all()
        menu = self.query_one("#settings_menu") if self._has_settings() else None
        actions = self.query_one("#actions")
        actions.display = True
        actions.clear_options()
        actions.add_options([
            Option(f"Language: {self.config.defaults.lang}  (toggle en → de → id)", id="lang"),
            Option("Clear cache", id="clear_cache"),
            Option("Back", id="back"),
        ])
        actions.focus()
        self.query_one("#status").update("settings")

    def _has_settings(self) -> bool:
        return len(self.query("#settings_menu")) > 0

    async def _settings_select(self, key: str | None) -> None:
        await self._action_select(key)  # reuse; settings items share action ids

    async def on_option_list_option_selected_settings(self, event) -> None:
        pass  # handled in unified handler

    @on(OptionList.OptionSelected, "#actions")
    async def _actions_handler(self, event) -> None:
        key = event.option.id
        if key == "lang":
            cur = self.config.defaults.lang
            nxt = _LANGS[(_LANGS.index(cur) + 1) % len(_LANGS)]
            self.config.defaults.lang = nxt
            self.query_one("#status").update(f"language → {nxt} (this session)")
            self._show_settings()
        elif key == "clear_cache":
            pipe = self._ensure_pipeline()
            n = pipe.cache.clear()
            self.query_one("#status").update(f"cache cleared — {n} entries removed")
            self._show_settings()
        elif key == "back":
            self._show_menu()
        else:
            await self._action_select(key)

    async def on_unmount(self) -> None:
        if self.pipeline:
            await self.pipeline.close()


def run_tui() -> None:
    IOCInsightApp().run()
