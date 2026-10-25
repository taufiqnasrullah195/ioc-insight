"""Telegram notifications via Bot API. TRD B.3.

Sends an alert to a configured channel/chat when a lookup meets the trigger
(default: verdict == MALICIOUS). No third-party SDK — plain Bot API over httpx.
"""
from __future__ import annotations

import httpx

from .models import LookupResult, Verdict

_BOT_API = "https://api.telegram.org/bot{token}/sendMessage"


class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str, min_severity: Verdict = Verdict.MALICIOUS):
        self.token = bot_token
        self.chat_id = chat_id
        self.min_severity = min_severity

    def _triggered(self, result: LookupResult) -> bool:
        verdict = result.ai.verdict if result.ai else None
        order = [Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.UNKNOWN, Verdict.CLEAN]
        if verdict is None:
            return False
        return order.index(verdict) <= order.index(self.min_severity)

    async def notify(self, result: LookupResult) -> bool:
        """Send alert if triggered. Returns True if a message was sent."""
        if not self._triggered(result):
            return False
        text = self._format(result)
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(_BOT_API.format(token=self.token), json=payload)
            return resp.status_code == 200 and resp.json().get("ok", False)

    def _format(self, r: LookupResult) -> str:
        ai = r.ai
        verdict = ai.verdict.value if ai else "UNKNOWN"
        action = ai.recommended_action.value if ai else "—"
        mitre = "  ·  ".join(t["id"] for t in r.mitre) if r.mitre else "—"
        return (
            f"🚨 *IOC Alert — {verdict}*\n\n"
            f"*IOC:* `{r.ioc.value}` ({r.ioc.type})\n"
            f"*Risk score:* {r.risk_score}/100\n"
            f"*Action:* {action}\n"
            f"*MITRE:* {mitre}\n"
            f"*AI:* {ai.model if ai else 'off'} · {ai.lang if ai else '—'}\n"
            f"_ioc-insight · {r.duration_ms}ms_"
        )
