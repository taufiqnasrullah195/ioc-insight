"""Automated actions on rule/verdict triggers. TRD P3.3.

When a lookup resolves to a blocking verdict, fire outbound actions:
- generic webhook (POST JSON to firewall / SOAR / any HTTP endpoint)
- Telegram alert (already in notify.py)
- blocklist is served as an API endpoint (see api.py /api/v1/blocklist)

All actions are fire-and-forget — failures never break the lookup.
"""
from __future__ import annotations

import httpx

from .models import LookupResult, RecommendedAction, Verdict

_BLOCKING_ACTIONS = {RecommendedAction.BLOCK}


def should_act(result: LookupResult) -> bool:
    """An action fires when the final action is BLOCK."""
    return bool(result.ai and result.ai.recommended_action in _BLOCKING_ACTIONS)


class ActionRunner:
    def __init__(self, webhook_url: str = "", timeout: int = 15):
        self.webhook_url = webhook_url
        self.timeout = timeout

    async def run(self, result: LookupResult) -> dict:
        """Execute outbound actions. Returns a report of what fired."""
        fired = {"webhook": False, "skipped": True}
        if not should_act(result):
            return fired
        fired["skipped"] = False
        if self.webhook_url:
            fired["webhook"] = await self._webhook(result)
        return fired

    async def _webhook(self, result: LookupResult) -> bool:
        ai = result.ai
        if ai is None:
            return False
        payload = {
            "source": "ioc-insight",
            "ioc": result.ioc.value,
            "type": result.ioc.type,
            "verdict": ai.verdict.value,
            "action": ai.recommended_action.value,
            "confidence": ai.confidence,
            "risk_score": result.risk_score,
            "rule_match": result.rule_match,
            "mitre": [t["id"] for t in result.mitre],
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.webhook_url, json=payload)
                return resp.status_code < 400
        except httpx.HTTPError:
            return False
