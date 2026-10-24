"""AlienVault OTX v2 analyzer — IPs, domains, URLs, hashes."""
from __future__ import annotations

from ..models import AnalyzerResult, IOC, IOCType
from .base import BaseAnalyzer


class OTXAnalyzer(BaseAnalyzer):
    name = "otx"
    supported_types = frozenset({"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"})
    BASE = "https://otx.alienvault.com/api/v1/indicators"

    async def _query(self, ioc: IOC) -> AnalyzerResult:
        section = self._section_for(ioc)
        resp = await self.client.get(
            f"{self.BASE}/{section}/{ioc.value}/general",
            headers={"X-OTX-API-KEY": self.config.resolved_key()},
        )
        resp.raise_for_status()
        d = resp.json()
        pulses = d.get("pulse_info", {})
        count = pulses.get("count", 0)
        tags = []
        for p in pulses.get("pulses", [])[:10]:
            tags.extend(p.get("tags", []))
        tags = sorted(set(tags))[:15]
        return AnalyzerResult(
            source=self.name, ioc=ioc, success=True,
            malicious_votes=count,  # pulse count as "votes"
            total_engines=0,
            reputation_score=None,
            tags=tags, raw=d,
        )

    def _section_for(self, ioc: IOC) -> str:
        return {
            "ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain",
            "url": "url", "md5": "file", "sha1": "file", "sha256": "file",
        }[ioc.type]
