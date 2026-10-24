"""AbuseIPDB v2 analyzer — IPs only."""
from __future__ import annotations

from ..models import AnalyzerResult, IOC, IOCType
from .base import BaseAnalyzer

# abuseipdb.com/check — category ids we surface as tags
_CATEGORIES = {
    4: "ddos", 14: "port-scan", 15: "hacking", 18: "brute-force",
    22: "ssh", 23: "iot-targeted",
}


class AbuseIPDBAnalyzer(BaseAnalyzer):
    name = "abuseipdb"
    supported_types = frozenset({"ipv4", "ipv6"})
    BASE = "https://api.abuseipdb.com/api/v2/check"

    async def _query(self, ioc: IOC) -> AnalyzerResult:
        resp = await self.client.get(
            self.BASE,
            headers={"Key": self.config.resolved_key(), "Accept": "application/json"},
            params={"ipAddress": ioc.value, "maxAgeInDays": 30},
        )
        resp.raise_for_status()
        d = resp.json()["data"]
        tags = sorted(
            {_CATEGORIES[c] for c in d.get("reports_categories", []) if c in _CATEGORIES}
        ) if "reports_categories" in d else []
        if d.get("isTor"):
            tags.append("tor-exit")
        if d.get("isWhitelisted"):
            tags.append("whitelisted")
        return AnalyzerResult(
            source=self.name, ioc=ioc, success=True,
            malicious_votes=d.get("totalReports", 0),
            total_engines=0,
            reputation_score=float(d.get("abuseConfidenceScore", 0)),
            tags=tags, raw=resp.json(),
        )
