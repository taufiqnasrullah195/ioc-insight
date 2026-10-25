"""urlscan.io analyzer — URLs and domains. Free tier, API key optional for lookup."""
from __future__ import annotations

from ..models import AnalyzerResult, IOC, IOCType
from .base import BaseAnalyzer


class UrlscanAnalyzer(BaseAnalyzer):
    name = "urlscan"
    supported_types = frozenset({"url", "domain"})
    requires_key = True
    BASE = "https://urlscan.io/api/v1"

    async def _query(self, ioc: IOC) -> AnalyzerResult:
        # search existing scans first (free, no submission quota burned)
        target = ioc.value if ioc.type == "url" else f"domain:{ioc.value}"
        params = {"q": f'page.url:"{ioc.value}"' if ioc.type == "url" else f"domain:{ioc.value}"}
        resp = await self.client.get(
            f"{self.BASE}/search/",
            headers={"API-Key": self.config.resolved_key()},
            params=params,
        )
        resp.raise_for_status()
        d = resp.json()
        results = d.get("results", [])
        malicious = sum(1 for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious"))
        tags = []
        for r in results[:5]:
            tags.extend(r.get("verdicts", {}).get("overall", {}).get("tags", []))
        tags = sorted(set(tags))[:10]
        return AnalyzerResult(
            source=self.name, ioc=ioc, success=True,
            malicious_votes=malicious,
            total_engines=len(results),  # number of past scans
            reputation_score=None,
            tags=tags, raw={"total_scans": len(results), "malicious_scans": malicious},
        )
