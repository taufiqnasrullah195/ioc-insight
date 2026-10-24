"""VirusTotal v3 analyzer — IPs, domains, URLs, hashes."""
from __future__ import annotations

import base64

from ..models import AnalyzerResult, IOC, IOCType
from .base import BaseAnalyzer


class VirusTotalAnalyzer(BaseAnalyzer):
    name = "virustotal"
    supported_types = frozenset({"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"})
    BASE = "https://www.virustotal.com/api/v3"

    async def _query(self, ioc: IOC) -> AnalyzerResult:
        path = self._path_for(ioc)
        resp = await self.client.get(
            f"{self.BASE}{path}",
            headers={"x-apikey": self.config.resolved_key()},
        )
        resp.raise_for_status()
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 0
        tags = list(attrs.get("tags", []))
        if attrs.get("reputation", 0) < 0:
            tags.append("negative-reputation")
        return AnalyzerResult(
            source=self.name, ioc=ioc, success=True,
            malicious_votes=malicious, total_engines=total,
            reputation_score=float(attrs.get("reputation", 0)),
            tags=tags, raw=resp.json(),
        )

    def _path_for(self, ioc: IOC) -> str:
        t = ioc.type
        if t in ("ipv4", "ipv6"):
            return f"/ip_addresses/{ioc.value}"
        if t == "domain":
            return f"/domains/{ioc.value}"
        if t == "url":
            # VT wants the URL as unpadded base64url identifier
            ident = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
            return f"/urls/{ident}"
        return f"/files/{ioc.value}"  # hashes
