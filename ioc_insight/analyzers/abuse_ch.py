"""abuse.ch analyzers — ThreatFox, URLhaus, MalwareBazaar.

NOTE: abuse.ch APIs now require a free Auth-Key (since 2024). Register once
at https://auth.abuse.ch/ → one key unlocks all three services.
"""
from __future__ import annotations

from ..models import AnalyzerResult, IOC
from .base import BaseAnalyzer


class _AbuseCHBase(BaseAnalyzer):
    requires_key = True  # abuse.ch Auth-Key (free) — auth.abuse.ch
    BASE = ""

    async def _post(self, payload: dict) -> dict:
        resp = await self.client.post(
            self.BASE,
            data=payload,
            headers={"Auth-Key": self.config.resolved_key()},
        )
        resp.raise_for_status()
        return resp.json()


class ThreatFoxAnalyzer(_AbuseCHBase):
    """ThreatFox — recent malware IOCs. Types: IP, domain, URL, hash."""
    name = "threatfox"
    supported_types = frozenset({"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"})
    BASE = "https://threatfox-api.abuse.ch/api/v1/"

    async def _query(self, ioc: IOC) -> AnalyzerResult:
        d = await self._post({"query": "search_ioc", "search_term": ioc.value})
        if d.get("query_status") == "no_result":
            return AnalyzerResult(source=self.name, ioc=ioc, success=True,
                                  malicious_votes=0, tags=[])
        data = d.get("data") or []
        tags = sorted({t for row in data for t in (row.get("tags") or [])})[:10]
        malware = sorted({row.get("malware_printable", "") for row in data} - {""})
        return AnalyzerResult(
            source=self.name, ioc=ioc, success=True,
            malicious_votes=len(data),  # number of ThreatFox sightings
            total_engines=0,
            tags=tags + [f"malware:{m}" for m in malware[:3]],
            raw={"sightings": len(data), "malware": malware},
        )


class URLhausAnalyzer(_AbuseCHBase):
    """URLhaus — malicious URLs. Types: URL, domain, IP (as host)."""
    name = "urlhaus"
    supported_types = frozenset({"url", "domain", "ipv4"})
    BASE = "https://urlhaus-api.abuse.ch/v1/"

    async def _query(self, ioc: IOC) -> AnalyzerResult:
        if ioc.type == "url":
            d = await self._post({"query": "url", "url": ioc.value})
        else:
            d = await self._post({"query": "host", "host": ioc.value})
        if d.get("query_status") in ("no_result", "ok"):
            count = d.get("url_count", 0) if ioc.type != "url" else (1 if d.get("url_status") else 0)
            tags = sorted({t for u in (d.get("urls") or []) for t in (u.get("tags") or [])})[:10]
            return AnalyzerResult(
                source=self.name, ioc=ioc, success=True,
                malicious_votes=int(count or 0),
                tags=tags, raw={"url_count": count},
            )
        return AnalyzerResult(source=self.name, ioc=ioc, success=True,
                              malicious_votes=0, tags=[])


class MalwareBazaarAnalyzer(_AbuseCHBase):
    """MalwareBazaar — malware sample hashes. Types: md5, sha1, sha256."""
    name = "malwarebazaar"
    supported_types = frozenset({"md5", "sha1", "sha256"})
    BASE = "https://mb-api.abuse.ch/api/v1/"

    async def _query(self, ioc: IOC) -> AnalyzerResult:
        d = await self._post({"query": "get_info", "hash": ioc.value})
        if d.get("query_status") == "hash_not_found":
            return AnalyzerResult(source=self.name, ioc=ioc, success=True,
                                  malicious_votes=0, tags=[])
        data = (d.get("data") or [{}])[0]
        tags = sorted({t for t in (data.get("tags") or [])})[:10]
        family = data.get("signature") or ""
        if family:
            tags.append(f"family:{family}")
        return AnalyzerResult(
            source=self.name, ioc=ioc, success=True,
            malicious_votes=1,  # present in MB = known malware sample
            tags=tags, raw={"signature": family, "file_type": data.get("file_type")},
        )
