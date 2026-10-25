"""GreyNoise analyzer — IPs only. Distinguishes internet noise from targeted attacks.

Free "community" tier: /v3/community/{ip} — limited but no credit card.
Classification: benign | malicious | unknown.
"""
from __future__ import annotations

from ..models import AnalyzerResult, IOC, IOCType
from .base import BaseAnalyzer


class GreyNoiseAnalyzer(BaseAnalyzer):
    name = "greynoise"
    supported_types = frozenset({"ipv4", "ipv6"})
    requires_key = True
    BASE = "https://api.greynoise.io/v3/community"

    async def _query(self, ioc: IOC) -> AnalyzerResult:
        resp = await self.client.get(
            f"{self.BASE}/{ioc.value}",
            headers={"key": self.config.resolved_key()},
        )
        resp.raise_for_status()
        d = resp.json()
        noise = bool(d.get("noise"))
        riot = bool(d.get("riot"))  # Rule It Out — known benign service
        classification = d.get("classification", "unknown")
        tags = []
        if noise:
            tags.append("internet-noise")
        if riot:
            tags.append("known-benign-service")
        if classification != "unknown":
            tags.append(f"class:{classification}")
        # votes: 1 if malicious-classified, 0 otherwise — feeds scoring
        return AnalyzerResult(
            source=self.name, ioc=ioc, success=True,
            malicious_votes=1 if classification == "malicious" else 0,
            total_engines=1,
            reputation_score={"malicious": 100.0, "benign": 0.0}.get(classification),
            tags=tags, raw=d,
        )
