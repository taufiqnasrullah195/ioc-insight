"""WHOIS domain age analyzer — domains only, no API key.

Flags newly registered domains: <30 days is a strong phishing/C2 signal.
Uses synchronous python-whois in a thread (library is blocking).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import whois

from ..models import AnalyzerResult, IOC, IOCType
from .base import BaseAnalyzer


class WhoisAgeAnalyzer(BaseAnalyzer):
    name = "whois_age"
    supported_types = frozenset({"domain"})
    requires_key = False

    async def _query(self, ioc: IOC) -> AnalyzerResult:
        w = await asyncio.to_thread(whois.whois, ioc.value)
        created = w.creation_date
        if isinstance(created, list):
            created = min(d for d in created if d)
        if created is None:
            return AnalyzerResult(
                source=self.name, ioc=ioc, success=True,
                tags=["no-creation-date"], raw={"registrar": str(w.registrar)},
            )
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days
        tags = []
        if age_days < 30:
            tags.append("newly-registered")
        if age_days < 180:
            tags.append("young-domain")
        return AnalyzerResult(
            source=self.name, ioc=ioc, success=True,
            reputation_score=None,
            malicious_votes=age_days,  # reuse field: age in days
            tags=tags,
            raw={"creation_date": created.isoformat(),
                 "registrar": str(w.registrar), "age_days": age_days},
        )
