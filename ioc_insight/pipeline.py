"""Lookup pipeline orchestration. TRD §3.

normalize → cache check (per analyzer) → parallel enrich (asyncio.gather)
→ store fresh results in cache → deterministic score → (AI added in S6)
"""
from __future__ import annotations

import asyncio
import time

import httpx

from .analyzers.abuse_ch import (
    MalwareBazaarAnalyzer,
    ThreatFoxAnalyzer,
    URLhausAnalyzer,
)
from .analyzers.abuseipdb import AbuseIPDBAnalyzer
from .analyzers.base import BaseAnalyzer
from .analyzers.greynoise import GreyNoiseAnalyzer
from .analyzers.otx import OTXAnalyzer
from .analyzers.urlscan import UrlscanAnalyzer
from .analyzers.virustotal import VirusTotalAnalyzer
from .analyzers.whois_age import WhoisAgeAnalyzer
from .ai.client import AIClient, AIUnavailableError
from .ai.fallback import fallback_assessment
from .cache import Cache
from .config import AppConfig
from .db import HistoryDB
from .mitre import map_techniques
from .models import AnalyzerResult, LookupResult
from .normalizer import normalize
from .ratelimit import RateLimiter
from .scoring import score

ANALYZER_CLASSES: list[type[BaseAnalyzer]] = [
    VirusTotalAnalyzer,
    AbuseIPDBAnalyzer,
    OTXAnalyzer,
    WhoisAgeAnalyzer,
    UrlscanAnalyzer,
    GreyNoiseAnalyzer,
    ThreatFoxAnalyzer,
    URLhausAnalyzer,
    MalwareBazaarAnalyzer,
]


class Pipeline:
    def __init__(self, config: AppConfig):
        self.config = config
        self.cache = Cache(config.cache.path, config.cache.ttl_hours)
        self.history = HistoryDB(config.history.path)
        self.limiter = RateLimiter()
        timeout = config.defaults.timeout_seconds
        self.client = httpx.AsyncClient(timeout=timeout)
        self.analyzers: list[BaseAnalyzer] = []
        for cls in ANALYZER_CLASSES:
            pcfg = config.providers.get(cls.name)
            if pcfg is None:
                continue
            self.analyzers.append(cls(pcfg, self.client, self.limiter))

    async def _run_analyzer(
        self, analyzer: BaseAnalyzer, ioc, use_cache: bool
    ) -> AnalyzerResult:
        if use_cache:
            cached = self.cache.get(analyzer.name, ioc)
            if cached is not None:
                return cached
        result = await analyzer.analyze(ioc)
        if result.success:
            self.cache.store(result)
        return result

    async def lookup(
        self, raw: str, use_cache: bool = True, use_ai: bool = True, lang: str | None = None
    ) -> LookupResult:
        start = time.monotonic()
        ioc = normalize(raw)  # raises InvalidIOCError on bad input
        results = list(await asyncio.gather(
            *(self._run_analyzer(a, ioc, use_cache) for a in self.analyzers)
        ))
        risk = score(results)
        ai = None
        if use_ai:
            lang = lang or self.config.defaults.lang
            try:
                ai = await AIClient(self.config.ai).assess(
                    ioc.value, ioc.type, risk, results, lang
                )
            except AIUnavailableError as e:
                ai = fallback_assessment(ioc.value, ioc.type, risk, results, lang, str(e))
            except Exception as e:  # belt and braces — AI must never block a lookup
                ai = fallback_assessment(ioc.value, ioc.type, risk, results, lang,
                                         f"{type(e).__name__}: {e}")
        duration_ms = int((time.monotonic() - start) * 1000)
        result = LookupResult(
            ioc=ioc,
            risk_score=risk,
            analyzer_results=results,
            ai=ai,
            duration_ms=duration_ms,
            mitre=map_techniques(results),
        )
        self.history.save(result)
        return result

    async def close(self) -> None:
        await self.client.aclose()
        self.cache.close()
        self.history.close()
