"""Analyzer plugin interface. TRD §2.2 — one file per source."""
from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from ..config import ProviderConfig
from ..models import AnalyzerResult, IOC, IOCType
from ..ratelimit import RateLimiter


class BaseAnalyzer(ABC):
    """One threat-intel source. Subclasses implement _query() per IOC type."""

    name: str = "base"
    supported_types: frozenset[IOCType] = frozenset()
    requires_key: bool = True

    def __init__(
        self,
        config: ProviderConfig,
        client: httpx.AsyncClient,
        limiter: RateLimiter | None = None,
    ):
        self.config = config
        self.client = client
        self.limiter = limiter or RateLimiter()

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    def is_ready(self) -> bool:
        """Enabled in config AND has an API key when it needs one."""
        if not self.config.enabled:
            return False
        if self.requires_key and not self.config.resolved_key():
            return False
        return True

    async def analyze(self, ioc: IOC) -> AnalyzerResult:
        """Template method: guard rails here, source logic in _query()."""
        if not self.supports(ioc.type):
            return self._skipped(ioc, f"does not support {ioc.type}")
        if not self.is_ready():
            return self._skipped(ioc, "disabled or missing API key")
        await self.limiter.acquire(self.name)
        try:
            return await self._query(ioc)
        except httpx.HTTPStatusError as e:
            return self._fail(ioc, f"HTTP {e.response.status_code}")
        except httpx.HTTPError as e:
            return self._fail(ioc, f"network: {type(e).__name__}")
        except Exception as e:  # parse errors etc — never crash the pipeline
            return self._fail(ioc, f"{type(e).__name__}: {e}")

    limiter: RateLimiter

    @abstractmethod
    async def _query(self, ioc: IOC) -> AnalyzerResult: ...

    def _skipped(self, ioc: IOC, reason: str) -> AnalyzerResult:
        return AnalyzerResult(source=self.name, ioc=ioc, success=False,
                              error=f"skipped: {reason}")

    def _fail(self, ioc: IOC, error: str) -> AnalyzerResult:
        return AnalyzerResult(source=self.name, ioc=ioc, success=False, error=error)
