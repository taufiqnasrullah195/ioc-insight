"""Token-bucket rate limiter per provider. TRD §11 — respect free-tier quotas.

Default limits (requests per minute):
  virustotal: 4 (free tier)
  abuseipdb:  15 (free tier, daily cap enforced server-side)
  otx:        60 (generous)
  whois_age:  10 (be polite to WHOIS servers)
"""
from __future__ import annotations

import asyncio
import time

DEFAULT_LIMITS_RPM: dict[str, int] = {
    "virustotal": 4,
    "abuseipdb": 15,
    "otx": 60,
    "whois_age": 10,
    "urlscan": 30,
    "greynoise": 10,
    "threatfox": 30,
    "urlhaus": 30,
    "malwarebazaar": 30,
}


class RateLimiter:
    """Async token bucket. acquire() waits until a token is available."""

    def __init__(self, limits_rpm: dict[str, int] | None = None):
        limits = dict(DEFAULT_LIMITS_RPM)
        if limits_rpm:
            limits.update(limits_rpm)
        self._rate = {name: rpm / 60.0 for name, rpm in limits.items()}
        self._capacity = {name: float(rpm) for name, rpm in limits.items()}
        self._tokens = {name: float(rpm) for name, rpm in limits.items()}
        self._last = {name: time.monotonic() for name in limits}

    def _refill(self, name: str) -> None:
        now = time.monotonic()
        elapsed = now - self._last[name]
        self._tokens[name] = min(
            self._capacity[name], self._tokens[name] + elapsed * self._rate[name]
        )
        self._last[name] = now

    def _try_take(self, provider: str) -> float:
        """Take a token if available; otherwise return seconds to wait."""
        self._refill(provider)
        if self._tokens[provider] >= 1.0:
            self._tokens[provider] -= 1.0
            return 0.0
        deficit = 1.0 - self._tokens[provider]
        return deficit / self._rate[provider]

    async def acquire(self, provider: str) -> None:
        if provider not in self._rate:
            return  # unknown provider → no limit
        while True:
            wait = self._try_take(provider)
            if wait <= 0:
                return
            await asyncio.sleep(wait)
