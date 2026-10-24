"""S3 tests — cache + rate limiter."""
import time

import pytest

from ioc_insight.cache import Cache
from ioc_insight.models import AnalyzerResult, IOC
from ioc_insight.ratelimit import DEFAULT_LIMITS_RPM, RateLimiter


def make_result(source: str, ioc: IOC, votes: int = 5) -> AnalyzerResult:
    return AnalyzerResult(
        source=source, ioc=ioc, success=True, malicious_votes=votes,
        total_engines=89, tags=["test"], raw={"some": "payload"},
    )


# --- cache ---

@pytest.fixture
def cache(tmp_path):
    c = Cache(str(tmp_path / "cache.db"), {"ip": 24, "domain": 24, "url": 12, "hash": 168})
    yield c
    c.close()


def test_cache_miss_returns_none(cache):
    ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
    assert cache.get("virustotal", ioc) is None


def test_cache_store_and_hit(cache):
    ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
    cache.store(make_result("virustotal", ioc, votes=7))
    hit = cache.get("virustotal", ioc)
    assert hit is not None
    assert hit.malicious_votes == 7
    assert hit.from_cache is True
    assert hit.raw == {"some": "payload"}


def test_cache_is_per_source(cache):
    ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
    cache.store(make_result("virustotal", ioc, votes=7))
    assert cache.get("abuseipdb", ioc) is None  # different source → miss


def test_cache_expired_entry_is_miss(tmp_path):
    c = Cache(str(tmp_path / "c.db"), {"ip": 0, "domain": 24, "url": 12, "hash": 168})
    ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
    c.store(make_result("virustotal", ioc))
    time.sleep(0.01)
    assert c.get("virustotal", ioc) is None  # ttl=0h → instantly expired
    c.close()


def test_cache_ttl_per_type(tmp_path):
    # hash TTL huge, url TTL tiny
    c = Cache(str(tmp_path / "c.db"), {"ip": 24, "domain": 24, "url": 0, "hash": 99999})
    h = IOC(raw="d41d8cd98f00b204e9800998ecf8427e", value="d41d8cd98f00b204e9800998ecf8427e", type="md5")
    u = IOC(raw="http://x.com", value="http://x.com", type="url")
    c.store(make_result("virustotal", h))
    c.store(make_result("virustotal", u))
    assert c.get("virustotal", h) is not None   # hash still fresh
    assert c.get("virustotal", u) is None       # url expired
    c.close()


def test_cache_overwrite(cache):
    ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
    cache.store(make_result("virustotal", ioc, votes=1))
    cache.store(make_result("virustotal", ioc, votes=9))
    assert cache.get("virustotal", ioc).malicious_votes == 9


def test_cache_clear(cache):
    ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
    cache.store(make_result("virustotal", ioc))
    cache.store(make_result("abuseipdb", ioc))
    assert cache.clear() == 2
    assert cache.get("virustotal", ioc) is None


# --- rate limiter ---

@pytest.mark.asyncio
async def test_limiter_allows_burst_up_to_capacity():
    rl = RateLimiter({"test": 60})  # 60 rpm → capacity 60 tokens
    start = time.monotonic()
    for _ in range(5):
        await rl.acquire("test")
    assert time.monotonic() - start < 0.5  # burst is instant


@pytest.mark.asyncio
async def test_limiter_throttles_beyond_capacity():
    rl = RateLimiter({"test": 60})  # 1 token/sec refill
    rl._tokens["test"] = 0.0        # drain
    start = time.monotonic()
    await rl.acquire("test")
    elapsed = time.monotonic() - start
    assert 0.5 < elapsed < 2.0  # ~1s wait for one token


@pytest.mark.asyncio
async def test_limiter_unknown_provider_passes():
    rl = RateLimiter()
    await rl.acquire("nonexistent")  # must not block or raise


@pytest.mark.asyncio
async def test_limiter_providers_independent():
    rl = RateLimiter({"a": 60, "b": 60})
    rl._tokens["a"] = 0.0
    # provider b unaffected by a being drained
    start = time.monotonic()
    await rl.acquire("b")
    assert time.monotonic() - start < 0.2


def test_default_limits_cover_our_providers():
    for p in ("virustotal", "abuseipdb", "otx", "whois_age"):
        assert p in DEFAULT_LIMITS_RPM
    assert DEFAULT_LIMITS_RPM["virustotal"] == 4  # VT free tier
