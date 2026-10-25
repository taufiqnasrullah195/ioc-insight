"""P2.2 tests — urlscan.io + GreyNoise analyzers + scoring rules."""
import httpx
import pytest
import respx

from ioc_insight.analyzers.greynoise import GreyNoiseAnalyzer
from ioc_insight.analyzers.urlscan import UrlscanAnalyzer
from ioc_insight.config import ProviderConfig
from ioc_insight.models import AnalyzerResult, IOC
from ioc_insight.scoring import score


def cfg(key: str = "test-key") -> ProviderConfig:
    return ProviderConfig(api_key=key, enabled=True)


@pytest.fixture
def client():
    return httpx.AsyncClient()


URL = IOC(raw="http://evil.com/x", value="http://evil.com/x", type="url")
DOMAIN = IOC(raw="evil.com", value="evil.com", type="domain")
IP = IOC(raw="1.2.3.4", value="1.2.3.4", type="ipv4")


# --- urlscan ---

@pytest.mark.asyncio
async def test_urlscan_counts_malicious_scans(client):
    payload = {"results": [
        {"verdicts": {"overall": {"malicious": True, "tags": ["phishing"]}}},
        {"verdicts": {"overall": {"malicious": False}}},
        {"verdicts": {"overall": {"malicious": True, "tags": ["phishing", "brand"]}}},
    ]}
    with respx.mock(assert_all_called=True) as mock:
        mock.get(url__startswith="https://urlscan.io/api/v1/search/").respond(200, json=payload)
        a = UrlscanAnalyzer(cfg(), client)
        r = await a.analyze(URL)
    assert r.success
    assert r.malicious_votes == 2
    assert r.total_engines == 3
    assert "phishing" in r.tags


@pytest.mark.asyncio
async def test_urlscan_domain_query_uses_domain_filter(client):
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get(url__startswith="https://urlscan.io/api/v1/search/").respond(200, json={"results": []})
        a = UrlscanAnalyzer(cfg(), client)
        r = await a.analyze(DOMAIN)
    assert r.success
    url = str(route.calls[0].request.url)
    assert "domain%3Aevil.com" in url or "domain:evil.com" in url


@pytest.mark.asyncio
async def test_urlscan_skips_ip(client):
    a = UrlscanAnalyzer(cfg(), client)
    r = await a.analyze(IP)
    assert not r.success and "skipped" in r.error


# --- greynoise ---

@pytest.mark.asyncio
async def test_greynoise_malicious(client):
    payload = {"noise": True, "riot": False, "classification": "malicious", "name": "unknown"}
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://api.greynoise.io/v3/community/1.2.3.4").respond(200, json=payload)
        a = GreyNoiseAnalyzer(cfg(), client)
        r = await a.analyze(IP)
    assert r.success
    assert r.malicious_votes == 1
    assert "class:malicious" in r.tags
    assert "internet-noise" in r.tags


@pytest.mark.asyncio
async def test_greynoise_benign_riot(client):
    payload = {"noise": False, "riot": True, "classification": "benign", "name": "Googlebot"}
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://api.greynoise.io/v3/community/1.2.3.4").respond(200, json=payload)
        a = GreyNoiseAnalyzer(cfg(), client)
        r = await a.analyze(IP)
    assert r.success
    assert r.malicious_votes == 0
    assert "known-benign-service" in r.tags


@pytest.mark.asyncio
async def test_greynoise_skips_domain(client):
    a = GreyNoiseAnalyzer(cfg(), client)
    r = await a.analyze(DOMAIN)
    assert not r.success and "skipped" in r.error


# --- scoring with new sources ---

def test_urlscan_scoring():
    def r(votes):
        ioc = IOC(raw="x", value="x", type="url")
        return AnalyzerResult(source="urlscan", ioc=ioc, success=True, malicious_votes=votes)
    assert score([r(0)]) == 0
    assert score([r(1)]) == 30
    assert score([r(3)]) == 30


def test_greynoise_scoring_malicious_and_riot():
    ioc = IOC(raw="x", value="x", type="ipv4")
    mal = AnalyzerResult(source="greynoise", ioc=ioc, success=True, tags=["class:malicious"])
    riot = AnalyzerResult(source="greynoise", ioc=ioc, success=True, tags=["known-benign-service"])
    assert score([mal]) == 30
    assert score([riot]) == 0  # -15 clamped at 0
    # riot can partially cancel other signals
    vt = AnalyzerResult(source="virustotal", ioc=ioc, success=True, malicious_votes=1)  # +10
    assert score([riot, vt]) == 0  # 10 - 15 → clamped 0


def test_default_config_has_new_providers():
    from ioc_insight.config import AppConfig
    cfg_ = AppConfig()
    assert "urlscan" in cfg_.providers
    assert "greynoise" in cfg_.providers
