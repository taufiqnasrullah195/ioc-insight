"""B.1 tests — abuse.ch analyzers (ThreatFox, URLhaus, MalwareBazaar), no key."""
import httpx
import pytest
import respx

from ioc_insight.analyzers.abuse_ch import (
    MalwareBazaarAnalyzer,
    ThreatFoxAnalyzer,
    URLhausAnalyzer,
)
from ioc_insight.config import AppConfig, ProviderConfig
from ioc_insight.models import AnalyzerResult, IOC
from ioc_insight.scoring import score


def cfg(key: str = "test-key") -> "ProviderConfig":
    from ioc_insight.config import ProviderConfig
    return ProviderConfig(api_key=key, enabled=True)


@pytest.fixture
def client():
    return httpx.AsyncClient()


DOMAIN = IOC(raw="evil.com", value="evil.com", type="domain")
URL = IOC(raw="http://evil.com/x", value="http://evil.com/x", type="url")
MD5 = IOC(raw="d41d8cd98f00b204e9800998ecf8427e", value="d41d8cd98f00b204e9800998ecf8427e", type="md5")


def test_abuse_ch_configured_with_auth_key():
    cfg_ = AppConfig()
    for name in ("threatfox", "urlhaus", "malwarebazaar"):
        assert cfg_.providers[name].enabled is True
        assert cfg_.providers[name].api_key == "ENV:ABUSECH_AUTH_KEY"


# --- ThreatFox ---

@pytest.mark.asyncio
async def test_threatfox_hit(client):
    payload = {"query_status": "ok", "data": [
        {"tags": ["emotet"], "malware_printable": "Emotet"},
        {"tags": ["emotet", "c2"], "malware_printable": "Emotet"},
    ]}
    with respx.mock(assert_all_called=True) as mock:
        mock.post("https://threatfox-api.abuse.ch/api/v1/").respond(200, json=payload)
        a = ThreatFoxAnalyzer(cfg(), client)
        r = await a.analyze(DOMAIN)
    assert r.success
    assert r.malicious_votes == 2
    assert "c2" in r.tags
    assert any(t.startswith("malware:Emotet") for t in r.tags)


@pytest.mark.asyncio
async def test_threatfox_no_result(client):
    with respx.mock(assert_all_called=True) as mock:
        mock.post("https://threatfox-api.abuse.ch/api/v1/").respond(200, json={"query_status": "no_result"})
        a = ThreatFoxAnalyzer(cfg(), client)
        r = await a.analyze(DOMAIN)
    assert r.success and r.malicious_votes == 0


# --- URLhaus ---

@pytest.mark.asyncio
async def test_urlhaus_host_with_urls(client):
    payload = {"query_status": "ok", "url_count": 3,
               "urls": [{"tags": ["phishing"]}, {"tags": ["malware"]}, {}]}
    with respx.mock(assert_all_called=True) as mock:
        mock.post("https://urlhaus-api.abuse.ch/v1/").respond(200, json=payload)
        a = URLhausAnalyzer(cfg(), client)
        r = await a.analyze(DOMAIN)
    assert r.success
    assert r.malicious_votes == 3
    assert "phishing" in r.tags


@pytest.mark.asyncio
async def test_urlhaus_clean(client):
    with respx.mock() as mock:
        mock.post("https://urlhaus-api.abuse.ch/v1/").respond(200, json={"query_status": "no_result"})
        a = URLhausAnalyzer(cfg(), client)
        r = await a.analyze(DOMAIN)
    assert r.success and r.malicious_votes == 0


# --- MalwareBazaar ---

@pytest.mark.asyncio
async def test_malwarebazaar_known_hash(client):
    payload = {"query_status": "ok", "data": [{"signature": "RedLine", "file_type": "exe", "tags": ["stealer"]}]}
    with respx.mock() as mock:
        mock.post("https://mb-api.abuse.ch/api/v1/").respond(200, json=payload)
        a = MalwareBazaarAnalyzer(cfg(), client)
        r = await a.analyze(MD5)
    assert r.success
    assert r.malicious_votes == 1
    assert any(t == "family:RedLine" for t in r.tags)


@pytest.mark.asyncio
async def test_malwarebazaar_unknown_hash(client):
    with respx.mock() as mock:
        mock.post("https://mb-api.abuse.ch/api/v1/").respond(200, json={"query_status": "hash_not_found"})
        a = MalwareBazaarAnalyzer(cfg(), client)
        r = await a.analyze(MD5)
    assert r.success and r.malicious_votes == 0


# --- scoring ---

def test_threatfox_scoring():
    def r(v):
        return AnalyzerResult(source="threatfox", ioc=DOMAIN, success=True, malicious_votes=v)
    assert score([r(0)]) == 0
    assert score([r(1)]) == 25
    assert score([r(3)]) == 35


def test_urlhaus_scoring():
    def r(v):
        return AnalyzerResult(source="urlhaus", ioc=DOMAIN, success=True, malicious_votes=v)
    assert score([r(0)]) == 0
    assert score([r(1)]) == 25
    assert score([r(5)]) == 35


def test_malwarebazaar_scoring():
    def r(v):
        return AnalyzerResult(source="malwarebazaar", ioc=MD5, success=True, malicious_votes=v)
    assert score([r(0)]) == 0
    assert score([r(1)]) == 40
