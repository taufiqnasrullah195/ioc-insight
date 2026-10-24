"""S4 tests — BaseAnalyzer + VT/AbuseIPDB/OTX/WHOIS (respx-mocked)."""
from unittest.mock import patch

import httpx
import pytest
import respx

from ioc_insight.analyzers.abuseipdb import AbuseIPDBAnalyzer
from ioc_insight.analyzers.otx import OTXAnalyzer
from ioc_insight.analyzers.virustotal import VirusTotalAnalyzer
from ioc_insight.analyzers.whois_age import WhoisAgeAnalyzer
from ioc_insight.config import ProviderConfig
from ioc_insight.models import IOC


def cfg(key: str = "test-key", enabled: bool = True) -> ProviderConfig:
    return ProviderConfig(api_key=key, enabled=enabled)


@pytest.fixture
def client():
    return httpx.AsyncClient()


IP = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
DOMAIN = IOC(raw="evil.com", value="evil.com", type="domain")
URL = IOC(raw="http://x.com/a", value="http://x.com/a", type="url")
MD5 = IOC(raw="d41d8cd98f00b204e9800998ecf8427e", value="d41d8cd98f00b204e9800998ecf8427e", type="md5")


# --- BaseAnalyzer behavior ---

@pytest.mark.asyncio
async def test_skips_unsupported_type(client):
    a = AbuseIPDBAnalyzer(cfg(), client)
    r = await a.analyze(DOMAIN)  # AbuseIPDB only supports IPs
    assert not r.success
    assert "skipped" in r.error


@pytest.mark.asyncio
async def test_skips_when_disabled(client):
    a = VirusTotalAnalyzer(cfg(enabled=False), client)
    r = await a.analyze(IP)
    assert not r.success
    assert "disabled" in r.error


@pytest.mark.asyncio
async def test_skips_when_key_missing(client):
    a = VirusTotalAnalyzer(cfg(key="ENV:DEFINITELY_MISSING"), client)
    r = await a.analyze(IP)
    assert not r.success
    assert "API key" in r.error


@pytest.mark.asyncio
async def test_http_error_becomes_failed_result(client):
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__startswith="https://www.virustotal.com/api/v3/").respond(403)
        a = VirusTotalAnalyzer(cfg(), client)
        r = await a.analyze(IP)
    assert not r.success
    assert "403" in r.error


# --- VirusTotal ---

@pytest.mark.asyncio
async def test_vt_ip_parses_stats(client):
    payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 12, "suspicious": 2,
                                 "harmless": 70, "undetected": 5},
        "reputation": -42, "tags": ["tor"],
    }}}
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").respond(200, json=payload)
        a = VirusTotalAnalyzer(cfg(), client)
        r = await a.analyze(IP)
    assert route.called
    assert route.calls[0].request.headers["x-apikey"] == "test-key"
    assert r.success
    assert r.malicious_votes == 12
    assert r.total_engines == 89
    assert "tor" in r.tags and "negative-reputation" in r.tags


@pytest.mark.asyncio
async def test_vt_url_base64_identifier(client):
    import base64
    ident = base64.urlsafe_b64encode(URL.value.encode()).decode().rstrip("=")
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"https://www.virustotal.com/api/v3/urls/{ident}").respond(
            200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 60}}}})
        a = VirusTotalAnalyzer(cfg(), client)
        r = await a.analyze(URL)
    assert r.success and r.malicious_votes == 1


# --- AbuseIPDB ---

@pytest.mark.asyncio
async def test_abuseipdb_parses_score_and_tor(client):
    payload = {"data": {
        "abuseConfidenceScore": 98, "totalReports": 142,
        "isTor": True, "isWhitelisted": False,
    }}
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://api.abuseipdb.com/api/v2/check").respond(200, json=payload)
        a = AbuseIPDBAnalyzer(cfg(), client)
        r = await a.analyze(IP)
    assert r.success
    assert r.reputation_score == 98.0
    assert r.malicious_votes == 142
    assert "tor-exit" in r.tags


# --- OTX ---

@pytest.mark.asyncio
async def test_otx_counts_pulses_and_tags(client):
    payload = {"pulse_info": {"count": 7, "pulses": [
        {"tags": ["c2", "botnet"]}, {"tags": ["c2", "ssh"]},
    ]}}
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general").respond(200, json=payload)
        a = OTXAnalyzer(cfg(), client)
        r = await a.analyze(IP)
    assert r.success
    assert r.malicious_votes == 7
    assert set(r.tags) == {"botnet", "c2", "ssh"}


# --- WHOIS age ---

class FakeWhois:
    def __init__(self, creation_date, registrar="TestRegistrar"):
        self.creation_date = creation_date
        self.registrar = registrar


@pytest.mark.asyncio
async def test_whois_newly_registered(client):
    from datetime import datetime, timedelta, timezone
    recent = datetime.now(timezone.utc) - timedelta(days=9)
    with patch("ioc_insight.analyzers.whois_age.whois.whois",
               return_value=FakeWhois(recent)):
        a = WhoisAgeAnalyzer(cfg(key=""), client)
        r = await a.analyze(DOMAIN)
    assert r.success
    assert "newly-registered" in r.tags
    assert r.raw["age_days"] == 9


@pytest.mark.asyncio
async def test_whois_old_domain_no_flags(client):
    from datetime import datetime, timezone
    old = datetime(2005, 1, 1, tzinfo=timezone.utc)
    with patch("ioc_insight.analyzers.whois_age.whois.whois",
               return_value=FakeWhois(old)):
        a = WhoisAgeAnalyzer(cfg(key=""), client)
        r = await a.analyze(DOMAIN)
    assert r.success
    assert r.tags == []
    assert r.raw["age_days"] > 7000


@pytest.mark.asyncio
async def test_whois_handles_list_creation_date(client):
    from datetime import datetime, timedelta, timezone
    recent = datetime.now(timezone.utc) - timedelta(days=100)
    with patch("ioc_insight.analyzers.whois_age.whois.whois",
               return_value=FakeWhois([recent, None, recent])):
        a = WhoisAgeAnalyzer(cfg(key=""), client)
        r = await a.analyze(DOMAIN)
    assert r.success and r.raw["age_days"] == 100


@pytest.mark.asyncio
async def test_whois_no_key_needed(client):
    a = WhoisAgeAnalyzer(cfg(key=""), client)
    assert a.is_ready()  # requires_key=False
