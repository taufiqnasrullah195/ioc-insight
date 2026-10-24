"""S5 tests — scoring rules + pipeline integration (HTTP fully mocked)."""
import httpx
import pytest
import respx

from ioc_insight.config import AppConfig, ProviderConfig
from ioc_insight.models import AnalyzerResult, IOC, Verdict
from ioc_insight.pipeline import Pipeline
from ioc_insight.scoring import band_for, score


def res_(source, success=True, votes=0, rep=None, tags=None):
    ioc = IOC(raw="x", value="x", type="ipv4")
    return AnalyzerResult(source=source, ioc=ioc, success=success,
                          malicious_votes=votes, reputation_score=rep,
                          tags=tags or [])


# --- scoring ---

def test_score_empty_is_zero():
    assert score([]) == 0


def test_score_ignores_failed_results():
    assert score([res_("virustotal", success=False, votes=99)]) == 0


@pytest.mark.parametrize("votes,expected", [(0, 0), (1, 10), (2, 10), (3, 25), (9, 25), (10, 40), (50, 40)])
def test_vt_bands(votes, expected):
    assert score([res_("virustotal", votes=votes)]) == expected


@pytest.mark.parametrize("conf,expected", [(0, 0), (9, 0), (10, 10), (39, 10), (40, 20), (79, 20), (80, 35), (100, 35)])
def test_abuseipdb_bands(conf, expected):
    assert score([res_("abuseipdb", rep=float(conf))]) == expected


@pytest.mark.parametrize("pulses,expected", [(0, 0), (1, 10), (4, 10), (5, 25), (30, 25)])
def test_otx_bands(pulses, expected):
    assert score([res_("otx", votes=pulses)]) == expected


@pytest.mark.parametrize("age,expected", [(1, 20), (29, 20), (30, 10), (179, 10), (180, 0), (5000, 0)])
def test_whois_age_bands(age, expected):
    assert score([res_("whois_age", votes=age)]) == expected


def test_whois_no_creation_date_scores_zero():
    assert score([res_("whois_age", votes=5, tags=["no-creation-date"])]) == 0


def test_score_adds_across_sources():
    results = [
        res_("virustotal", votes=12),   # +40
        res_("abuseipdb", rep=98.0),    # +35
        res_("otx", votes=7),           # +25
    ]
    assert score(results) == 100  # clamped from 100


def test_score_clamped_at_100():
    results = [res_("virustotal", votes=50), res_("abuseipdb", rep=100.0),
               res_("otx", votes=99), res_("whois_age", votes=3)]
    assert score(results) == 100


def test_band_for():
    assert band_for(0) == Verdict.CLEAN
    assert band_for(20) == Verdict.UNKNOWN
    assert band_for(50) == Verdict.SUSPICIOUS
    assert band_for(75) == Verdict.MALICIOUS


# --- pipeline integration ---

def make_config(tmp_path) -> AppConfig:
    cfg = AppConfig()
    cfg.cache.path = str(tmp_path / "cache.db")
    for p in cfg.providers.values():
        p.api_key = "test-key"
    return cfg


VT_PAYLOAD = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 12, "harmless": 77},
    "reputation": 0, "tags": [],
}}}
ABUSEIPDB_PAYLOAD = {"data": {"abuseConfidenceScore": 98, "totalReports": 142,
                          "isTor": False, "isWhitelisted": False}}
OTX_PAYLOAD = {"pulse_info": {"count": 7, "pulses": [{"tags": ["c2"]}]}}


@pytest.mark.asyncio
async def test_pipeline_full_lookup(tmp_path):
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").respond(200, json=VT_PAYLOAD)
        mock.get("https://api.abuseipdb.com/api/v2/check").respond(200, json=ABUSEIPDB_PAYLOAD)
        mock.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general").respond(200, json=OTX_PAYLOAD)
        pipe = Pipeline(make_config(tmp_path))
        result = await pipe.lookup("8.8.8.8", use_ai=False)
        await pipe.close()

    assert result.ioc.type == "ipv4"
    assert result.risk_score == 100  # 40 + 35 + 25
    assert result.ai is None
    assert result.duration_ms >= 0
    successes = [r for r in result.analyzer_results if r.success]
    assert len(successes) == 3
    whois = [r for r in result.analyzer_results if r.source == "whois_age"][0]
    assert not whois.success and "skipped" in whois.error  # IP → WHOIS skipped


@pytest.mark.asyncio
async def test_pipeline_uses_cache_on_second_lookup(tmp_path):
    with respx.mock() as mock:
        vt = mock.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").respond(200, json=VT_PAYLOAD)
        mock.get("https://api.abuseipdb.com/api/v2/check").respond(200, json=ABUSEIPDB_PAYLOAD)
        mock.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general").respond(200, json=OTX_PAYLOAD)
        pipe = Pipeline(make_config(tmp_path))
        r1 = await pipe.lookup("8.8.8.8", use_ai=False)
        r2 = await pipe.lookup("8.8.8.8", use_ai=False)  # should hit cache
        await pipe.close()

    assert vt.call_count == 1  # second lookup came from cache
    cached = [r for r in r2.analyzer_results if r.source == "virustotal"][0]
    assert cached.from_cache is True
    assert r2.risk_score == r1.risk_score


@pytest.mark.asyncio
async def test_pipeline_no_cache_flag_bypasses(tmp_path):
    with respx.mock() as mock:
        vt = mock.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").respond(200, json=VT_PAYLOAD)
        mock.get("https://api.abuseipdb.com/api/v2/check").respond(200, json=ABUSEIPDB_PAYLOAD)
        mock.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general").respond(200, json=OTX_PAYLOAD)
        pipe = Pipeline(make_config(tmp_path))
        await pipe.lookup("8.8.8.8", use_ai=False)
        r = await pipe.lookup("8.8.8.8", use_cache=False, use_ai=False)
        await pipe.close()

    assert vt.call_count == 2
    cached = [x for x in r.analyzer_results if x.source == "virustotal"][0]
    assert cached.from_cache is False


@pytest.mark.asyncio
async def test_pipeline_survives_one_analyzer_down(tmp_path):
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__startswith="https://www.virustotal.com/").respond(500)
        mock.get("https://api.abuseipdb.com/api/v2/check").respond(200, json=ABUSEIPDB_PAYLOAD)
        mock.get(url__startswith="https://otx.alienvault.com/").respond(200, json=OTX_PAYLOAD)
        pipe = Pipeline(make_config(tmp_path))
        result = await pipe.lookup("8.8.8.8", use_ai=False)
        await pipe.close()

    vt = [r for r in result.analyzer_results if r.source == "virustotal"][0]
    assert not vt.success and "500" in vt.error
    assert result.risk_score == 60  # 0 (VT down) + 35 + 25


@pytest.mark.asyncio
async def test_pipeline_invalid_ioc_raises(tmp_path):
    pipe = Pipeline(make_config(tmp_path))
    with pytest.raises(Exception):
        await pipe.lookup("definitely not an ioc!!", use_ai=False)
    await pipe.close()
