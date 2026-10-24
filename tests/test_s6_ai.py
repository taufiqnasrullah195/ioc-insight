"""S6 tests — AI client (mocked), fallback, pipeline AI wiring."""
import json
from unittest.mock import AsyncMock, patch

import pytest

from ioc_insight.ai.client import AIClient, AIUnavailableError, _parse_json
from ioc_insight.ai.fallback import fallback_assessment
from ioc_insight.ai.prompts import compact_results, system_prompt, user_prompt
from ioc_insight.config import AIConfig, AppConfig, ProviderConfig
from ioc_insight.models import (
    AIAssessment, AnalyzerResult, IOC, RecommendedAction, Verdict,
)
from ioc_insight.pipeline import Pipeline


GOOD_JSON = {
    "verdict": "MALICIOUS", "confidence": 92,
    "explanation": "Reported 142 times for SSH brute-force.",
    "recommended_action": "BLOCK",
    "report_markdown": "## IOC Triage\n**Verdict:** MALICIOUS",
}


def ai_cfg() -> AIConfig:
    return AIConfig(api_key="test-key", timeout_seconds=5)


def results_fixture():
    ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
    return [AnalyzerResult(source="abuseipdb", ioc=ioc, success=True,
                           malicious_votes=142, reputation_score=98.0,
                           tags=["brute-force"])]


# --- prompts ---

def test_system_prompt_language_switch():
    assert "English" in system_prompt("en")
    assert "German" in system_prompt("de")
    assert "Indonesian" in system_prompt("id")
    assert "English" in system_prompt("xx")  # unknown → default


def test_compact_results_trims_raw():
    rs = results_fixture()
    rs[0].raw = {"huge": "x" * 5000}
    compact = compact_results(rs)
    assert "raw" not in compact[0]
    assert compact[0]["reputation_score"] == 98.0


def test_compact_results_whois_relabels_age():
    ioc = IOC(raw="evil.com", value="evil.com", type="domain")
    r = AnalyzerResult(source="whois_age", ioc=ioc, success=True,
                       malicious_votes=9, tags=["newly-registered"],
                       raw={"registrar": "ShadyReg", "age_days": 9})
    compact = compact_results([r])[0]
    assert compact["domain_age_days"] == 9
    assert "malicious_votes" not in compact
    assert compact["registrar"] == "ShadyReg"


def test_user_prompt_contains_ioc_and_band():
    p = user_prompt("8.8.8.8", "ipv4", 87, Verdict.MALICIOUS, results_fixture())
    data = json.loads(p.split("\n", 1)[1])
    assert data["ioc"] == "8.8.8.8"
    assert data["heuristic_band"] == "MALICIOUS"


# --- _parse_json tolerance ---

def test_parse_plain_json():
    assert _parse_json(json.dumps(GOOD_JSON))["verdict"] == "MALICIOUS"


def test_parse_json_in_markdown_fence():
    fenced = "```json\n" + json.dumps(GOOD_JSON) + "\n```"
    assert _parse_json(fenced)["confidence"] == 92


def test_parse_json_with_surrounding_text():
    noisy = "Here is my analysis:\n" + json.dumps(GOOD_JSON) + "\nHope that helps!"
    assert _parse_json(noisy)["recommended_action"] == "BLOCK"


def test_parse_json_missing_key_raises():
    bad = dict(GOOD_JSON)
    del bad["verdict"]
    with pytest.raises(ValueError):
        _parse_json(json.dumps(bad))


def test_parse_json_garbage_raises():
    with pytest.raises(ValueError):
        _parse_json("I cannot help with that.")


# --- AIClient with mocked OpenAI ---

def mock_completion(content: str):
    m = AsyncMock()
    resp = AsyncMock()
    resp.choices = [AsyncMock()]
    resp.choices[0].message.content = content
    m.return_value = resp
    return m


@pytest.mark.asyncio
async def test_client_success():
    client = AIClient(ai_cfg())
    with patch.object(client._client.chat.completions, "create",
                      mock_completion(json.dumps(GOOD_JSON))):
        a = await client.assess("8.8.8.8", "ipv4", 87, results_fixture(), "en")
    assert a.verdict == Verdict.MALICIOUS
    assert a.confidence == 92
    assert a.model == "ali/kimi-k3"
    assert a.lang == "en"


@pytest.mark.asyncio
async def test_client_repairs_bad_json_once():
    create = AsyncMock()
    bad = AsyncMock()
    bad.choices = [AsyncMock()]
    bad.choices[0].message.content = "not json at all"
    good = AsyncMock()
    good.choices = [AsyncMock()]
    good.choices[0].message.content = json.dumps(GOOD_JSON)
    create.side_effect = [bad, good]

    client = AIClient(ai_cfg())
    with patch.object(client._client.chat.completions, "create", create):
        a = await client.assess("8.8.8.8", "ipv4", 87, results_fixture(), "en")
    assert create.call_count == 2  # retried with repair message
    assert a.verdict == Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_client_network_error_no_retry():
    create = AsyncMock(side_effect=ConnectionError("provider down"))
    client = AIClient(ai_cfg())
    with patch.object(client._client.chat.completions, "create", create):
        with pytest.raises(AIUnavailableError):
            await client.assess("8.8.8.8", "ipv4", 87, results_fixture(), "en")
    assert create.call_count == 1  # network errors don't retry


@pytest.mark.asyncio
async def test_client_bad_json_twice_raises():
    create = mock_completion("still not json")
    client = AIClient(ai_cfg())
    with patch.object(client._client.chat.completions, "create", create):
        with pytest.raises(AIUnavailableError):
            await client.assess("8.8.8.8", "ipv4", 87, results_fixture(), "en")


# --- fallback ---

@pytest.mark.parametrize("lang", ["en", "de", "id"])
def test_fallback_all_langs(lang):
    a = fallback_assessment("8.8.8.8", "ipv4", 87, results_fixture(), lang, "test")
    assert a.verdict == Verdict.MALICIOUS  # 87 ≥ 75
    assert a.recommended_action == RecommendedAction.BLOCK
    assert a.model == "heuristic-fallback"
    assert a.lang == lang
    assert len(a.explanation) > 20


def test_fallback_defangs_ioc_in_report():
    a = fallback_assessment("http://evil.com", "url", 90, [], "en", "test")
    assert "hxxp://evil[.]com" in a.report_markdown


def test_fallback_unknown_band_investigate():
    a = fallback_assessment("8.8.8.8", "ipv4", 30, [], "en", "test")
    assert a.verdict == Verdict.UNKNOWN
    assert a.recommended_action == RecommendedAction.INVESTIGATE


# --- pipeline AI wiring ---

def make_config(tmp_path) -> AppConfig:
    cfg = AppConfig()
    cfg.cache.path = str(tmp_path / "cache.db")
    for p in cfg.providers.values():
        p.api_key = "test-key"
    return cfg


@pytest.mark.asyncio
async def test_pipeline_ai_attached(tmp_path):
    fake = AIAssessment(
        verdict=Verdict.MALICIOUS, confidence=92, explanation="x",
        recommended_action=RecommendedAction.BLOCK, report_markdown="x",
        model="ali/kimi-k3", lang="en",
    )
    pipe = Pipeline(make_config(tmp_path))
    pipe.analyzers = []  # isolate AI wiring from HTTP
    with patch("ioc_insight.pipeline.AIClient") as MockClient:
        MockClient.return_value.assess = AsyncMock(return_value=fake)
        r = await pipe.lookup("8.8.8.8", use_cache=False)
    await pipe.close()
    assert r.ai is fake
    MockClient.return_value.assess.assert_awaited_once()


@pytest.mark.asyncio
async def test_pipeline_ai_failure_uses_fallback(tmp_path):
    pipe = Pipeline(make_config(tmp_path))
    # no analyzers will succeed (no mocks → httpx would hit network; instead
    # patch analyzer list to empty and force AI to raise)
    pipe.analyzers = []
    with patch("ioc_insight.pipeline.AIClient") as MockClient:
        instance = MockClient.return_value
        instance.assess = AsyncMock(side_effect=AIUnavailableError("down"))
        r = await pipe.lookup("8.8.8.8", use_cache=False)
    await pipe.close()
    assert r.ai is not None
    assert r.ai.model == "heuristic-fallback"
    assert r.risk_score == 0  # no analyzers → 0
    assert r.ai.verdict == Verdict.CLEAN  # band_for(0)


@pytest.mark.asyncio
async def test_pipeline_no_ai_flag(tmp_path):
    pipe = Pipeline(make_config(tmp_path))
    pipe.analyzers = []
    r = await pipe.lookup("8.8.8.8", use_cache=False, use_ai=False)
    await pipe.close()
    assert r.ai is None
