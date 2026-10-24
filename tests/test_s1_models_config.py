"""S1 tests — models + config loader."""
import os
from datetime import datetime, timezone

import pytest

from ioc_insight.config import AppConfig, load_config
from ioc_insight.models import (
    AIAssessment,
    AnalyzerResult,
    IOC,
    LookupResult,
    RecommendedAction,
    Verdict,
    score_band,
)


# --- models ---

def test_ioc_model_holds_raw_and_normalized():
    ioc = IOC(raw="evil[.]com", value="evil.com", type="domain")
    assert ioc.raw == "evil[.]com"
    assert ioc.value == "evil.com"
    assert ioc.type == "domain"


def test_analyzer_result_defaults():
    ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
    r = AnalyzerResult(source="virustotal", ioc=ioc, success=True)
    assert r.malicious_votes == 0
    assert r.from_cache is False
    assert r.error is None
    assert isinstance(r.fetched_at, datetime)
    assert r.fetched_at.tzinfo == timezone.utc


def test_ai_assessment_confidence_bounds():
    with pytest.raises(Exception):
        AIAssessment(
            verdict=Verdict.MALICIOUS, confidence=101, explanation="x",
            recommended_action=RecommendedAction.BLOCK, report_markdown="x",
            model="m", lang="en",
        )


def test_lookup_result_score_bounds():
    ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
    with pytest.raises(Exception):
        LookupResult(ioc=ioc, risk_score=150, analyzer_results=[])


def test_score_band_mapping():
    assert score_band(0) == Verdict.CLEAN
    assert score_band(19) == Verdict.CLEAN
    assert score_band(20) == Verdict.UNKNOWN
    assert score_band(49) == Verdict.UNKNOWN
    assert score_band(50) == Verdict.SUSPICIOUS
    assert score_band(74) == Verdict.SUSPICIOUS
    assert score_band(75) == Verdict.MALICIOUS
    assert score_band(100) == Verdict.MALICIOUS


def test_lookup_result_ai_optional():
    ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
    r = LookupResult(ioc=ioc, risk_score=10, analyzer_results=[])
    assert r.ai is None


# --- config ---

def test_default_config_when_file_missing(tmp_path):
    cfg = load_config(tmp_path / "nonexistent.yaml")
    assert cfg.ai.model == "ali/kimi-k3"
    assert cfg.ai.base_url == "https://api.vleee.net/v1"
    assert cfg.defaults.lang == "en"
    assert "virustotal" in cfg.providers
    assert cfg.providers["whois_age"].enabled is True


def test_config_loads_from_yaml(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "ai:\n  model: test/model\n  temperature: 0.5\n"
        "defaults:\n  lang: de\n"
        "providers:\n  otx:\n    api_key: ENV:MY_OTX\n    enabled: false\n"
    )
    cfg = load_config(cfg_file)
    assert cfg.ai.model == "test/model"
    assert cfg.ai.temperature == 0.5
    assert cfg.defaults.lang == "de"
    assert cfg.providers["otx"].enabled is False


def test_env_indirection_resolves(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "secret123")
    cfg = AppConfig()
    assert cfg.providers["virustotal"].resolved_key() == "secret123"
    assert cfg.providers["virustotal"].api_key == "ENV:VT_API_KEY"  # not stored


def test_env_indirection_missing_var_returns_empty():
    os.environ.pop("DEFINITELY_MISSING_VAR", None)
    from ioc_insight.config import ProviderConfig
    p = ProviderConfig(api_key="ENV:DEFINITELY_MISSING_VAR")
    assert p.resolved_key() == ""


def test_literal_key_passthrough():
    from ioc_insight.config import ProviderConfig
    p = ProviderConfig(api_key="literal-key-abc")
    assert p.resolved_key() == "literal-key-abc"


def test_config_rejects_bad_lang(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("defaults:\n  lang: fr\n")
    with pytest.raises(Exception):
        load_config(cfg_file)
