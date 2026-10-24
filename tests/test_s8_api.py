"""S8 tests — FastAPI endpoints (TestClient, pipeline mocked)."""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from ioc_insight.api import app
from ioc_insight.models import (
    AIAssessment, AnalyzerResult, IOC, LookupResult, RecommendedAction, Verdict,
)
from ioc_insight.normalizer import InvalidIOCError


def fake_result(value="8.8.8.8"):
    ioc = IOC(raw=value, value=value, type="ipv4")
    return LookupResult(
        ioc=ioc, risk_score=87,
        analyzer_results=[AnalyzerResult(source="abuseipdb", ioc=ioc, success=True,
                                         malicious_votes=142, reputation_score=98.0)],
        ai=AIAssessment(verdict=Verdict.MALICIOUS, confidence=92, explanation="x",
                        recommended_action=RecommendedAction.BLOCK,
                        report_markdown="## t", model="ali/kimi-k3", lang="en"),
        duration_ms=1800,
    )


@pytest.fixture
def client(tmp_path):
    with TestClient(app) as c:
        pipe = app.state.pipeline
        # isolate test from real data/history.db accumulated during dev —
        # swap the reference; do NOT close the shared one
        from ioc_insight.db import HistoryDB
        pipe.history = HistoryDB(str(tmp_path / "history.db"))
        pipe.lookup = AsyncMock(side_effect=lambda ioc, **kw: (
            fake_result(ioc) if "garbage" not in ioc else (_ for _ in ()).throw(InvalidIOCError("bad"))
        ))
        yield c


def test_lookup_endpoint(client):
    r = client.post("/api/v1/lookup", json={"ioc": "8.8.8.8"})
    assert r.status_code == 200
    data = r.json()
    assert data["ioc"]["value"] == "8.8.8.8"
    assert data["risk_score"] == 87
    assert data["ai"]["verdict"] == "MALICIOUS"


def test_lookup_invalid_ioc_422(client):
    r = client.post("/api/v1/lookup", json={"ioc": "garbage!!"})
    assert r.status_code == 422


def test_lookup_bad_lang_422(client):
    r = client.post("/api/v1/lookup", json={"ioc": "8.8.8.8", "lang": "fr"})
    assert r.status_code == 422


def test_lookup_no_ai(client):
    r = client.post("/api/v1/lookup", json={"ioc": "8.8.8.8", "ai": False})
    assert r.status_code == 200


def test_health_endpoint(client):
    with patch("ioc_insight.api.AIClient") as MockAI:
        MockAI.return_value.health = AsyncMock(return_value=True)
        r = client.get("/api/v1/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["ai"]["reachable"] is True
    assert data["ai"]["model"] == "ali/kimi-k3"
    assert "virustotal" in data["analyzers"]


def test_health_ai_down(client):
    with patch("ioc_insight.api.AIClient") as MockAI:
        MockAI.return_value.health = AsyncMock(return_value=False)
        r = client.get("/api/v1/health")
    assert r.json()["ai"]["reachable"] is False


def test_history_contract(client):
    r = client.get("/api/v1/history?limit=10")
    assert r.status_code == 200
    data = r.json()
    assert data["items"] == []
    assert data["limit"] == 10
