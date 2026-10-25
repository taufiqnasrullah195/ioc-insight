"""B.4 tests — bulk lookup API endpoint."""
from contextlib import contextmanager
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from ioc_insight.api import app
from ioc_insight.models import (
    AIAssessment, AnalyzerResult, IOC, LookupResult, RecommendedAction, Verdict,
)
from ioc_insight.normalizer import InvalidIOCError


def fake_result(value):
    ioc = IOC(raw=value, value=value, type="ipv4")
    return LookupResult(
        ioc=ioc, risk_score=87,
        analyzer_results=[AnalyzerResult(source="otx", ioc=ioc, success=True)],
        ai=AIAssessment(verdict=Verdict.MALICIOUS, confidence=90, explanation="x",
                        recommended_action=RecommendedAction.BLOCK,
                        report_markdown="## t", model="m", lang="en"),
        duration_ms=100,
    )


@contextmanager
def _client():
    with TestClient(app) as client:  # context manager runs lifespan
        pipe = app.state.pipeline

        async def fake_lookup(raw, **kw):
            if "garbage" in raw:
                raise InvalidIOCError("cannot classify")
            return fake_result(raw)
        pipe.lookup = AsyncMock(side_effect=fake_lookup)
        yield client


def test_bulk_success():
    with _client() as client:
        r = client.post("/api/v1/lookup/bulk",
                        json={"iocs": ["8.8.8.8", "1.1.1.1", "garbage!!"], "ai": False})
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 3
    assert data["succeeded"] == 2
    ok = [x for x in data["results"] if x["ok"]]
    bad = [x for x in data["results"] if not x["ok"]]
    assert len(ok) == 2 and len(bad) == 1
    assert bad[0]["ioc"] == "garbage!!"
    assert ok[0]["result"]["ioc"]["value"] == "8.8.8.8"


def test_bulk_empty_422():
    with _client() as client:
        r = client.post("/api/v1/lookup/bulk", json={"iocs": []})
    assert r.status_code == 422


def test_bulk_too_many_422():
    with _client() as client:
        r = client.post("/api/v1/lookup/bulk", json={"iocs": [f"10.0.0.{i}" for i in range(51)]})
    assert r.status_code == 422


def test_bulk_skips_blank_lines():
    with _client() as client:
        r = client.post("/api/v1/lookup/bulk",
                        json={"iocs": ["8.8.8.8", "", "  ", "1.1.1.1"], "ai": False})
    assert r.status_code == 200
    assert r.json()["total"] == 2  # blank lines dropped
