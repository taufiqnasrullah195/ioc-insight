"""S9 tests — history DB + API history with real data."""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from ioc_insight.api import app
from ioc_insight.config import AppConfig
from ioc_insight.db import HistoryDB
from ioc_insight.models import (
    AIAssessment, AnalyzerResult, IOC, LookupResult, RecommendedAction, Verdict,
)
from ioc_insight.pipeline import Pipeline


def make_result(value="8.8.8.8", score=87, verdict=Verdict.MALICIOUS):
    ioc = IOC(raw=value, value=value, type="ipv4")
    return LookupResult(
        ioc=ioc, risk_score=score,
        analyzer_results=[AnalyzerResult(source="abuseipdb", ioc=ioc, success=True,
                                         malicious_votes=142, reputation_score=98.0)],
        ai=AIAssessment(verdict=verdict, confidence=92, explanation="x",
                        recommended_action=RecommendedAction.BLOCK,
                        report_markdown="## t", model="ali/kimi-k3", lang="id"),
        duration_ms=1800,
    )


# --- HistoryDB unit ---

@pytest.fixture
def db(tmp_path):
    d = HistoryDB(str(tmp_path / "history.db"))
    yield d
    d.close()


def test_save_and_count(db):
    assert db.count() == 0
    rid = db.save(make_result())
    assert rid == 1
    assert db.count() == 1


def test_save_without_ai(db):
    r = make_result()
    r.ai = None
    rid = db.save(r)
    item = db.list()["items"][0]
    assert item["verdict"] is None
    assert item["model"] is None


def test_list_ordering_newest_first(db):
    db.save(make_result("1.1.1.1"))
    db.save(make_result("2.2.2.2"))
    db.save(make_result("3.3.3.3"))
    items = db.list()["items"]
    assert [i["ioc_value"] for i in items] == ["3.3.3.3", "2.2.2.2", "1.1.1.1"]


def test_list_pagination(db):
    for i in range(5):
        db.save(make_result(f"10.0.0.{i}"))
    page = db.list(limit=2, offset=2)
    assert page["total"] == 5
    assert len(page["items"]) == 2
    assert page["items"][0]["ioc_value"] == "10.0.0.2"


def test_get_roundtrip_full_payload(db):
    original = make_result(verdict=Verdict.SUSPICIOUS)
    rid = db.save(original)
    loaded = db.get(rid)
    assert loaded is not None
    assert loaded.ai.verdict == Verdict.SUSPICIOUS
    assert loaded.ai.lang == "id"
    assert loaded.analyzer_results[0].malicious_votes == 142


def test_get_missing_returns_none(db):
    assert db.get(9999) is None


# --- pipeline persists history ---

def make_config(tmp_path) -> AppConfig:
    cfg = AppConfig()
    cfg.cache.path = str(tmp_path / "cache.db")
    cfg.history.path = str(tmp_path / "history.db")
    for p in cfg.providers.values():
        p.api_key = "test-key"
    return cfg


@pytest.mark.asyncio
async def test_pipeline_saves_to_history(tmp_path):
    pipe = Pipeline(make_config(tmp_path))
    pipe.analyzers = []
    await pipe.lookup("8.8.8.8", use_cache=False, use_ai=False)
    await pipe.lookup("1.1.1.1", use_cache=False, use_ai=False)
    count = pipe.history.count()
    await pipe.close()
    assert count == 2


# --- API history with real data ---

def test_api_history_returns_saved_lookups(tmp_path):
    with TestClient(app) as client:
        pipe = app.state.pipeline
        from ioc_insight.db import HistoryDB
        pipe.history = HistoryDB(str(tmp_path / "history.db"))  # swap, don't close shared

        async def fake_lookup(ioc, **kw):
            r = make_result(ioc)
            pipe.history.save(r)  # mocked lookup must still persist
            return r
        pipe.lookup = AsyncMock(side_effect=fake_lookup)

        client.post("/api/v1/lookup", json={"ioc": "8.8.8.8"})
        client.post("/api/v1/lookup", json={"ioc": "1.1.1.1"})

        r = client.get("/api/v1/history")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        ids = [i["id"] for i in data["items"]]
        assert ids == sorted(ids, reverse=True)  # newest first

        # fetch full record by id
        rid = data["items"][0]["id"]
        r2 = client.get(f"/api/v1/history/{rid}")
        assert r2.status_code == 200
        assert r2.json()["ai"]["verdict"] == "MALICIOUS"


def test_api_history_item_404():
    with TestClient(app) as client:
        r = client.get("/api/v1/history/999999")
        assert r.status_code == 404
