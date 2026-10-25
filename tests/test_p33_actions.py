"""P3.3 tests — automated actions + blocklist endpoint."""
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from ioc_insight.actions import ActionRunner, should_act
from ioc_insight.api import app
from ioc_insight.models import (
    AIAssessment, AnalyzerResult, IOC, LookupResult, RecommendedAction, Verdict,
)


def make_result(action=RecommendedAction.BLOCK, with_ai=True):
    ioc = IOC(raw="1.2.3.4", value="1.2.3.4", type="ipv4")
    return LookupResult(
        ioc=ioc, risk_score=100,
        analyzer_results=[AnalyzerResult(source="otx", ioc=ioc, success=True)],
        ai=AIAssessment(verdict=Verdict.MALICIOUS, confidence=95, explanation="x",
                        recommended_action=action, report_markdown="## t",
                        model="m", lang="en") if with_ai else None,
        duration_ms=100, rule_match="heavy-abuse-reports",
        mitre=[{"id": "T1110", "name": "Brute Force", "sources": ["otx"]}],
    )


# --- should_act ---

def test_should_act_on_block():
    assert should_act(make_result(RecommendedAction.BLOCK)) is True


def test_no_act_on_monitor():
    assert should_act(make_result(RecommendedAction.MONITOR)) is False


def test_no_act_without_ai():
    assert should_act(make_result(with_ai=False)) is False


# --- webhook ---

@pytest.mark.asyncio
async def test_webhook_fires_on_block():
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("https://fw.example.com/block").respond(200)
        runner = ActionRunner("https://fw.example.com/block")
        out = await runner.run(make_result())
    assert out["webhook"] is True
    assert out["skipped"] is False
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["ioc"] == "1.2.3.4"
    assert body["action"] == "BLOCK"
    assert body["rule_match"] == "heavy-abuse-reports"
    assert body["mitre"] == ["T1110"]


@pytest.mark.asyncio
async def test_webhook_not_fired_without_url():
    runner = ActionRunner("")  # no webhook configured
    out = await runner.run(make_result())
    assert out["webhook"] is False
    assert out["skipped"] is False  # should_act passed, just no webhook


@pytest.mark.asyncio
async def test_webhook_failure_returns_false():
    with respx.mock() as mock:
        mock.post(url__startswith="https://fw.example.com/").respond(500)
        runner = ActionRunner("https://fw.example.com/block")
        out = await runner.run(make_result())
    assert out["webhook"] is False


@pytest.mark.asyncio
async def test_network_error_swallowed():
    runner = ActionRunner("https://nonexistent.invalid/x")
    out = await runner.run(make_result())
    assert out["webhook"] is False  # never raises


# --- blocklist endpoint ---

def test_blocklist_endpoint():
    with TestClient(app) as client:
        pipe = app.state.pipeline
        from ioc_insight.db import HistoryDB
        import tempfile, os
        tmp = tempfile.mkdtemp()
        pipe.history = HistoryDB(os.path.join(tmp, "h.db"))
        pipe.history.save(make_result())  # MALICIOUS
        clean = make_result(RecommendedAction.MONITOR)
        clean.ai.verdict = Verdict.CLEAN
        clean.ioc = IOC(raw="8.8.8.8", value="8.8.8.8", type="ipv4")
        pipe.history.save(clean)
        r = client.get("/api/v1/blocklist.txt")
    assert r.status_code == 200
    assert "1.2.3.4" in r.text
    assert "8.8.8.8" not in r.text  # only MALICIOUS
