"""B.3 tests — Telegram notifier."""
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from ioc_insight.config import NotifyConfig
from ioc_insight.models import (
    AIAssessment, AnalyzerResult, IOC, LookupResult, RecommendedAction, Verdict,
)
from ioc_insight.notify import TelegramNotifier


def make_result(verdict):
    ioc = IOC(raw="1.2.3.4", value="1.2.3.4", type="ipv4")
    return LookupResult(
        ioc=ioc, risk_score=100 if verdict == Verdict.MALICIOUS else 50,
        analyzer_results=[AnalyzerResult(source="otx", ioc=ioc, success=True,
                                         malicious_votes=5, tags=["c2"])],
        ai=AIAssessment(verdict=verdict, confidence=90, explanation="x",
                        recommended_action=RecommendedAction.BLOCK,
                        report_markdown="## t", model="ali/kimi-k3", lang="id"),
        duration_ms=100,
        mitre=[{"id": "T1071", "name": "C2", "sources": ["otx"]}],
    )


@pytest.fixture
def notifier():
    return TelegramNotifier(bot_token="tok", chat_id="-100123", min_severity=Verdict.MALICIOUS)


# --- trigger logic ---

def test_triggers_on_malicious(notifier):
    assert notifier._triggered(make_result(Verdict.MALICIOUS)) is True


def test_no_trigger_below_severity(notifier):
    assert notifier._triggered(make_result(Verdict.SUSPICIOUS)) is False
    assert notifier._triggered(make_result(Verdict.CLEAN)) is False


def test_suspicious_included_when_min_severity_suspicious():
    n = TelegramNotifier("tok", "-100123", min_severity=Verdict.SUSPICIOUS)
    assert n._triggered(make_result(Verdict.SUSPICIOUS)) is True
    assert n._triggered(make_result(Verdict.MALICIOUS)) is True
    assert n._triggered(make_result(Verdict.CLEAN)) is False


def test_no_trigger_without_ai(notifier):
    r = make_result(Verdict.MALICIOUS)
    r.ai = None
    assert notifier._triggered(r) is False


# --- message format ---

def test_format_contains_key_fields(notifier):
    text = notifier._format(make_result(Verdict.MALICIOUS))
    assert "1.2.3.4" in text
    assert "MALICIOUS" in text
    assert "100/100" in text
    assert "T1071" in text
    assert "BLOCK" in text


# --- send ---

@pytest.mark.asyncio
async def test_notify_sends_when_triggered(notifier):
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post("https://api.telegram.org/bottok/sendMessage").respond(
            200, json={"ok": True})
        sent = await notifier.notify(make_result(Verdict.MALICIOUS))
    assert sent is True
    body = route.calls[0].request.content.decode()
    assert "-100123" in body


@pytest.mark.asyncio
async def test_notify_skips_when_not_triggered(notifier):
    with respx.mock(assert_all_called=False) as mock:
        mock.post(url__startswith="https://api.telegram.org/").respond(200, json={"ok": True})
        sent = await notifier.notify(make_result(Verdict.CLEAN))
    assert sent is False
    assert len(mock.calls) == 0  # no HTTP call made


# --- config ---

def test_notify_config_env_resolution(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok123")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100999")
    cfg = NotifyConfig(enabled=True)
    assert cfg.is_ready() is True
    assert cfg.resolved_token() == "tok123"
    assert cfg.resolved_chat_id() == "-100999" or cfg.resolved_chat_id() == "-100999"


def test_notify_config_not_ready_when_disabled():
    assert NotifyConfig(enabled=False).is_ready() is False
