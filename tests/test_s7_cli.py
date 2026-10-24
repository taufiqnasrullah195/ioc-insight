"""S7 tests — CLI one-shot + bulk (typer CliRunner, pipeline mocked)."""
import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from ioc_insight.cli import app
from ioc_insight.models import (
    AIAssessment, AnalyzerResult, IOC, LookupResult, RecommendedAction, Verdict,
)

runner = CliRunner()


def fake_result(value="8.8.8.8", score=87, with_ai=True):
    ioc = IOC(raw=value, value=value, type="ipv4")
    ai = AIAssessment(
        verdict=Verdict.MALICIOUS, confidence=92, explanation="Reported for SSH brute-force.",
        recommended_action=RecommendedAction.BLOCK,
        report_markdown="## IOC Triage\n**Verdict:** MALICIOUS",
        model="ali/kimi-k3", lang="en",
    ) if with_ai else None
    return LookupResult(
        ioc=ioc, risk_score=87,
        analyzer_results=[AnalyzerResult(source="abuseipdb", ioc=ioc, success=True,
                                         malicious_votes=142, reputation_score=98.0)],
        ai=ai, duration_ms=1800,
    )


def _patched_pipeline(result_or_exc):
    """Patch Pipeline used inside cli module."""
    instance = AsyncMock()
    if isinstance(result_or_exc, Exception):
        instance.lookup = AsyncMock(side_effect=result_or_exc)
    else:
        instance.lookup = AsyncMock(return_value=result_or_exc)
    return patch("ioc_insight.cli.Pipeline", return_value=instance)


def test_cli_one_shot_renders():
    with _patched_pipeline(fake_result()):
        result = runner.invoke(app, ["8.8.8.8", "--no-cache"])
    assert result.exit_code == 0
    out = result.stdout
    assert "MALICIOUS" in out
    assert "87/100" in out
    assert "BLOCK" in out
    assert "abuseipdb" in out


def test_cli_json_output():
    with _patched_pipeline(fake_result()):
        result = runner.invoke(app, ["8.8.8.8", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["ioc"]["value"] == "8.8.8.8"
    assert data["risk_score"] == 87
    assert data["ai"]["verdict"] == "MALICIOUS"


def test_cli_no_ai_flag():
    with _patched_pipeline(fake_result(with_ai=False)):
        result = runner.invoke(app, ["8.8.8.8", "--no-ai"])
    assert result.exit_code == 0
    assert "87/100" in result.stdout
    assert "ai: off" in result.stdout


def test_cli_invalid_ioc_exit_2():
    from ioc_insight.normalizer import InvalidIOCError
    with _patched_pipeline(InvalidIOCError("cannot classify")):
        result = runner.invoke(app, ["garbage!!"])
    assert result.exit_code == 2


def test_cli_bulk(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("8.8.8.8\n1.1.1.1\n# comment\n\n")
    results = [fake_result("8.8.8.8"), fake_result("1.1.1.1")]
    instance = AsyncMock()
    instance.lookup = AsyncMock(side_effect=results)
    with patch("ioc_insight.cli.Pipeline", return_value=instance):
        result = runner.invoke(app, ["--file", str(f)])
    assert result.exit_code == 0
    assert "2/2 lookups succeeded" in result.stdout
    assert "8.8.8.8" in result.stdout and "1.1.1.1" in result.stdout


def test_cli_bulk_missing_file():
    result = runner.invoke(app, ["--file", "/nonexistent/x.txt"])
    assert result.exit_code == 2


def test_cli_bulk_json(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("8.8.8.8\n")
    instance = AsyncMock()
    instance.lookup = AsyncMock(return_value=fake_result())
    with patch("ioc_insight.cli.Pipeline", return_value=instance):
        result = runner.invoke(app, ["--file", str(f), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list) and data[0]["ioc"]["value"] == "8.8.8.8"


def test_tui_module_importable():
    # full TUI interaction needs a terminal; verify it constructs
    from ioc_insight.tui import IOCInsightApp
    app_ = IOCInsightApp()
    assert app_ is not None
