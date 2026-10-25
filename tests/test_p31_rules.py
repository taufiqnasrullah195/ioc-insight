"""P3.1 tests — detection rules engine."""
from pathlib import Path

import pytest
import yaml

from ioc_insight.models import AnalyzerResult, IOC
from ioc_insight.rules import _eval_condition, evaluate, load_rules


def res(source, **kw):
    ioc = IOC(raw="x", value="x", type=kw.pop("ioc_type", "ipv4"))
    return AnalyzerResult(source=source, ioc=ioc, success=True, **kw)


IP = IOC(raw="1.2.3.4", value="1.2.3.4", type="ipv4")
DOMAIN = IOC(raw="evil.com", value="evil.com", type="domain")
HASH = IOC(raw="a" * 64, value="a" * 64, type="sha256")


# --- field resolution ---

def test_resolve_direct_field():
    r = res("abuseipdb", reputation_score=98.0)
    assert _eval_condition({"field": "abuseipdb.reputation_score", "op": "gte", "value": 80},
                           IP, [r]) is True


def test_resolve_age_days_special():
    r = res("whois_age", raw={"age_days": 9})
    assert _eval_condition({"field": "whois_age.age_days", "op": "lt", "value": 30},
                           DOMAIN, [r]) is True


def test_missing_source_is_false():
    assert _eval_condition({"field": "otx.malicious_votes", "op": "gte", "value": 1},
                           IP, []) is False


def test_failed_source_is_false():
    r = res("otx", malicious_votes=99)
    r.success = False
    assert _eval_condition({"field": "otx.malicious_votes", "op": "gte", "value": 1},
                           IP, [r]) is False


def test_contains_on_tags():
    r = res("abuseipdb", tags=["brute-force", "tor-exit"])
    assert _eval_condition({"field": "abuseipdb.tags", "op": "contains", "value": "tor-exit"},
                           IP, [r]) is True


def test_any_or_logic():
    cond = {"any": [
        {"field": "urlscan.malicious_votes", "op": "gte", "value": 1},
        {"field": "otx.malicious_votes", "op": "gte", "value": 1},
    ]}
    results = [res("otx", malicious_votes=2)]  # only otx present
    assert _eval_condition(cond, DOMAIN, results) is True
    assert _eval_condition(cond, DOMAIN, []) is False


def test_all_and_logic():
    cond = {"all": [
        {"field": "abuseipdb.reputation_score", "op": "gte", "value": 80},
        {"field": "abuseipdb.malicious_votes", "op": "gte", "value": 20},
    ]}
    ok = [res("abuseipdb", reputation_score=98.0, malicious_votes=99)]
    not_enough = [res("abuseipdb", reputation_score=98.0, malicious_votes=5)]
    assert _eval_condition(cond, IP, ok) is True
    assert _eval_condition(cond, IP, not_enough) is False


# --- full evaluate ---

def test_first_matching_rule_wins():
    rules_yaml = """
- name: rule-a
  when: { ioc_type: ipv4 }
  conditions:
    - { field: abuseipdb.reputation_score, op: gte, value: 50 }
  verdict: SUSPICIOUS
  action: MONITOR
- name: rule-b
  when: { ioc_type: ipv4 }
  conditions:
    - { field: abuseipdb.reputation_score, op: gte, value: 90 }
  verdict: MALICIOUS
  action: BLOCK
"""
    rules = load_rules_from_text(rules_yaml)
    results = [res("abuseipdb", reputation_score=98.0)]
    m = evaluate(IP, results, rules)
    assert m.name == "rule-a"  # first match wins even though b also matches


def test_no_match_returns_none():
    rules = load_rules_from_text("""
- name: needs-domain
  when: { ioc_type: domain }
  conditions:
    - { field: whois_age.age_days, op: lt, value: 30 }
  verdict: MALICIOUS
  action: BLOCK
""")
    assert evaluate(IP, [], rules) is None  # wrong ioc_type → skipped


def test_default_rules_file_loads():
    rules = load_rules(Path("/opt/data/ioc-insight/rules.yaml"))
    assert len(rules) >= 4
    assert any(r.name == "high-confidence-phishing-domain" for r in rules)


def load_rules_from_text(text):
    data = yaml.safe_load(text) or []
    from ioc_insight.rules import Rule
    out = []
    for item in data:
        when = item.get("when") or {}
        out.append(Rule(
            name=item["name"], verdict=item["verdict"], action=item["action"],
            confidence=item.get("confidence", 80), description=item.get("description", ""),
            ioc_type=when.get("ioc_type"), conditions=item.get("conditions", []),
        ))
    return out


# --- pipeline integration ---

@pytest.mark.asyncio
async def test_pipeline_rule_overrides_verdict(tmp_path):
    from ioc_insight.config import AppConfig
    from ioc_insight.pipeline import Pipeline
    cfg = AppConfig()
    cfg.cache.path = str(tmp_path / "c.db")
    cfg.history.path = str(tmp_path / "h.db")
    pipe = Pipeline(cfg)
    pipe.analyzers = []
    # inject a rule that always fires for ipv4
    from ioc_insight.rules import Rule
    pipe._rules = [Rule(name="always-block", verdict="MALICIOUS", action="BLOCK",
                        confidence=99, ioc_type="ipv4", conditions=[])]
    r = await pipe.lookup("8.8.8.8", use_ai=False, use_cache=False)
    await pipe.close()
    assert r.rule_match == "always-block"
