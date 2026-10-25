"""Detection rules engine. TRD P3.1.

Analyst-authored rules in rules.yaml evaluated against enrichment results.
First matching rule wins → deterministic verdict + action. AI explains,
it never decides.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import AnalyzerResult, IOC, Verdict

RULES_PATH = Path(__file__).resolve().parent.parent / "rules.yaml"

_OPS = {}


def _op(name):
    def deco(fn):
        _OPS[name] = fn
        return fn
    return deco


@_op("eq")
def _eq(a, b): return a == b

@_op("ne")
def _ne(a, b): return a != b

@_op("lt")
def _lt(a, b): return a is not None and a < b

@_op("lte")
def _lte(a, b): return a is not None and a <= b

@_op("gt")
def _gt(a, b): return a is not None and a > b

@_op("gte")
def _gte(a, b): return a is not None and a >= b

@_op("contains")
def _contains(a, b): return a is not None and b in a

@_op("exists")
def _exists(a, b): return a is not None

@_op("not_exists")
def _not_exists(a, b): return a is None


@dataclass
class RuleMatch:
    name: str
    verdict: Verdict
    action: str
    confidence: int
    description: str = ""


@dataclass
class Rule:
    name: str
    verdict: str
    action: str
    confidence: int = 80
    description: str = ""
    ioc_type: str | None = None
    conditions: list = field(default_factory=list)


def _resolve_field(field: str, ioc: IOC, results: list[AnalyzerResult]):
    """Resolve 'source.attr' against analyzer results.

    Special: 'whois_age.age_days' reads raw.age_days; otherwise
    attr is a direct AnalyzerResult field. Returns None if source absent/failed.
    """
    if "." not in field:
        return None
    source, attr = field.split(".", 1)
    res = next((r for r in results if r.source == source and r.success), None)
    if res is None:
        return None
    if attr == "age_days":
        return res.raw.get("age_days")
    return getattr(res, attr, None)


def _eval_condition(cond: dict, ioc: IOC, results: list[AnalyzerResult]) -> bool:
    # `any:` = OR over sub-conditions
    if "any" in cond:
        return any(_eval_condition(c, ioc, results) for c in cond["any"])
    if "all" in cond:
        return all(_eval_condition(c, ioc, results) for c in cond["all"])

    fname = cond.get("field", "")
    op = cond.get("op", "eq")
    value = cond.get("value")
    actual = _resolve_field(fname, ioc, results)
    fn = _OPS.get(op)
    if fn is None:
        return False
    return bool(fn(actual, value))


def load_rules(path: Path | None = None) -> list[Rule]:
    path = path or RULES_PATH
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    rules = []
    for item in data:
        when = item.get("when") or {}
        rules.append(Rule(
            name=item["name"],
            verdict=item["verdict"],
            action=item["action"],
            confidence=item.get("confidence", 80),
            description=item.get("description", ""),
            ioc_type=when.get("ioc_type"),
            conditions=item.get("conditions", []),
        ))
    return rules


def evaluate(ioc: IOC, results: list[AnalyzerResult],
             rules: list[Rule]) -> RuleMatch | None:
    """First matching rule wins. Returns None if nothing matches."""
    for rule in rules:
        if rule.ioc_type and rule.ioc_type != ioc.type:
            continue
        if all(_eval_condition(c, ioc, results) for c in rule.conditions):
            return RuleMatch(
                name=rule.name, verdict=Verdict(rule.verdict),
                action=rule.action, confidence=rule.confidence,
                description=rule.description,
            )
    return None
