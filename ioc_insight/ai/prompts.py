"""System prompts per language + compact payload builder. TRD §8."""
from __future__ import annotations

import json

from ..models import AnalyzerResult, Verdict

_LANG_NAMES = {"en": "English", "de": "German (Deutsch)", "id": "Indonesian (Bahasa Indonesia)"}

_SYSTEM_TEMPLATE = """You are a senior SOC L1 triage assistant. You receive multi-source threat-intel
enrichment data for one IOC plus a deterministic heuristic risk score, and you
produce a final assessment.

Respond with STRICT JSON only — no markdown fences, no commentary:
{{"verdict": "MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN",
  "confidence": <int 0-100>,
  "explanation": "<2-4 sentences, plain language>",
  "recommended_action": "BLOCK|ESCALATE_L2|LIKELY_FALSE_POSITIVE|MONITOR|INVESTIGATE",
  "report_markdown": "<ticket-ready markdown report>"}}

Rules:
- Write ALL free-text fields (explanation, report_markdown) in {lang_name}.
- Weigh conflicting sources: explain disagreements instead of ignoring them.
- The heuristic score is a hint, not ground truth — you may override it, but say why.
- report_markdown must contain: verdict, confidence, score, action, per-source
  summary lines, short analyst summary. Keep it under 60 lines.
- If all sources failed or returned nothing, verdict=UNKNOWN, action=INVESTIGATE."""


def system_prompt(lang: str) -> str:
    return _SYSTEM_TEMPLATE.format(lang_name=_LANG_NAMES.get(lang, "English"))


def compact_results(results: list[AnalyzerResult]) -> list[dict]:
    """Trim raw payloads — key fields only, to control token usage."""
    out = []
    for r in results:
        entry = {
            "source": r.source,
            "success": r.success,
            "error": r.error,
            "malicious_votes": r.malicious_votes,
            "total_engines": r.total_engines,
            "reputation_score": r.reputation_score,
            "tags": r.tags,
            "from_cache": r.from_cache,
        }
        # WHOIS: malicious_votes carries age_days — relabel for the model
        if r.source == "whois_age" and r.success:
            entry["domain_age_days"] = r.malicious_votes
            entry.pop("malicious_votes")
            if r.raw.get("registrar"):
                entry["registrar"] = r.raw["registrar"]
        out.append(entry)
    return out


def user_prompt(ioc_value: str, ioc_type: str, risk_score: int,
                band: Verdict, results: list[AnalyzerResult]) -> str:
    payload = {
        "ioc": ioc_value,
        "type": ioc_type,
        "heuristic_score": risk_score,
        "heuristic_band": band.value,
        "sources": compact_results(results),
    }
    return "Analyze this IOC and respond with the required JSON:\n" + json.dumps(
        payload, ensure_ascii=False, default=str
    )
