"""Rule-based fallback when the AI provider is unreachable. TRD §8.

Never blocks the result — deterministic score band becomes the verdict.
"""
from __future__ import annotations

from ..models import (
    AIAssessment,
    AnalyzerResult,
    RecommendedAction,
    Verdict,
)
from ..normalizer import defang
from ..scoring import band_for

_ACTION_BY_VERDICT = {
    Verdict.MALICIOUS: RecommendedAction.BLOCK,
    Verdict.SUSPICIOUS: RecommendedAction.ESCALATE_L2,
    Verdict.CLEAN: RecommendedAction.MONITOR,
    Verdict.UNKNOWN: RecommendedAction.INVESTIGATE,
}

_ACTION_LABEL = {
    "en": {RecommendedAction.BLOCK: "BLOCK at perimeter", RecommendedAction.ESCALATE_L2: "Escalate to L2",
           RecommendedAction.LIKELY_FALSE_POSITIVE: "Likely false positive — close",
           RecommendedAction.MONITOR: "Monitor", RecommendedAction.INVESTIGATE: "Investigate manually"},
    "de": {RecommendedAction.BLOCK: "Am Perimeter BLOCKIEREN", RecommendedAction.ESCALATE_L2: "An L2 eskalieren",
           RecommendedAction.LIKELY_FALSE_POSITIVE: "Vermutlich Fehlalarm — schließen",
           RecommendedAction.MONITOR: "Beobachten", RecommendedAction.INVESTIGATE: "Manuell untersuchen"},
    "id": {RecommendedAction.BLOCK: "BLOKIR di perimeter", RecommendedAction.ESCALATE_L2: "Eskalasi ke L2",
           RecommendedAction.LIKELY_FALSE_POSITIVE: "Kemungkinan false positive — tutup",
           RecommendedAction.MONITOR: "Pantau", RecommendedAction.INVESTIGATE: "Investigasi manual"},
}


def fallback_assessment(
    ioc_value: str, ioc_type: str, risk_score: int,
    results: list[AnalyzerResult], lang: str, reason: str,
) -> AIAssessment:
    verdict = band_for(risk_score)
    action = _ACTION_BY_VERDICT[verdict]
    labels = _ACTION_LABEL.get(lang, _ACTION_LABEL["en"])
    ok = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    lines = [
        f"## IOC Triage — {defang(ioc_value)}",
        f"**Verdict:** {verdict.value} (heuristic) · **Score:** {risk_score}/100",
        f"**Action:** {labels[action]}",
        "",
        "### Sources",
    ]
    for r in ok:
        lines.append(f"- {r.source}: votes={r.malicious_votes} "
                     f"score={r.reputation_score} tags={','.join(r.tags) or '-'}")
    for r in failed:
        lines.append(f"- {r.source}: unavailable ({r.error})")
    lines += ["", f"*AI unavailable ({reason}) — verdict from heuristic score only.*"]
    report = "\n".join(lines)

    explanation = {
        "en": f"Automated heuristic assessment: score {risk_score}/100 maps to {verdict.value}. "
              f"{len(ok)} source(s) responded, {len(failed)} unavailable. AI analysis unavailable.",
        "de": f"Automatische Heuristik: Score {risk_score}/100 entspricht {verdict.value}. "
              f"{len(ok)} Quelle(n) antworteten, {len(failed)} nicht verfügbar. KI-Analyse nicht verfügbar.",
        "id": f"Penilaian heuristik otomatis: skor {risk_score}/100 terpetakan ke {verdict.value}. "
              f"{len(ok)} sumber merespons, {len(failed)} tidak tersedia. Analisis AI tidak tersedia.",
    }.get(lang, "")

    return AIAssessment(
        verdict=verdict, confidence=risk_score, explanation=explanation,
        recommended_action=action, report_markdown=report,
        model="heuristic-fallback", lang=lang,
    )
