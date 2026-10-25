"""Deterministic composite risk scoring. TRD §7 — no AI involved.

Additive points per signal, clamped 0–100. AI may override the verdict
band, but this score is computed the same way every time.
"""
from __future__ import annotations

from .models import AnalyzerResult, Verdict

BANDS = [
    (75, Verdict.MALICIOUS),
    (50, Verdict.SUSPICIOUS),
    (20, Verdict.UNKNOWN),
    (0, Verdict.CLEAN),
]


def score(results: list[AnalyzerResult]) -> int:
    points = 0
    for r in results:
        if not r.success:
            continue  # failed/skipped analyzers contribute nothing (TRD §7)
        if r.source == "virustotal":
            v = r.malicious_votes
            points += 40 if v >= 10 else 25 if v >= 3 else 10 if v >= 1 else 0
        elif r.source == "abuseipdb":
            c = r.reputation_score or 0
            points += 35 if c >= 80 else 20 if c >= 40 else 10 if c >= 10 else 0
        elif r.source == "otx":
            p = r.malicious_votes  # pulse count
            points += 25 if p >= 5 else 10 if p >= 1 else 0
        elif r.source == "whois_age":
            age_days = r.malicious_votes  # field reuse, documented in whois_age.py
            if "no-creation-date" not in r.tags:
                points += 20 if age_days < 30 else 10 if age_days < 180 else 0
        elif r.source == "urlscan":
            # any past scan flagged malicious is a strong signal
            points += 30 if r.malicious_votes >= 1 else 0
        elif r.source == "greynoise":
            # RIOT (known benign) reduces score; malicious class raises it
            if "known-benign-service" in r.tags:
                points -= 15
            elif "class:malicious" in r.tags:
                points += 30
        elif r.source == "threatfox":
            # sightings in ThreatFox = known-bad IOC
            points += 35 if r.malicious_votes >= 3 else 25 if r.malicious_votes >= 1 else 0
        elif r.source == "urlhaus":
            points += 35 if r.malicious_votes >= 5 else 25 if r.malicious_votes >= 1 else 0
        elif r.source == "malwarebazaar":
            points += 40 if r.malicious_votes >= 1 else 0  # in MB = known malware
    return min(100, max(0, points))


def band_for(s: int) -> Verdict:
    for threshold, verdict in BANDS:
        if s >= threshold:
            return verdict
    return Verdict.CLEAN  # unreachable, satisfies type checkers
