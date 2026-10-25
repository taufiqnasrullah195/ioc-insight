"""Core data models — see docs/TECHNICAL-REQUIREMENTS.md §6."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

IOCType = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]


class Verdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class RecommendedAction(str, Enum):
    BLOCK = "BLOCK"
    ESCALATE_L2 = "ESCALATE_L2"
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
    MONITOR = "MONITOR"
    INVESTIGATE = "INVESTIGATE"


class IOC(BaseModel):
    raw: str  # as pasted, possibly defanged
    value: str  # refanged, normalized
    type: IOCType


class AnalyzerResult(BaseModel):
    source: str  # "virustotal" | "abuseipdb" | "otx" | "whois_age"
    ioc: IOC
    success: bool
    error: str | None = None
    malicious_votes: int = 0
    total_engines: int = 0
    reputation_score: float | None = None  # 0–100, source-native scale
    tags: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    from_cache: bool = False


class AIAssessment(BaseModel):
    verdict: Verdict
    confidence: int = Field(ge=0, le=100)
    explanation: str
    recommended_action: RecommendedAction
    report_markdown: str
    model: str
    lang: str


class LookupResult(BaseModel):
    ioc: IOC
    risk_score: int = Field(ge=0, le=100)
    analyzer_results: list[AnalyzerResult]
    ai: AIAssessment | None = None
    duration_ms: int = 0
    mitre: list[dict] = Field(default_factory=list)  # [{id, name, sources}]


def score_band(score: int) -> Verdict:
    """Deterministic band mapping — TRD §7."""
    if score >= 75:
        return Verdict.MALICIOUS
    if score >= 50:
        return Verdict.SUSPICIOUS
    if score >= 20:
        return Verdict.UNKNOWN
    return Verdict.CLEAN
