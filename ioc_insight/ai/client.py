"""AI client — OpenAI-compatible provider (api.vleee.net / ali/kimi-k3). TRD §8.

Strict JSON output with one repair retry. On total failure the caller
(Pipeline) substitutes the heuristic fallback — AI never blocks a lookup.
"""
from __future__ import annotations

import asyncio
import json

from openai import AsyncOpenAI

from ..config import AIConfig
from ..models import AIAssessment, AnalyzerResult
from ..scoring import band_for
from .prompts import system_prompt, user_prompt

_REPAIR_SUFFIX = (
    "\n\nYour previous reply was not valid JSON. Respond again with ONLY "
    "the required JSON object — no markdown fences, no commentary."
)


class AIClient:
    def __init__(self, config: AIConfig):
        self.config = config
        self._client = AsyncOpenAI(
            base_url=config.base_url,
            api_key=config.resolved_key() or "missing-key",
            timeout=config.timeout_seconds,
        )

    async def ask(self, question: str, history_items: list[dict], lang: str = "en") -> str:
        """Free-form Q&A over lookup history. Returns plain text in `lang`."""
        from .prompts import qa_system_prompt, qa_user_prompt
        messages = [
            {"role": "system", "content": qa_system_prompt(lang)},
            {"role": "user", "content": qa_user_prompt(question, history_items)},
        ]
        return await asyncio.wait_for(
            self._complete(messages), timeout=self.config.timeout_seconds
        )

    async def assess(
        self,
        ioc_value: str,
        ioc_type: str,
        risk_score: int,
        results: list[AnalyzerResult],
        lang: str = "en",
    ) -> AIAssessment:
        band = band_for(risk_score)
        messages = [
            {"role": "system", "content": system_prompt(lang)},
            {"role": "user", "content": user_prompt(ioc_value, ioc_type, risk_score, band, results)},
        ]
        last_err: Exception | None = None
        bad_content = ""
        for attempt in (1, 2):
            try:
                content = await asyncio.wait_for(
                    self._complete(messages), timeout=self.config.timeout_seconds
                )
                data = _parse_json(content)
                return AIAssessment(
                    verdict=data["verdict"],
                    confidence=int(data["confidence"]),
                    explanation=str(data["explanation"]),
                    recommended_action=data["recommended_action"],
                    report_markdown=str(data["report_markdown"]),
                    model=self.config.model,
                    lang=lang,
                )
            except Exception as e:
                last_err = e
                if isinstance(e, (json.JSONDecodeError, ValueError, KeyError)):
                    bad_content = content  # parse/validation issue → worth one repair retry
                else:
                    break  # network/auth error → retrying won't help
            if attempt == 1:
                messages.append({"role": "assistant", "content": bad_content})
                messages.append({"role": "user", "content": _REPAIR_SUFFIX})
        raise AIUnavailableError(f"AI assessment failed: {last_err}")

    async def _complete(self, messages: list[dict]) -> str:
        kwargs: dict = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": self.config.max_tokens,
        }
        if self.config.temperature is not None:
            kwargs["temperature"] = self.config.temperature
        resp = await self._client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""

    async def health(self) -> bool:
        try:
            resp = await asyncio.wait_for(
                self._client.chat.completions.create(
                    model=self.config.model,
                    messages=[{"role": "user", "content": "ping"}],
                    max_tokens=1,
                ),
                timeout=10,
            )
            return resp.choices is not None
        except Exception:
            return False


class AIUnavailableError(Exception):
    pass


def _parse_json(text: str) -> dict:
    """Tolerant: strip markdown fences, find first {...} block."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    start = t.find("{")
    end = t.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no JSON object found in AI response")
    data = json.loads(t[start : end + 1])
    for key in ("verdict", "confidence", "explanation", "recommended_action", "report_markdown"):
        if key not in data:
            raise ValueError(f"missing key in AI response: {key}")
    return data
