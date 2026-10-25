"""Config loader — YAML file + ENV: indirection for secrets. See TRD §5."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"

Lang = Literal["en", "de", "id"]


class ProviderConfig(BaseModel):
    api_key: str = ""
    enabled: bool = True

    def resolved_key(self) -> str:
        """`ENV:NAME` → value of env var NAME; anything else is literal."""
        if self.api_key.startswith("ENV:"):
            return os.environ.get(self.api_key[4:], "")
        return self.api_key


class AIConfig(BaseModel):
    base_url: str = "https://api.vleee.net/v1"
    api_key: str = "ENV:HERMES_CUSTOM_API_VLEEE_NET_API_KEY"
    model: str = "ali/kimi-k3"
    temperature: float | None = None  # kimi-k3 rejects this param — omit unless set
    max_tokens: int = 4096  # reasoning model: headroom for thinking tokens
    timeout_seconds: int = 180  # reasoning model (kimi-k3) thinks before answering

    def resolved_key(self) -> str:
        if self.api_key.startswith("ENV:"):
            return os.environ.get(self.api_key[4:], "")
        return self.api_key


class CacheConfig(BaseModel):
    path: str = "data/cache.db"
    ttl_hours: dict[str, int] = Field(
        default_factory=lambda: {"ip": 24, "domain": 24, "url": 12, "hash": 168}
    )


class HistoryConfig(BaseModel):
    path: str = "data/history.db"


class DefaultsConfig(BaseModel):
    lang: Lang = "en"
    timeout_seconds: int = 15


class AppConfig(BaseModel):
    providers: dict[str, ProviderConfig] = Field(
        default_factory=lambda: {
            "virustotal": ProviderConfig(api_key="ENV:VT_API_KEY"),
            "abuseipdb": ProviderConfig(api_key="ENV:ABUSEIPDB_API_KEY"),
            "otx": ProviderConfig(api_key="ENV:OTX_API_KEY"),
            "whois_age": ProviderConfig(),  # no key needed
        }
    )
    ai: AIConfig = Field(default_factory=AIConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)


def load_config(path: Path | None = None) -> AppConfig:
    """Load config.yaml; missing file → defaults. Unknown keys rejected by pydantic."""
    path = path or CONFIG_PATH
    if not path.exists():
        return AppConfig()
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return AppConfig.model_validate(data)
