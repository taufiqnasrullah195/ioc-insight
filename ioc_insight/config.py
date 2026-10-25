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


class NotifyConfig(BaseModel):
    """Telegram alerts — bot token + target chat/channel."""
    enabled: bool = False
    bot_token: str = "ENV:TELEGRAM_BOT_TOKEN"
    chat_id: str = "ENV:TELEGRAM_CHAT_ID"
    min_severity: str = "MALICIOUS"  # MALICIOUS | SUSPICIOUS | UNKNOWN | CLEAN

    def resolved_token(self) -> str:
        if self.bot_token.startswith("ENV:"):
            return os.environ.get(self.bot_token[4:], "")
        return self.bot_token

    def resolved_chat_id(self) -> str:
        if self.chat_id.startswith("ENV:"):
            return os.environ.get(self.chat_id[4:], "")
        return self.chat_id

    def is_ready(self) -> bool:
        return self.enabled and bool(self.resolved_token()) and bool(self.resolved_chat_id())


class ActionsConfig(BaseModel):
    """Automated outbound actions on BLOCK verdicts."""
    enabled: bool = False
    webhook_url: str = "ENV:ACTION_WEBHOOK_URL"  # firewall / SOAR / any HTTP endpoint

    def resolved_webhook(self) -> str:
        if self.webhook_url.startswith("ENV:"):
            return os.environ.get(self.webhook_url[4:], "")
        return self.webhook_url

    def is_ready(self) -> bool:
        return self.enabled and bool(self.resolved_webhook())


class AppConfig(BaseModel):
    providers: dict[str, ProviderConfig] = Field(
        default_factory=lambda: {
            "virustotal": ProviderConfig(api_key="ENV:VT_API_KEY"),
            "abuseipdb": ProviderConfig(api_key="ENV:ABUSEIPDB_API_KEY"),
            "otx": ProviderConfig(api_key="ENV:OTX_API_KEY"),
            "whois_age": ProviderConfig(),  # no key needed
            "urlscan": ProviderConfig(api_key="ENV:URLSCAN_API_KEY"),
            "greynoise": ProviderConfig(api_key="ENV:GREYNOISE_API_KEY"),
            # abuse.ch — one free Auth-Key (auth.abuse.ch) covers all three
            "threatfox": ProviderConfig(api_key="ENV:ABUSECH_AUTH_KEY"),
            "urlhaus": ProviderConfig(api_key="ENV:ABUSECH_AUTH_KEY"),
            "malwarebazaar": ProviderConfig(api_key="ENV:ABUSECH_AUTH_KEY"),
        }
    )
    ai: AIConfig = Field(default_factory=AIConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    actions: ActionsConfig = Field(default_factory=ActionsConfig)


def load_config(path: Path | None = None) -> AppConfig:
    """Load config.yaml; missing file → defaults. Unknown keys rejected by pydantic."""
    path = path or CONFIG_PATH
    if not path.exists():
        return AppConfig()
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return AppConfig.model_validate(data)
