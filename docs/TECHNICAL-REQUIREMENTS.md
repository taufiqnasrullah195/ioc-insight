# TECHNICAL REQUIREMENTS — IOC Insight

**Project codename:** `ioc-insight`
**Version:** 0.1 (Phase 1 planning)
**Date:** 2026-10-24
**Author:** TheWiseParadise + Hermes
**Status:** DRAFT — awaiting approval before implementation

---

## 1. Purpose & Positioning

CLI + web tool for SOC L1 analysts: paste any IOC (IP, domain, URL, hash),
get multi-source threat-intel enrichment **plus an AI-generated verdict,
explanation, and recommended action** in EN/DE/ID — as a ticket-ready report.

**Differentiator vs. existing OSS (ioc-triage, ioc-threat-intel, ioc_checker):**
all of them stop at "collect + show raw data". None have an AI synthesis
layer, natural-language explanations, or multilingual ticket reports. That
gap is this project's reason to exist.

**Influences (feature-curated, not forked):**
- `intelowlproject/IntelOwl` — plugin analyzer pattern
- `tallcyberguy/ioc-triage` — WHOIS domain age, per-type provider dispatch
- `ryuk27/ioc-threat-intel` — auto type detection, composite risk scoring
- `ahmedel-bar/ioc_checker` — single-command CLI ergonomics

---

## 2. Scope

### Phase 1 (this document — build target)
1. IOC type auto-detection + defang/refang (IPv4, IPv6, domain, URL, MD5/SHA1/SHA256)
2. Plugin analyzer architecture (`BaseAnalyzer` interface)
3. Analyzers: VirusTotal v3, AbuseIPDB, AlienVault OTX, WHOIS domain age
4. Async parallel enrichment (asyncio + httpx)
5. SQLite cache with per-type TTL + per-key rate limiting
6. Composite risk score (0–100, deterministic rules — NOT AI-dependent)
7. **AI layer** via custom provider `api.vleee.net` (OpenAI-compatible), model `ali/kimi-k3`:
   - Verdict synthesis (MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN + confidence)
   - Natural-language explanation
   - Recommended action (block / escalate L2 / likely FP / monitor)
   - Ticket-ready markdown report in **EN / DE / ID**
8. CLI: single + file-bulk input, rich table + JSON output
9. FastAPI backend (`/api/v1/lookup`) — web UI is Phase 2, but API ships in P1
10. History DB (every lookup persisted) — Q&A over history is Phase 2

### Phase 2 (documented, NOT built in P1)
- Web dashboard (React + Vite + Tailwind)
- urlscan.io, GreyNoise, Shodan analyzers
- Passive DNS enrichment
- MITRE ATT&CK mapping
- AI Q&A over lookup history
- Docker packaging

### Explicitly Out of Scope
- Private/submit-only lookups (public data only — all queries go to public APIs)
- Feed ingestion (ThreatFox/URLhaus pullers) — this is a lookup tool, not a feed aggregator
- Auth/multi-user in P1 (single-operator tool; API key auth comes with web UI in P2)

---

## 3. Architecture

```
CLI (Typer) ──┐
              ├──► Core Pipeline ──► Normalizer ──► Enrichment Engine
Web UI (P2) ──┘      │                    │         (asyncio.gather)
                     │                    │              │
                     │                    │     ┌────────┼─────────┐
                     │                    │     ▼        ▼         ▼
                     │                    │   [VT]  [AbuseIPDB] [OTX] [WHOIS-age]
                     │                    │     │        │         │      │
                     │                    ▼     └────────┴────┬────┴──────┘
                     │              TypeDetector/      Cache layer (SQLite,
                     │              Defang/Refang      TTL + rate limit)
                     ▼
              Risk Scorer (deterministic rules → 0–100)
                     ▼
              AI Analyzer (OpenAI-compatible client → api.vleee.net,
                           model ali/kimi-k3, lang param EN/DE/ID)
                     ▼
              Report Builder (markdown / JSON / rich table)
                     ▼
              History DB (SQLite, table: lookups)
```

**Process layout (P1):** single Python process. CLI invokes pipeline directly;
FastAPI app imports the same `pipeline.py` — no service split.

---

## 4. Technology Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Language | Python 3.13 | matches host toolchain |
| Package mgmt | `uv` | host has uv, no pip (PEP 668) |
| Async HTTP | `httpx` | one client for analyzers + AI provider |
| CLI | `typer` + `rich` (one-shot) · `textual` (interactive TUI control panel) | single-command ergonomics, pretty tables, full-screen menu mode |
| TUI | `textual` | keyboard/mouse nav, real widgets — not static prints |
| API | FastAPI + uvicorn | team familiarity (it-support-platform) |
| DB | SQLite via `sqlite3` stdlib | zero-infra; Postgres migration path kept clean |
| WHOIS | `python-whois` | domain age, no API key needed |
| AI client | `openai` SDK pointed at `https://api.vleee.net/v1` | same provider family as Hermes config |
| Validation | `pydantic` v2 | IOC models, analyzer results, config |
| Tests | `pytest` + `pytest-asyncio` + `respx` (HTTP mock) | TDD per user workflow |

---

## 5. Configuration

`config.yaml` in project root (gitignored), template committed as
`config.example.yaml`:

```yaml
providers:
  virustotal:
    api_key: "ENV:VT_API_KEY"
    enabled: true
  abuseipdb:
    api_key: "ENV:ABUSEIPDB_API_KEY"
    enabled: true
  otx:
    api_key: "ENV:OTX_API_KEY"
    enabled: true
  whois_age:
    enabled: true          # no key needed

ai:
  base_url: "https://api.vleee.net/v1"
  api_key: "ENV:HERMES_CUSTOM_API_VLEEE_NET_API_KEY"
  model: "ali/kimi-k3"
  temperature: 0.2
  max_tokens: 1200
  timeout_seconds: 60

cache:
  path: "data/cache.db"
  ttl_hours: {ip: 24, domain: 24, url: 12, hash: 168}

history:
  path: "data/history.db"

defaults:
  lang: "en"               # en | de | id
  timeout_seconds: 15      # per analyzer HTTP call
```

Precedence: CLI flag > env var > config file.

---

## 6. Data Model (pydantic)

```python
IOCType = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]

class IOC(BaseModel):
    raw: str                 # as pasted (possibly defanged)
    value: str               # refanged, normalized
    type: IOCType

class AnalyzerResult(BaseModel):
    source: str              # "virustotal" | "abuseipdb" | "otx" | "whois_age"
    ioc: IOC
    success: bool
    error: str | None = None
    malicious_votes: int = 0
    total_engines: int = 0
    reputation_score: float | None = None   # 0–100, source-native if available
    tags: list[str] = []
    raw: dict = {}           # full source payload (for AI context)
    fetched_at: datetime
    from_cache: bool = False

class AIAssessment(BaseModel):
    verdict: Literal["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"]
    confidence: int          # 0–100
    explanation: str         # natural language, requested lang
    recommended_action: Literal["BLOCK", "ESCALATE_L2", "LIKELY_FALSE_POSITIVE",
                                "MONITOR", "INVESTIGATE"]
    report_markdown: str     # ticket-ready
    model: str
    lang: str

class LookupResult(BaseModel):
    ioc: IOC
    risk_score: int          # 0–100 deterministic composite
    analyzer_results: list[AnalyzerResult]
    ai: AIAssessment | None  # None when --no-ai
    duration_ms: int
```

---

## 7. Composite Risk Scoring (deterministic — no AI)

Base 0, additive, clamped 0–100:

| Signal | Points |
|--------|--------|
| VT malicious votes ≥ 10 | +40 |
| VT malicious votes 3–9 | +25 |
| VT malicious votes 1–2 | +10 |
| AbuseIPDB confidence ≥ 80% | +35 |
| AbuseIPDB confidence 40–79% | +20 |
| AbuseIPDB confidence 10–39% | +10 |
| OTX pulses ≥ 5 | +25 |
| OTX pulses 1–4 | +10 |
| Domain age < 30 days (domains only) | +20 |
| Domain age < 180 days | +10 |
| Analyzer failed/unreachable | +0 (tracked, not scored) |

Score bands: 0–19 CLEAN · 20–49 UNKNOWN · 50–74 SUSPICIOUS · 75–100 MALICIOUS.
The band feeds the AI prompt as a hint; AI verdict may override with reasoning.

---

## 8. AI Layer Design

**Client:** `openai.OpenAI(base_url=cfg.ai.base_url, api_key=...)`
**Model:** `ali/kimi-k3` (configurable)
**Prompt strategy:** system prompt defines role ("senior SOC triage assistant,
respond ONLY in {lang}"), user message contains a compact JSON of analyzer
results (raw payloads trimmed to key fields to control tokens) + score band.

**Required structured output:** strict JSON schema enforced by parsing +
one retry with "fix to valid JSON" on parse failure:
```json
{"verdict": "...", "confidence": 0, "explanation": "...",
 "recommended_action": "...", "report_markdown": "..."}
```

**Language:** `--lang en|de|id` → system prompt instructs output language;
report section headers translated via prompt, not templates.

**Failure mode:** if AI call fails/times out → result still ships with
deterministic score + rule-based fallback verdict; `ai=null`, CLI prints a
warning line. AI is an enhancement, never a blocker.

---

## 9. Module Layout

```
ioc-insight/
├── pyproject.toml
├── config.example.yaml
├── ioc_insight/
│   ├── __init__.py
│   ├── config.py            # pydantic-settings loader
│   ├── models.py            # §6
│   ├── normalizer.py        # detect type, defang/refang, validate
│   ├── cache.py             # SQLite TTL cache
│   ├── ratelimit.py         # per-provider token bucket
│   ├── pipeline.py          # orchestrates normalize→enrich→score→ai→report
│   ├── scoring.py           # §7
│   ├── analyzers/
│   │   ├── base.py          # BaseAnalyzer ABC: supports(ioc_type), analyze(ioc)
│   │   ├── virustotal.py
│   │   ├── abuseipdb.py
│   │   ├── otx.py
│   │   └── whois_age.py
│   ├── ai/
│   │   ├── client.py        # OpenAI-compatible wrapper
│   │   ├── prompts.py       # system prompts per lang
│   │   └── fallback.py      # rule-based verdict when AI down
│   ├── report/
│   │   ├── markdown.py      # ticket-ready report
│   │   └── cli_render.py    # rich tables
│   ├── db.py                # history (table: lookups)
│   ├── api.py               # FastAPI: POST /api/v1/lookup, GET /api/v1/history
│   └── cli.py               # typer app: `iocinsight <ioc>`, `--file`, `--lang`,
│                            #   `--json`, `--no-ai`, `--no-cache`
└── tests/
    ├── test_normalizer.py
    ├── test_scoring.py
    ├── test_cache.py
    ├── analyzers/test_*.py  # respx-mocked HTTP
    ├── test_ai_client.py    # mocked OpenAI
    ├── test_pipeline.py
    └── test_api.py
```

---

## 10. API Design (P1)

- `POST /api/v1/lookup`
  Request: `{"ioc": "8.8.8.8", "lang": "en", "ai": true, "use_cache": true}`
  Response: `LookupResult` JSON · 200 · `422` invalid IOC
- `GET /api/v1/history?limit=50&offset=0` → list of past `LookupResult` summaries
- `GET /api/v1/health` → `{status, analyzers: {name: enabled}, ai: reachable}`

CORS: localhost-only default. Auth: none in P1 (local tool).

---

## 11. Security Notes

- All API keys via env vars; config file only references `ENV:NAME`, never stores secrets.
- `.gitignore`: `config.yaml`, `data/`.
- No user input reaches shell; all IOCs validated by regex/pydantic before any network call.
- Outbound HTTP only to allowlisted provider hosts + configured AI base_url.
- Rate limiting respects free-tier quotas (VT: 4 req/min — enforced in `ratelimit.py`).

---

## 12. Build Plan (TDD, phased, STOP after each step)

| Step | Deliverable | Verification |
|------|-------------|--------------|
| S1 | Project scaffold (uv, pyproject, config loader, models) | `pytest` green on model tests |
| S2 | `normalizer.py` + tests (all IOC types, defang/refang, invalid input) | unit tests |
| S3 | `cache.py` + `ratelimit.py` + tests | unit tests |
| S4 | `BaseAnalyzer` + VT + AbuseIPDB + OTX + WHOIS (respx-mocked tests) | unit tests per analyzer |
| S5 | `scoring.py` + `pipeline.py` (no AI yet) + tests | integration test, mocked HTTP |
| S6 | AI layer (client, prompts EN/DE/ID, fallback) + tests (mocked) | unit tests + 1 real smoke call |
| S7 | CLI (`typer` + `rich`) | manual run on 3 real IOCs |
| S8 | FastAPI endpoints + tests | `test_api.py` green, uvicorn smoke |
| S9 | History DB + report polish | e2e test |
| S10 | README + config.example.yaml + demo run | real-run transcript in README |

**Rule:** each STEP ships complete + verified, then STOP for approval.

---

## 13. Open Decisions (resolve before S1)

- D-1: Project folder location — propose `/opt/data/ioc-insight` (greenfield, sibling of it-support-hub). **CONFIRM?**
- D-2: License for GitHub publish — propose MIT. **CONFIRM?**
- D-3: GitHub repo creation now or after S10? (default: after S10, private→public)
- D-4: AI API key env var — reuse `HERMES_CUSTOM_API_VLEEE_NET_API_KEY` from Hermes `.env`? **CONFIRM?**
