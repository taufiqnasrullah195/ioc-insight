"""FastAPI surface. TRD §10 — same pipeline as CLI, no logic duplication.

  POST /api/v1/lookup   {"ioc": "8.8.8.8", "lang": "en", "ai": true, "use_cache": true}
  GET  /api/v1/history  ?limit=50&offset=0   (populated from S9)
  GET  /api/v1/health   analyzer + AI reachability
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .ai.client import AIClient
from .config import load_config
from .models import LookupResult
from .normalizer import InvalidIOCError
from .pipeline import Pipeline

WEB_DIST = Path(__file__).resolve().parent.parent / "web" / "dist"


class LookupRequest(BaseModel):
    ioc: str
    lang: str | None = None
    ai: bool = True
    use_cache: bool = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.config = load_config()
    app.state.pipeline = Pipeline(app.state.config)
    yield
    await app.state.pipeline.close()


app = FastAPI(title="IOC Insight", version="0.1.0", lifespan=lifespan)


@app.post("/api/v1/lookup", response_model=LookupResult)
async def lookup(req: LookupRequest) -> LookupResult:
    if req.lang and req.lang not in ("en", "de", "id"):
        raise HTTPException(422, f"lang must be en|de|id, got {req.lang!r}")
    try:
        return await app.state.pipeline.lookup(
            req.ioc, use_cache=req.use_cache, use_ai=req.ai, lang=req.lang
        )
    except InvalidIOCError as e:
        raise HTTPException(422, str(e)) from e


@app.get("/api/v1/health")
async def health():
    cfg = app.state.config
    analyzers = {
        a.name: {"enabled": a.config.enabled, "ready": a.is_ready()}
        for a in app.state.pipeline.analyzers
    }
    ai_ok = await AIClient(cfg.ai).health()
    return {"status": "ok", "analyzers": analyzers, "ai": {"model": cfg.ai.model, "reachable": ai_ok}}


@app.get("/api/v1/history")
async def history(limit: int = 50, offset: int = 0):
    return app.state.pipeline.history.list(limit=limit, offset=offset)


@app.get("/api/v1/history/{lookup_id}", response_model=LookupResult)
async def history_item(lookup_id: int):
    result = app.state.pipeline.history.get(lookup_id)
    if result is None:
        raise HTTPException(404, f"lookup #{lookup_id} not found")
    return result


# --- production: serve the built web UI from the same port (TRD P2.1d) ---
if WEB_DIST.exists():
    app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        """SPA fallback — any non-API path serves index.html."""
        candidate = WEB_DIST / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(WEB_DIST / "index.html")
