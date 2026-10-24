"""Lookup history — SQLite persistence. TRD §9 db.py.

Every lookup is persisted (full LookupResult JSON) so the TUI/API history
views can list past verdicts and re-open them.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .models import LookupResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS lookups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    verdict TEXT,
    confidence INTEGER,
    model TEXT,
    lang TEXT,
    duration_ms INTEGER NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lookups_created ON lookups(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_lookups_ioc ON lookups(ioc_value);
"""


class HistoryDB:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)

    def save(self, result: LookupResult) -> int:
        ai = result.ai
        cur = self._conn.execute(
            "INSERT INTO lookups (ioc_value, ioc_type, risk_score, verdict,"
            " confidence, model, lang, duration_ms, payload, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                result.ioc.value, result.ioc.type, result.risk_score,
                ai.verdict.value if ai else None,
                ai.confidence if ai else None,
                ai.model if ai else None,
                ai.lang if ai else None,
                result.duration_ms,
                result.model_dump_json(),
                time.time(),
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def list(self, limit: int = 50, offset: int = 0) -> dict:
        total = self._conn.execute("SELECT COUNT(*) FROM lookups").fetchone()[0]
        rows = self._conn.execute(
            "SELECT id, ioc_value, ioc_type, risk_score, verdict, confidence,"
            " model, lang, duration_ms, created_at FROM lookups"
            " ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        items = [
            {
                "id": r[0], "ioc_value": r[1], "ioc_type": r[2],
                "risk_score": r[3], "verdict": r[4], "confidence": r[5],
                "model": r[6], "lang": r[7], "duration_ms": r[8],
                "created_at": r[9],
            }
            for r in rows
        ]
        return {"items": items, "limit": limit, "offset": offset, "total": total}

    def get(self, lookup_id: int) -> LookupResult | None:
        row = self._conn.execute(
            "SELECT payload FROM lookups WHERE id=?", (lookup_id,)
        ).fetchone()
        if row is None:
            return None
        return LookupResult.model_validate_json(row[0])

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM lookups").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
