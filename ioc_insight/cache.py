"""SQLite TTL cache for analyzer results. TRD §5 cache config.

One row per (source, ioc_value). TTL is per IOC type from config;
expired rows are treated as misses and overwritten on next store.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .models import AnalyzerResult, IOC

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    source TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    PRIMARY KEY (source, ioc_value)
);
"""


class Cache:
    def __init__(self, path: str, ttl_hours: dict[str, int]):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        # normalize ttl keys: ipv4/ipv6→ip, md5/sha1/sha256→hash
        self._ttl = dict(ttl_hours)

    def _ttl_for(self, ioc_type: str) -> float:
        if ioc_type in ("ipv4", "ipv6"):
            key = "ip"
        elif ioc_type in ("md5", "sha1", "sha256"):
            key = "hash"
        else:
            key = ioc_type
        return self._ttl.get(key, 24) * 3600

    def get(self, source: str, ioc: IOC) -> AnalyzerResult | None:
        row = self._conn.execute(
            "SELECT payload, fetched_at FROM cache WHERE source=? AND ioc_value=?",
            (source, ioc.value),
        ).fetchone()
        if row is None:
            return None
        payload, fetched_at = row
        if time.time() - fetched_at > self._ttl_for(ioc.type):
            return None  # expired → miss
        data = json.loads(payload)
        data["ioc"] = ioc.model_dump()
        data["from_cache"] = True
        return AnalyzerResult.model_validate(data)

    def store(self, result: AnalyzerResult) -> None:
        data = result.model_dump(mode="json")
        data.pop("from_cache", None)
        self._conn.execute(
            "INSERT OR REPLACE INTO cache (source, ioc_value, ioc_type, payload, fetched_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                result.source,
                result.ioc.value,
                result.ioc.type,
                json.dumps(data),
                time.time(),
            ),
        )
        self._conn.commit()

    def clear(self) -> int:
        cur = self._conn.execute("DELETE FROM cache")
        self._conn.commit()
        return cur.rowcount

    def close(self) -> None:
        self._conn.close()
