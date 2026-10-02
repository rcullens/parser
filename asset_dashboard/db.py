"""SQLite persistence for verified asset endpoints."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from .parser import ParsedAsset

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    scheme TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER,
    path TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_line TEXT,
    ingested_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_severity ON assets(severity);
CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host);
"""

_INSERT_SQL = """
INSERT OR IGNORE INTO assets (
    url, scheme, host, port, path, severity, source_line, ingested_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA_SQL)
    return conn


def batch_insert_assets(
    conn: sqlite3.Connection,
    rows: Iterable[tuple[ParsedAsset, str]],
    *,
    ingested_at: str | None = None,
    batch_size: int = 500,
) -> int:
    """Insert verified assets with ``INSERT OR IGNORE``. Returns newly inserted count."""
    timestamp = ingested_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    buffer: list[tuple] = []
    inserted = 0

    def flush(pending: Sequence[tuple]) -> int:
        if not pending:
            return 0
        before = conn.total_changes
        conn.executemany(_INSERT_SQL, pending)
        return conn.total_changes - before

    with conn:
        for asset, severity in rows:
            buffer.append(
                (
                    asset.url,
                    asset.scheme,
                    asset.host,
                    asset.port,
                    asset.path,
                    severity,
                    asset.source_line,
                    timestamp,
                )
            )
            if len(buffer) >= batch_size:
                inserted += flush(buffer)
                buffer.clear()
        inserted += flush(buffer)
    return inserted
