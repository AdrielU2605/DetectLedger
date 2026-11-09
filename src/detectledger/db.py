"""SQLite storage for normalized Windows events.

Every event keeps its full original JSON in `raw`, so detection rules can match
any field later (via SQLite's json_extract) without us having to predict which
fields matter today. A few common fields are copied into real columns so they
can be indexed and filtered quickly.
"""

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,
    dataset   TEXT NOT NULL,      -- which recording the event came from
    ts        TEXT,               -- UTC timestamp as recorded
    event_id  INTEGER,            -- Windows/Sysmon event ID (e.g. 4688, 10)
    channel   TEXT,               -- log channel (Security, Sysmon/Operational, ...)
    provider  TEXT,               -- event source/provider name
    host      TEXT,               -- machine the event was logged on
    raw       TEXT NOT NULL       -- original event as JSON
);
CREATE INDEX IF NOT EXISTS idx_events_dataset  ON events(dataset);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (and create if needed) the events database."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn
