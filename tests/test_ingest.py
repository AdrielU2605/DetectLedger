"""Tests for loading event recordings into SQLite.

The fixture is a small hand-written file (not real telemetry) that covers the
messy cases real datasets contain: string event IDs, alternate field names,
blank lines, and junk lines.
"""

import json
import zipfile
from pathlib import Path

import pytest

from detectledger.db import connect
from detectledger.ingest import ingest_file

FIXTURE = Path(__file__).parent / "fixtures" / "mini_events.jsonl"


@pytest.fixture
def conn():
    return connect(":memory:")


def test_loads_valid_events_and_skips_junk(conn):
    result = ingest_file(conn, FIXTURE)
    assert result.inserted == 3
    assert result.skipped == 2  # "not json" line and the JSON array


def test_normalizes_common_fields(conn):
    ingest_file(conn, FIXTURE, dataset="mini")
    rows = conn.execute("SELECT * FROM events ORDER BY id").fetchall()

    assert rows[0]["event_id"] == 1
    assert rows[0]["host"] == "TESTHOST1"
    assert rows[0]["ts"] == "2024-01-01 10:00:00.000"
    assert rows[1]["event_id"] == 4688          # string "4688" became an int
    assert rows[1]["ts"] == "2024-01-01T10:00:01.000Z"  # fell back to @timestamp
    assert rows[2]["event_id"] is None          # unparseable ID stored as NULL
    assert rows[2]["host"] == "TESTHOST2"       # nested ECS-style host


def test_raw_json_is_queryable(conn):
    ingest_file(conn, FIXTURE, dataset="mini")
    (cmd,) = conn.execute(
        "SELECT json_extract(raw, '$.CommandLine') FROM events WHERE event_id = 1"
    ).fetchone()
    assert "comsvcs.dll, MiniDump" in cmd


def test_reingest_replaces_instead_of_duplicating(conn):
    ingest_file(conn, FIXTURE, dataset="mini")
    ingest_file(conn, FIXTURE, dataset="mini")
    (n,) = conn.execute("SELECT COUNT(*) FROM events").fetchone()
    assert n == 3


def test_reads_zip_archives(conn, tmp_path):
    archive = tmp_path / "recording.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("recording.json", json.dumps({"EventID": 10, "Channel": "Security"}) + "\n")
        zf.writestr("__MACOSX/._recording.json", "garbage")
    result = ingest_file(conn, archive)
    assert result.dataset == "recording"
    assert result.inserted == 1
