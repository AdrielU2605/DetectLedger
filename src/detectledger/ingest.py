"""Load recorded Windows event logs (newline-delimited JSON) into SQLite.

The OTRF Security-Datasets recordings ship as .zip files containing one JSON
event per line. This module accepts either the .zip or a plain .json/.jsonl file.
"""

import io
import json
import sqlite3
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# Different log shippers name the same thing differently; take the first one present.
TIMESTAMP_KEYS = ("UtcTime", "@timestamp", "TimeCreated", "EventTime")
HOST_KEYS = ("Hostname", "Computer", "host")
PROVIDER_KEYS = ("SourceName", "ProviderName", "Provider_Name")

BATCH_SIZE = 1000


@dataclass
class IngestResult:
    dataset: str
    inserted: int
    skipped: int  # lines that were not valid JSON objects


def _first(record: dict, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, dict):  # e.g. ECS-style {"host": {"name": ...}}
            value = value.get("name")
        if value not in (None, ""):
            return str(value)
    return None


def _event_id(record: dict) -> int | None:
    try:
        return int(record.get("EventID"))
    except (TypeError, ValueError):
        return None


def iter_lines(path: Path) -> Iterator[str]:
    """Yield raw text lines from a .zip of JSON files or a single JSON file."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.startswith("__MACOSX") or not name.endswith((".json", ".jsonl")):
                    continue
                with zf.open(name) as fh:
                    yield from io.TextIOWrapper(fh, encoding="utf-8", errors="replace")
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            yield from fh


def normalize(record: dict, dataset: str) -> tuple:
    """Turn one raw event into a row for the events table."""
    return (
        dataset,
        _first(record, TIMESTAMP_KEYS),
        _event_id(record),
        record.get("Channel"),
        _first(record, PROVIDER_KEYS),
        _first(record, HOST_KEYS),
        json.dumps(record, ensure_ascii=False),
    )


def ingest_file(conn: sqlite3.Connection, path: str | Path, dataset: str | None = None) -> IngestResult:
    """Load one recording. Re-ingesting the same dataset name replaces its old rows."""
    path = Path(path)
    dataset = dataset or path.name.split(".")[0]
    inserted = skipped = 0
    batch: list[tuple] = []

    sql = "INSERT INTO events (dataset, ts, event_id, channel, provider, host, raw) VALUES (?,?,?,?,?,?,?)"
    with conn:  # one transaction: either the whole file loads or nothing changes
        conn.execute("DELETE FROM events WHERE dataset = ?", (dataset,))
        for line in iter_lines(path):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if not isinstance(record, dict):
                skipped += 1
                continue
            batch.append(normalize(record, dataset))
            if len(batch) >= BATCH_SIZE:
                conn.executemany(sql, batch)
                inserted += len(batch)
                batch.clear()
        if batch:
            conn.executemany(sql, batch)
            inserted += len(batch)

    return IngestResult(dataset, inserted, skipped)
