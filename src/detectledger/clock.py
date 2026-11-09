"""Put every event on one trustworthy UTC clock.

Recordings mix several timestamp fields, and their labels can't be trusted:

  * Sysmon `UtcTime`   - true UTC, set by the Sysmon driver.            (trusted)
  * `EventTime`        - often local time, hours away from UTC.
  * `TimeCreated`      - sometimes ends in "Z" (claims UTC) but is still local time.
  * `@timestamp`       - when the log *collector* received the event: UTC, but seconds late,
                         and in some pipelines also mislabeled.

So instead of trusting labels, we learn each recording's offsets from the data itself. Sysmon
events carry `UtcTime` *and* the other fields, so (UtcTime - other) tells us exactly how far off
that field is. Time-zone offsets are whole multiples of 15 minutes, so we round to that, which
also strips out the few seconds of collector delay. Events without `UtcTime` (e.g. the Security
log) are then corrected by those learned offsets.
"""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta

TRUSTED = "UtcTime"
# For events without UtcTime, prefer the event's own clock over the collector's receive time.
FALLBACKS = ("TimeCreated", "EventTime", "@timestamp")
QUANTUM = timedelta(minutes=15)


def parse(value) -> datetime | None:
    """Parse the timestamp formats seen in the datasets into a naive datetime (no tz trust)."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().rstrip("Z").replace("T", " ")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _round(delta: timedelta) -> timedelta:
    return QUANTUM * round(delta / QUANTUM)


def learn_offsets(records: list[dict]) -> dict[str, timedelta]:
    """For each fallback field, the offset to ADD to it to get UTC (learned from Sysmon events)."""
    diffs: dict[str, list[timedelta]] = {f: [] for f in FALLBACKS}
    for rec in records:
        utc = parse(rec.get(TRUSTED))
        if utc is None:
            continue
        for f in FALLBACKS:
            other = parse(rec.get(f))
            if other is not None:
                diffs[f].append(utc - other)
    return {f: _round(statistics.median(d)) for f, d in diffs.items() if d}


def to_utc(record: dict, offsets: dict[str, timedelta]) -> tuple[str | None, str]:
    """Return (ISO-8601 UTC timestamp, how we got it)."""
    utc = parse(record.get(TRUSTED))
    if utc is not None:
        return _iso(utc), TRUSTED
    for f in FALLBACKS:
        value = parse(record.get(f))
        if value is not None and f in offsets:
            return _iso(value + offsets[f]), f"{f}{_fmt(offsets[f])}"
    # No Sysmon events to learn from: only trust a value that explicitly claims UTC.
    for f in FALLBACKS:
        raw = record.get(f)
        if isinstance(raw, str) and raw.endswith("Z") and (value := parse(raw)):
            return _iso(value), f"{f}(unverified)"
    return None, "none"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _fmt(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    h, m = divmod(abs(minutes), 60)
    return f"{sign}{h}h" + (f"{m:02d}m" if m else "")
