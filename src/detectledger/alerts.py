"""Alert timeline and investigation context, shared by the CLI and the MCP server."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta

from .sigma import Alert, Rule, run_rule

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

# The fields an analyst looks at first, in reading order. Only those present are shown.
KEY_FIELDS = (
    "User", "SubjectUserName", "SubjectDomainName", "TargetUserName",
    "Image", "NewProcessName", "CommandLine", "ParentImage", "ParentProcessName", "ParentCommandLine",
    "SourceImage", "TargetImage", "GrantedAccess",
    "ServiceName", "ImagePath", "ServiceFileName",
    "TargetObject", "Details", "Properties", "AccessMask",
)


def key_fields(event: dict, max_len: int = 300) -> dict:
    out = {}
    for f in KEY_FIELDS:
        v = event.get(f)
        if v in (None, "", "-"):
            continue
        text = " ".join(str(v).split())  # collapse tabs/newlines (4662 Properties are multi-line)
        out[f] = text if len(text) <= max_len else text[:max_len] + "…"
    return out


MERGE_WINDOW = timedelta(seconds=2)


def _signature(a: Alert) -> tuple:
    """What makes two alerts 'the same activity' (beyond rule + host)."""
    e = a.event
    return (
        (e.get("CommandLine") or e.get("ImagePath") or e.get("Details")
         or e.get("TargetImage") or e.get("SubjectUserName") or "").lower(),
        (e.get("SourceImage") or "").lower(),
    )


def _is_sysmon(a: Alert) -> bool:
    return "sysmon" in str(a.event.get("Channel", "")).lower()


def _time(a: Alert) -> datetime | None:
    return datetime.fromisoformat(a.ts.rstrip("Z")) if a.ts else None


def merge_duplicates(alerts: list[Alert]) -> list[Alert]:
    """Fold alerts for the same rule/host/activity within 2s into one.

    The same process launch is usually logged twice (Sysmon 1 + Security 4688). We keep the
    Sysmon copy as the representative because its UtcTime has millisecond precision.
    """
    kept: list[Alert] = []
    open_groups: dict[tuple, Alert] = {}
    for a in sorted(alerts, key=lambda x: x.ts or ""):
        key = (a.rule.id, (a.host or "").lower(), _signature(a))
        head = open_groups.get(key)
        t, th = _time(a), (_time(head) if head else None)
        if head and t and th and t - th <= MERGE_WINDOW:
            if _is_sysmon(a) and not _is_sysmon(head):  # promote the more precise copy
                a.merged = head.merged + [head]
                head.merged = []
                kept[next(i for i, k in enumerate(kept) if k is head)] = a
                open_groups[key] = a
            else:
                head.merged.append(a)
            continue
        kept.append(a)
        open_groups[key] = a
    return kept


def all_alerts(conn: sqlite3.Connection, rules: list[Rule], dataset: str | None = None,
               merge: bool = True) -> list[Alert]:
    """Every alert from every rule, oldest first (ties: most severe first)."""
    alerts = [a for r in rules for a in run_rule(conn, r, dataset)]
    if merge:
        alerts = merge_duplicates(alerts)
    alerts.sort(key=lambda a: (a.ts or "", LEVEL_ORDER.get(a.rule.level, 9)))
    return alerts


def find_alert(conn: sqlite3.Connection, rules: list[Rule], alert_id: str) -> Alert | None:
    prefix, _, rowid = alert_id.partition("-")
    if not rowid.isdigit():
        return None
    for rule in rules:
        if rule.id.split("-")[0] != prefix:
            continue
        row = conn.execute("SELECT dataset FROM events WHERE id = ?", (int(rowid),)).fetchone()
        if row is None:
            return None
        for a in run_rule(conn, rule, row["dataset"]):
            if a.event_rowid == int(rowid):
                return a
    return None


def alert_to_dict(a: Alert) -> dict:
    return {
        "alert_id": a.id,
        "time_utc": a.ts,
        "host": a.host,
        "dataset": a.dataset,
        "rule": a.rule.title,
        "rule_id": a.rule.id,
        "level": a.rule.level,
        "attack_techniques": a.rule.techniques,
        "event_id": a.event.get("EventID"),
        "fields": key_fields(a.event),
        "duplicate_events_merged": len(a.merged),
    }


def context(conn: sqlite3.Connection, alert: Alert, minutes: int = 5, limit: int = 40) -> list[dict]:
    """Process launches on the same host within +/- `minutes` of the alert.

    Uses Sysmon event 1 only (Security 4688 duplicates it) so each process appears once.
    """
    if not alert.ts or not alert.host:
        return []
    center = datetime.fromisoformat(alert.ts.rstrip("Z"))
    lo = (center - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
    hi = (center + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.999Z")
    rows = conn.execute(
        """SELECT id, ts_utc, raw FROM events
           WHERE dataset = ? AND host = ? AND event_id = 1
             AND channel = 'Microsoft-Windows-Sysmon/Operational' COLLATE NOCASE
             AND ts_utc BETWEEN ? AND ?
           ORDER BY ts_utc LIMIT ?""",
        (alert.dataset, alert.host, lo, hi, limit),
    ).fetchall()
    out = []
    for r in rows:
        e = json.loads(r["raw"])
        out.append({
            "time_utc": r["ts_utc"],
            "is_alert_event": r["id"] == alert.event_rowid,
            "user": e.get("User"),
            "image": e.get("Image"),
            "command_line": e.get("CommandLine"),
            "parent_image": e.get("ParentImage"),
        })
    return out
