"""Tests for alert merging and investigation context."""

import json

import yaml

from detectledger.alerts import context, merge_duplicates
from detectledger.db import connect
from detectledger.sigma import SYSMON, Alert, Rule

RULE = Rule.from_dict({
    "title": "t", "id": "aaaa1111-0000-0000-0000-000000000000",
    "logsource": {"product": "windows", "category": "process_creation"},
    "detection": yaml.safe_load("{sel: {Image|endswith: '\\x.exe'}, condition: sel}"),
})


def alert(rowid, ts, channel, cmd="x.exe go", host="H1"):
    return Alert(RULE, "d", rowid, ts, host, {"Channel": channel, "CommandLine": cmd})


def test_sysmon_and_security_copies_merge_and_sysmon_wins():
    sec = alert(1, "2020-01-01T00:00:01.000Z", "security")
    sysm = alert(2, "2020-01-01T00:00:01.826Z", SYSMON)
    [kept] = merge_duplicates([sec, sysm])
    assert kept is sysm and kept.merged == [sec]


def test_different_activity_or_far_apart_stays_separate():
    a = alert(1, "2020-01-01T00:00:00.000Z", SYSMON)
    b = alert(2, "2020-01-01T00:00:00.500Z", SYSMON, cmd="x.exe other")
    c = alert(3, "2020-01-01T00:00:00.700Z", SYSMON, host="H2")
    d = alert(4, "2020-01-01T00:00:09.000Z", SYSMON)
    assert len(merge_duplicates([a, b, c, d])) == 4


def test_context_returns_nearby_launches_on_same_host_only():
    conn = connect(":memory:")
    rows = [
        (1, "H1", "2020-01-01T00:00:00.000Z", "before.exe"),
        (2, "H1", "2020-01-01T00:03:00.000Z", "x.exe go"),
        (3, "H2", "2020-01-01T00:03:01.000Z", "otherhost.exe"),
        (4, "H1", "2020-01-01T00:30:00.000Z", "much_later.exe"),
    ]
    for rid, host, ts, cmd in rows:
        conn.execute(
            "INSERT INTO events (id, dataset, ts_utc, event_id, channel, host, raw) VALUES (?, 'd', ?, 1, ?, ?, ?)",
            (rid, ts, SYSMON, host, json.dumps({"CommandLine": cmd})),
        )
    a = alert(2, "2020-01-01T00:03:00.000Z", SYSMON)
    got = context(conn, a, minutes=5)
    assert [c["command_line"] for c in got] == ["before.exe", "x.exe go"]
    assert got[1]["is_alert_event"]
