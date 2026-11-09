"""Tests for timestamp normalization, using the real clock quirks seen in OTRF recordings."""

from datetime import timedelta

from detectledger import clock


def test_parses_all_formats_seen_in_datasets():
    for raw in ("2020-10-18 23:50:09.088", "2020-09-21 18:58:29", "2020-09-21T22:58:31.654Z"):
        assert clock.parse(raw) is not None
    assert clock.parse("garbage") is None
    assert clock.parse(None) is None


def test_learns_local_time_offset_and_ignores_collector_lag():
    # EventTime is local (UTC-4); @timestamp is UTC but arrives ~2.5s late.
    sysmon = [
        {"UtcTime": "2020-09-22 08:28:20.866", "EventTime": "2020-09-22 04:28:20",
         "@timestamp": "2020-09-22T08:28:23.382Z"},
        {"UtcTime": "2020-09-22 08:30:00.000", "EventTime": "2020-09-22 04:30:00",
         "@timestamp": "2020-09-22T08:30:02.100Z"},
    ]
    offsets = clock.learn_offsets(sysmon)
    assert offsets["EventTime"] == timedelta(hours=4)
    assert offsets["@timestamp"] == timedelta(0)  # seconds of lag rounded away


def test_corrects_mislabeled_z_timestamp():
    # schtask_create: TimeCreated ends in "Z" but is really UTC-5.
    sysmon = {"UtcTime": "2020-12-19 11:59:29.976", "TimeCreated": "2020-12-19T06:59:29.977Z"}
    security = {"TimeCreated": "2020-12-19T07:00:00.000Z"}
    offsets = clock.learn_offsets([sysmon])
    ts, source = clock.to_utc(security, offsets)
    assert ts == "2020-12-19T12:00:00.000Z"
    assert source == "TimeCreated+5h"


def test_trusted_utctime_wins():
    ts, source = clock.to_utc({"UtcTime": "2020-01-01 00:00:00.5", "EventTime": "1999-01-01 00:00:00"}, {})
    assert (ts, source) == ("2020-01-01T00:00:00.500Z", "UtcTime")


def test_without_sysmon_only_explicit_utc_is_used_and_flagged():
    assert clock.to_utc({"EventTime": "2020-01-01 00:00:00"}, {}) == (None, "none")
    ts, source = clock.to_utc({"@timestamp": "2020-01-01T00:00:00.000Z"}, {})
    assert ts == "2020-01-01T00:00:00.000Z" and source == "@timestamp(unverified)"
