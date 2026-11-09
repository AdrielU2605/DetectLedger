"""Unit tests for the Sigma engine, using small hand-written events."""

import json

import pytest
import yaml

from detectledger.db import connect
from detectledger.sigma import SYSMON, Rule, SigmaError, Source, load_rules, run_rule

PROC = Source(SYSMON, frozenset({1}))


def rule(detection: str, category: str = "process_creation") -> Rule:
    doc = {
        "title": "test", "id": "t-1",
        "logsource": {"product": "windows", "category": category},
        "detection": yaml.safe_load(detection),
    }
    return Rule.from_dict(doc)


# ---- value matching -------------------------------------------------------------

@pytest.mark.parametrize("detection, event, expected", [
    # plain values are exact but case-insensitive
    ("{sel: {Image: 'C:\\Windows\\cmd.exe'}, condition: sel}", {"Image": "c:\\windows\\CMD.EXE"}, True),
    ("{sel: {Image: 'cmd.exe'}, condition: sel}", {"Image": "C:\\Windows\\cmd.exe"}, False),
    # modifiers
    ("{sel: {Image|endswith: '\\cmd.exe'}, condition: sel}", {"Image": "C:\\Windows\\cmd.exe"}, True),
    ("{sel: {Image|startswith: 'C:\\Users'}, condition: sel}", {"Image": "C:\\Windows\\cmd.exe"}, False),
    ("{sel: {CommandLine|contains: 'minidump'}, condition: sel}", {"CommandLine": "x MiniDump y"}, True),
    # list = OR, contains|all = AND
    ("{sel: {CommandLine|contains: [foo, bar]}, condition: sel}", {"CommandLine": "has bar"}, True),
    ("{sel: {CommandLine|contains|all: [foo, bar]}, condition: sel}", {"CommandLine": "has bar"}, False),
    ("{sel: {CommandLine|contains|all: [foo, bar]}, condition: sel}", {"CommandLine": "bar foo"}, True),
    # wildcards, and escaped wildcards. Gotcha: in Sigma `\*` is a LITERAL star, so
    # "backslash then wildcard" must be written `\\*`.
    ("{sel: {Image: 'C:\\\\*\\cmd.exe'}, condition: sel}", {"Image": "C:\\Windows\\cmd.exe"}, True),
    ("{sel: {Image: 'C:\\*\\cmd.exe'}, condition: sel}", {"Image": "C:\\Windows\\cmd.exe"}, False),
    ("{sel: {CommandLine: 'a\\*b'}, condition: sel}", {"CommandLine": "a*b"}, True),
    ("{sel: {CommandLine: 'a\\*b'}, condition: sel}", {"CommandLine": "axxb"}, False),
    # regex is case-sensitive and searches anywhere
    ("{sel: {CommandLine|re: '-[Ee]nc\\s'}, condition: sel}", {"CommandLine": "powershell -enc AAA"}, True),
    # null means the field is missing or empty
    ("{sel: {ParentImage: null}, condition: sel}", {"Image": "x"}, True),
    ("{sel: {ParentImage: null}, condition: sel}", {"ParentImage": "x"}, False),
    # numbers compare as text
    ("{sel: {EventID: 4688}, condition: sel}", {"EventID": "4688"}, True),
    # list of maps = OR of AND-blocks
    ("{sel: [{Image|endswith: a.exe}, {OriginalFileName: A.EXE}], condition: sel}", {"OriginalFileName": "a.exe"}, True),
])
def test_value_matching(detection, event, expected):
    assert rule(detection).matches(event, PROC) is expected


# ---- conditions -----------------------------------------------------------------

DETECTION = """
sel_a: {A: '1'}
sel_b: {B: '1'}
filter: {C: '1'}
"""


@pytest.mark.parametrize("condition, event, expected", [
    ("sel_a and sel_b", {"A": "1", "B": "1"}, True),
    ("sel_a and sel_b", {"A": "1"}, False),
    ("sel_a or sel_b", {"B": "1"}, True),
    ("sel_a and not filter", {"A": "1", "C": "1"}, False),
    ("1 of sel_*", {"B": "1"}, True),
    ("all of sel_*", {"B": "1"}, False),
    ("1 of them", {"C": "1"}, True),
    ("(sel_a or sel_b) and not filter", {"A": "1"}, True),
    ("not sel_a or sel_b", {"A": "1"}, False),  # `not` binds tighter than `or`
])
def test_conditions(condition, event, expected):
    r = rule(DETECTION + f"condition: {condition}")
    assert r.matches(event, PROC) is expected


@pytest.mark.parametrize("bad", ["sel_a and", "sel_a and nope", "(sel_a", "1 of zzz*", "sel_a sel_b"])
def test_bad_conditions_raise(bad):
    with pytest.raises(SigmaError):
        rule(DETECTION + f"condition: '{bad}'")


def test_unsupported_modifier_raises():
    with pytest.raises(SigmaError):
        rule("{sel: {Image|base64offset: x}, condition: sel}")


# ---- running against the store ----------------------------------------------------

def _insert(conn, channel, event_id, event):
    conn.execute(
        "INSERT INTO events (dataset, event_id, channel, raw) VALUES ('t', ?, ?, ?)",
        (event_id, channel, json.dumps(event)),
    )


def test_security_4688_uses_field_aliases_and_ignores_channel_case():
    conn = connect(":memory:")
    # Security 4688 calls the process "NewProcessName", and this pipeline lowercased the channel
    _insert(conn, "security", 4688, {"NewProcessName": "C:\\Windows\\System32\\reg.exe"})
    _insert(conn, SYSMON, 1, {"Image": "C:\\Windows\\System32\\reg.exe"})
    _insert(conn, SYSMON, 1, {"Image": "C:\\Windows\\System32\\cmd.exe"})
    r = rule("{sel: {Image|endswith: '\\reg.exe'}, condition: sel}")
    assert len(run_rule(conn, r)) == 2


def test_repo_rules_all_load():
    rules = load_rules("rules")
    assert rules, "expected at least one rule in rules/"
    for r in rules:
        assert r.techniques, f"{r.title} has no ATT&CK technique tag"
