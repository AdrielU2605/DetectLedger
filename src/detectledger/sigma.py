"""A small Sigma rule engine.

Sigma (https://sigmahq.io) is the vendor-neutral YAML format for detection rules.
This module supports the parts of the spec our rules use:

  * logsource -> which Windows log channel + event IDs to look at
  * detection selections: field/value maps, value lists (OR), lists of maps (OR)
  * value modifiers: contains, startswith, endswith, all, re
  * wildcards (* and ?) in values, case-insensitive matching, null values
  * conditions: and / or / not / parentheses / "1 of x*" / "all of x*" / "them"

Rules are evaluated in Python against events from the SQLite store.
"""

from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

SYSMON = "Microsoft-Windows-Sysmon/Operational"


# --------------------------------------------------------------------------- logsources

@dataclass(frozen=True)
class Source:
    """One place in the logs where a Sigma logsource's events live."""
    channel: str
    event_ids: frozenset[int] | None = None   # None = any event in the channel
    aliases: tuple[tuple[str, str], ...] = ()  # Sigma field name -> this log's field name


# Security 4688 names process fields differently than Sysmon event 1.
_SEC_4688_ALIASES = (("Image", "NewProcessName"), ("ParentImage", "ParentProcessName"))

CATEGORIES: dict[str, list[Source]] = {
    "process_creation": [Source(SYSMON, frozenset({1})),
                         Source("Security", frozenset({4688}), _SEC_4688_ALIASES)],
    "network_connection": [Source(SYSMON, frozenset({3}))],
    "image_load": [Source(SYSMON, frozenset({7}))],
    "create_remote_thread": [Source(SYSMON, frozenset({8}))],
    "process_access": [Source(SYSMON, frozenset({10}))],
    "file_event": [Source(SYSMON, frozenset({11}))],
    "registry_add": [Source(SYSMON, frozenset({12}))],
    "registry_set": [Source(SYSMON, frozenset({13}))],
    "registry_event": [Source(SYSMON, frozenset({12, 13, 14}))],
    "pipe_created": [Source(SYSMON, frozenset({17, 18}))],
    "ps_module": [Source("Microsoft-Windows-PowerShell/Operational", frozenset({4103}))],
    "ps_script": [Source("Microsoft-Windows-PowerShell/Operational", frozenset({4104}))],
}

SERVICES: dict[str, list[Source]] = {
    "security": [Source("Security")],
    "system": [Source("System")],
    "sysmon": [Source(SYSMON)],
    "powershell": [Source("Microsoft-Windows-PowerShell/Operational")],
}


def resolve_logsource(logsource: dict) -> list[Source]:
    if logsource.get("product", "windows") != "windows":
        raise SigmaError(f"unsupported product: {logsource.get('product')}")
    if "category" in logsource:
        key, table = logsource["category"], CATEGORIES
    elif "service" in logsource:
        key, table = logsource["service"], SERVICES
    else:
        raise SigmaError("logsource needs a category or service")
    if key not in table:
        raise SigmaError(f"unsupported logsource: {key}")
    return table[key]


class SigmaError(ValueError):
    pass


# --------------------------------------------------------------------------- value matching

def wildcard_to_regex(value: str) -> str:
    """Sigma wildcards: * = any run of chars, ? = one char, backslash escapes * ? and \\."""
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return "".join(out)


KNOWN_MODIFIERS = {"contains", "startswith", "endswith", "all", "re"}


@dataclass
class FieldMatcher:
    field: str
    values: list[Any]
    require_all: bool
    patterns: list[re.Pattern | None]  # None = match a null/missing field
    is_regex: bool = False             # `re` modifier: search anywhere, case-sensitive

    @classmethod
    def build(cls, key: str, raw_values: Any) -> FieldMatcher:
        name, *mods = key.split("|")
        unknown = set(mods) - KNOWN_MODIFIERS
        if unknown:
            raise SigmaError(f"unsupported modifier(s) {sorted(unknown)} on {name}")
        values = raw_values if isinstance(raw_values, list) else [raw_values]

        patterns: list[re.Pattern | None] = []
        for v in values:
            if v is None:
                patterns.append(None)
                continue
            text = str(v)
            if "re" in mods:
                body = text
            else:
                body = wildcard_to_regex(text)
                if "contains" in mods:
                    body = f".*{body}.*"
                elif "startswith" in mods:
                    body = f"{body}.*"
                elif "endswith" in mods:
                    body = f".*{body}"
            flags = 0 if "re" in mods else re.IGNORECASE
            patterns.append(re.compile(body, flags | re.DOTALL))
        return cls(name, values, "all" in mods, patterns, is_regex="re" in mods)

    def matches(self, get: Callable[[str], Any]) -> bool:
        actual = get(self.field)
        text = None if actual in (None, "") else str(actual)

        def one(p: re.Pattern | None) -> bool:
            if p is None:
                return text is None
            if text is None:
                return False
            # `re` searches anywhere; everything else must match the whole value
            return bool(p.search(text) if self.is_regex else p.fullmatch(text))

        results = (one(p) for p in self.patterns)
        return all(results) if self.require_all else any(results)


@dataclass
class Selection:
    """A named detection block. Alternatives are OR'd; matchers inside one are AND'd."""
    alternatives: list[list[FieldMatcher]] = field(default_factory=list)
    keywords: list[re.Pattern] = field(default_factory=list)

    @classmethod
    def build(cls, body: Any) -> Selection:
        if isinstance(body, dict):
            return cls([[FieldMatcher.build(k, v) for k, v in body.items()]])
        if isinstance(body, list) and all(isinstance(x, dict) for x in body):
            return cls([[FieldMatcher.build(k, v) for k, v in d.items()] for d in body])
        if isinstance(body, list):  # keyword search: any value anywhere in the event
            return cls(keywords=[re.compile(f".*{wildcard_to_regex(str(k))}.*", re.I | re.S) for k in body])
        raise SigmaError(f"unsupported selection: {body!r}")

    def matches(self, get: Callable[[str], Any], event: dict) -> bool:
        if self.keywords:
            texts = [str(v) for v in event.values() if v is not None]
            return any(k.fullmatch(t) for k in self.keywords for t in texts)
        return any(all(m.matches(get) for m in alt) for alt in self.alternatives)


# --------------------------------------------------------------------------- conditions

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(condition: str) -> list[str]:
    tokens, pos = [], 0
    condition = condition.strip()
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            raise SigmaError(f"can't parse condition near: {condition[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


Evaluator = Callable[[Callable[[str], bool]], bool]


def compile_condition(condition: str, names: list[str]) -> Evaluator:
    """Parse a condition into a function that takes `is_match(selection_name) -> bool`.

    Grammar (lowest to highest precedence):  or  ->  and  ->  not  ->  atom
    """
    tokens = _tokenize(condition)
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise SigmaError(f"unexpected end of condition: {condition!r}")
        pos += 1
        return tokens[pos - 1]

    def expand(pattern: str) -> list[str]:
        if pattern == "them":
            found = [n for n in names if not n.startswith("_")]
        else:
            found = [n for n in names if fnmatch.fnmatchcase(n, pattern)]
        if not found:
            raise SigmaError(f"'{pattern}' matches no selection")
        return found

    def parse_or() -> Evaluator:
        left = parse_and()
        while peek() == "or":
            take()
            right = parse_and()
            left = (lambda a, b: lambda f: a(f) or b(f))(left, right)
        return left

    def parse_and() -> Evaluator:
        left = parse_not()
        while peek() == "and":
            take()
            right = parse_not()
            left = (lambda a, b: lambda f: a(f) and b(f))(left, right)
        return left

    def parse_not() -> Evaluator:
        if peek() == "not":
            take()
            inner = parse_not()
            return lambda f: not inner(f)
        return parse_atom()

    def parse_atom() -> Evaluator:
        tok = take()
        if tok == "(":
            inner = parse_or()
            if take() != ")":
                raise SigmaError(f"missing ')' in {condition!r}")
            return inner
        if tok.lower() in ("1", "all") and peek() == "of":
            take()
            group = expand(take())
            if tok == "1":
                return lambda f: any(f(n) for n in group)
            return lambda f: all(f(n) for n in group)
        if tok not in names:
            raise SigmaError(f"unknown selection '{tok}' in condition")
        return lambda f: f(tok)

    result = parse_or()
    if pos != len(tokens):
        raise SigmaError(f"unexpected '{tokens[pos]}' in condition {condition!r}")
    return result


# --------------------------------------------------------------------------- rules

@dataclass
class Rule:
    id: str
    title: str
    level: str
    tags: list[str]
    description: str
    falsepositives: list[str]
    sources: list[Source]
    selections: dict[str, Selection]
    condition: Evaluator
    path: Path | None = None

    @property
    def techniques(self) -> list[str]:
        """ATT&CK technique IDs from tags like 'attack.t1003.001'."""
        return [t.split(".", 1)[1].upper() for t in self.tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]

    @classmethod
    def from_dict(cls, doc: dict, path: Path | None = None) -> Rule:
        for required in ("title", "id", "logsource", "detection"):
            if required not in doc:
                raise SigmaError(f"{path or 'rule'}: missing '{required}'")
        detection = dict(doc["detection"])
        condition = detection.pop("condition", None)
        if not isinstance(condition, str):
            raise SigmaError(f"{path or doc['title']}: detection needs a single string condition")
        selections = {name: Selection.build(body) for name, body in detection.items()}
        return cls(
            id=str(doc["id"]),
            title=doc["title"],
            level=doc.get("level", "medium"),
            tags=[t.lower() for t in doc.get("tags", [])],
            description=doc.get("description", "").strip(),
            falsepositives=doc.get("falsepositives", []),
            sources=resolve_logsource(doc["logsource"]),
            selections=selections,
            condition=compile_condition(condition, list(selections)),
            path=path,
        )

    def matches(self, event: dict, source: Source) -> bool:
        aliases = dict(source.aliases)

        def get(name: str) -> Any:
            if name in event:
                return event[name]
            return event.get(aliases.get(name, name))

        cache: dict[str, bool] = {}

        def is_match(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name].matches(get, event)
            return cache[name]

        return self.condition(is_match)


def load_rules(directory: str | Path) -> list[Rule]:
    rules = []
    for path in sorted(Path(directory).rglob("*.yml")):
        with open(path, encoding="utf-8") as fh:
            rules.append(Rule.from_dict(yaml.safe_load(fh), path))
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise SigmaError(f"duplicate rule ids: {sorted(dupes)}")
    return rules


# --------------------------------------------------------------------------- running

@dataclass
class Alert:
    rule: Rule
    dataset: str
    event_rowid: int
    ts: str | None
    host: str | None
    event: dict


def run_rule(conn: sqlite3.Connection, rule: Rule, dataset: str | None = None) -> list[Alert]:
    alerts = []
    for source in rule.sources:
        # NOCASE: some collection pipelines write "security" instead of "Security"
        sql = "SELECT id, dataset, ts, host, raw FROM events WHERE channel = ? COLLATE NOCASE"
        params: list[Any] = [source.channel]
        if source.event_ids is not None:
            sql += f" AND event_id IN ({','.join('?' * len(source.event_ids))})"
            params += sorted(source.event_ids)
        if dataset:
            sql += " AND dataset = ?"
            params.append(dataset)
        for row in conn.execute(sql + " ORDER BY id", params):
            event = json.loads(row["raw"])
            if rule.matches(event, source):
                alerts.append(Alert(rule, row["dataset"], row["id"], row["ts"], row["host"], event))
    return alerts
