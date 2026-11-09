"""Detection regression tests: every rule against every real attack recording.

Needs the datasets loaded first:  detectledger fetch --all
(CI does this automatically; locally the tests skip with a hint if the data is missing.)
"""

from collections import Counter
from pathlib import Path

import pytest
import yaml

from detectledger.datasets import CATALOG
from detectledger.db import connect
from detectledger.sigma import load_rules, run_rule

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "events.db"
RULES = {r.path.stem: r for r in load_rules(ROOT / "rules")}
EXPECTATIONS = yaml.safe_load((Path(__file__).parent / "expectations.yml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def conn():
    if not DB.exists():
        pytest.skip("datasets not loaded; run `detectledger fetch --all`")
    c = connect(DB)
    loaded = {r[0] for r in c.execute("SELECT DISTINCT dataset FROM events")}
    missing = set(CATALOG) - loaded
    if missing:
        pytest.skip(f"datasets missing: {sorted(missing)}; run `detectledger fetch --all`")
    return c


def test_every_rule_has_expectations():
    assert set(RULES) == set(EXPECTATIONS), "rules and tests/expectations.yml are out of sync"


def test_expectations_reference_real_datasets():
    for name, exp in EXPECTATIONS.items():
        unknown = set(exp["fires_on"]) - set(CATALOG)
        assert not unknown, f"{name}: unknown datasets {unknown}"


def test_every_dataset_is_detected_by_some_rule():
    covered = {d for exp in EXPECTATIONS.values() for d in exp["fires_on"]}
    assert set(CATALOG) <= covered, f"no rule detects: {sorted(set(CATALOG) - covered)}"


@pytest.mark.parametrize("name", sorted(RULES))
def test_rule_against_all_datasets(conn, name):
    counts = Counter(a.dataset for a in run_rule(conn, RULES[name]))
    expected = EXPECTATIONS[name]["fires_on"]

    for dataset, n in expected.items():
        assert counts[dataset] == n, f"true positive: expected {n} alert(s) on {dataset}, got {counts[dataset]}"

    false_positives = {d: n for d, n in counts.items() if d not in expected}
    assert not false_positives, f"false positives on other datasets: {false_positives}"
