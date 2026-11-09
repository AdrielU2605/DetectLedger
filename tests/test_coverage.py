"""Tests for ATT&CK coverage output."""

from pathlib import Path

from detectledger.coverage import load_expectations, navigator_layer, technique_map
from detectledger.sigma import load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "rules")
EXP = load_expectations(ROOT / "tests" / "expectations.yml")


def test_every_technique_is_validated_in_ci():
    untested = [t for t, info in technique_map(RULES, EXP).items() if not info["validated_on"]]
    assert not untested, f"techniques with no CI validation: {untested}"


def test_uses_official_tactics_not_rule_union():
    m = technique_map(RULES, EXP)
    assert m["T1027"]["tactics"] == {"defense-evasion"}      # rule also tags execution
    assert m["T1003.001"]["tactics"] == {"credential-access"}


def test_navigator_layer_shape():
    layer = navigator_layer(RULES, EXP)
    assert layer["domain"] == "enterprise-attack"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1003.001", "T1047", "T1059.001"} <= ids
    assert all(t["color"] == "#31a354" for t in layer["techniques"])  # all validated


def test_committed_layer_is_up_to_date():
    """docs/attack-navigator-layer.json must be regenerated when rules change."""
    import json
    committed = json.loads((ROOT / "docs" / "attack-navigator-layer.json").read_text(encoding="utf-8"))
    assert committed == navigator_layer(RULES, EXP), "run: detectledger coverage --navigator docs/attack-navigator-layer.json"
