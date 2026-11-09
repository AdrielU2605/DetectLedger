"""MITRE ATT&CK coverage: which techniques the rules detect, and whether that is tested.

Exports a layer file for the official ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/):
open it there with "Open Existing Layer" -> "Upload from local" to see coverage on the full matrix.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import yaml

from .sigma import Rule


# Official ATT&CK tactics for the techniques our rules use. A rule's tags list the tactics of
# ALL its techniques, so we can't infer a single technique's tactics from them.
TACTICS = {
    "T1003": ["credential-access"],
    "T1027": ["defense-evasion"],
    "T1047": ["execution"],
    "T1053": ["execution", "persistence", "privilege-escalation"],
    "T1059": ["execution"],
    "T1136": ["persistence"],
    "T1543": ["persistence", "privilege-escalation"],
    "T1547": ["persistence", "privilege-escalation"],
    "T1569": ["execution"],
}


def load_expectations(path: str | Path) -> dict:
    p = Path(path)
    return yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}


def technique_map(rules: list[Rule], expectations: dict) -> dict[str, dict]:
    """technique ID -> {rules: [...], tactics: {...}, validated_on: {...}}"""
    out: dict[str, dict] = defaultdict(lambda: {"rules": [], "tactics": set(), "validated_on": set()})
    for r in rules:
        tested = set((expectations.get(r.path.stem if r.path else "", {}) or {}).get("fires_on", {}))
        for t in r.techniques:
            out[t]["rules"].append(r.title)
            official = TACTICS.get(t.split(".")[0])
            out[t]["tactics"].update(official or [x.replace("_", "-") for x in r.tactics])
            out[t]["validated_on"].update(tested)
    return dict(sorted(out.items()))


def navigator_layer(rules: list[Rule], expectations: dict) -> dict:
    techniques = []
    for tid, info in technique_map(rules, expectations).items():
        validated = sorted(info["validated_on"])
        techniques.append({
            "techniqueID": tid,
            "score": len(info["rules"]),
            "color": "#31a354" if validated else "#fdae61",  # green = tested in CI, orange = untested
            "comment": "Rules: " + "; ".join(info["rules"])
                       + (f". Validated in CI on: {', '.join(validated)}" if validated else ". Not validated"),
            "enabled": True,
            "showSubtechniques": True,
        })
    return {
        "name": "DetectLedger coverage",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": "Techniques detected by DetectLedger Sigma rules. Green = validated against real "
                       "attack telemetry in CI. Score = number of rules.",
        "techniques": techniques,
        "legendItems": [{"label": "Detected + validated in CI", "color": "#31a354"},
                        {"label": "Detected, not validated", "color": "#fdae61"}],
        "hideDisabled": False,
    }


def markdown_table(rules: list[Rule], expectations: dict) -> str:
    lines = ["| Technique | Tactics | Rules | Validated on |", "|---|---|---|---|"]
    for tid, info in technique_map(rules, expectations).items():
        url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        lines.append(f"| [{tid}]({url}) | {', '.join(sorted(info['tactics']))} | {len(info['rules'])} | "
                     f"{', '.join(sorted(info['validated_on'])) or '—'} |")
    return "\n".join(lines)
