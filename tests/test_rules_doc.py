"""docs/RULES.md must document every rule and only real rules."""

import pathlib
import re

from engine import rules

DOC = (pathlib.Path(__file__).parent.parent / "docs" / "RULES.md").read_text()


def test_every_rule_is_documented():
    documented = set(re.findall(r"^\| `([a-z_]+)` \|", DOC, re.M))
    assert documented == set(rules.RULES), set(rules.RULES) ^ documented


def test_documented_mitre_ids_match_code():
    for name, rule in rules.RULES.items():
        row = next(line for line in DOC.splitlines() if line.startswith(f"| `{name}` |"))
        for tech in rule.attack + rule.atlas:
            assert f"[{tech}]" in row, (name, tech)
