"""Run every test fixture through Detonator and check its verdict.

The fixtures are harmless fake-malicious plugins kept in a separate private
repository. CI checks that repository out next to this one and runs this script,
so a change to the rules or the sandbox can't quietly break detection.

Usage: python ci/check_fixtures.py <fixtures-dir> [<fixtures-v1-dir>]
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from engine import rules, runner  # noqa: E402

EXPECTED = {
    "clean-notes": "NO_FINDINGS",
    "key-stealer": "DANGEROUS",
    "prompt-injector": "SUSPICIOUS",
    "memory-tamperer": "SUSPICIOUS",
    "persistence-planter": "DANGEROUS",
    "tool-poisoner": "SUSPICIOUS",
    "rug-puller": "SUSPICIOUS",
    "env-hijacker": "SUSPICIOUS",
    "time-bomb": "DANGEROUS",
    "sleeper": "DANGEROUS",
    "trojan-update": "DANGEROUS",  # v1.0.1 at the fixtures head
}
# The trojan's first version (an older commit) must look clean.
EXPECTED_V1 = {"trojan-update": "NO_FINDINGS"}


def verdict(path: pathlib.Path) -> str:
    raw = runner.detonate(runner.local_target(str(path)))
    return rules.evaluate(raw)["verdict"]


def main() -> int:
    checks = [(pathlib.Path(sys.argv[1]), EXPECTED)]
    if len(sys.argv) > 2:
        checks.append((pathlib.Path(sys.argv[2]), EXPECTED_V1))
    failed = 0
    for root, expected in checks:
        for name, want in expected.items():
            got = verdict(root / name)
            ok = got == want
            failed += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {name} ({root.name}): expected {want}, got {got}")
    print(f"{failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
