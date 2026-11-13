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
    "info-stealer": "DANGEROUS",
    "secret-leaker": "DANGEROUS",
    "memory-snooper": "DANGEROUS",
    "env-dumper": "SUSPICIOUS",
    "backdoor-listener": "SUSPICIOUS",
    "config-hijacker": "SUSPICIOUS",
    "name-escaper": "SUSPICIOUS",
    "log-flooder": "SUSPICIOUS",
    "native-loader": "REVIEW",
    "broken-loader": "REVIEW",
    "trigger-word": "REVIEW",
    "missing-deps": "NO_FINDINGS",
    # Caught only by the outside monitor (tracer + fake internet)
    "monitor-evader": "DANGEROUS",
    "report-forger": "DANGEROUS",
    # Sharper rules: disguised leaks, middleware, argument changes, look-alikes, floods, claims
    "encoded-leaker": "DANGEROUS",
    "arg-swapper": "DANGEROUS",
    "request-rewriter": "DANGEROUS",
    "claim-breaker": "SUSPICIOUS",
    "lookalike-tools": "SUSPICIOUS",
    "output-flooder": "SUSPICIOUS",
    "chat-snooper": "SUSPICIOUS",
}
# Fixtures that must be caught by one specific finding, not just reach the verdict
# some other way: (rule, words that must be in its title).
MUST_FIND = {
    "encoded-leaker": ("secret_in_output", "disguised"),
    "arg-swapper": ("tool_args_changed", "only for send_message"),
    "request-rewriter": ("model_request_changed", "different server"),
    "claim-breaker": ("claim_mismatch", ""),
    "lookalike-tools": ("lookalike_name", "disguised"),
    "output-flooder": ("output_flood", "every turn"),
    "chat-snooper": ("chat_data_sent", ""),
}
# The trojan's first version (an older commit) must look clean.
EXPECTED_V1 = {"trojan-update": "NO_FINDINGS"}


def run(path: pathlib.Path) -> dict:
    return rules.evaluate(runner.detonate(runner.local_target(str(path))))


def main() -> int:
    checks = [(pathlib.Path(sys.argv[1]), EXPECTED)]
    if len(sys.argv) > 2:
        checks.append((pathlib.Path(sys.argv[2]), EXPECTED_V1))
    failed = 0
    fired = set()
    for root, expected in checks:
        for name, want in expected.items():
            report = run(root / name)
            got = report["verdict"]
            fired |= {f["rule"] for f in report["findings"]}
            ok = got == want
            must = MUST_FIND.get(name) if expected is EXPECTED else None
            if must and not any(f["rule"] == must[0] and must[1] in f["title"] for f in report["findings"]):
                ok = False
                got += f" without a {must[0]} finding mentioning '{must[1]}'"
            failed += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {name} ({root.name}): expected {want}, got {got}")
    # Every rule must be set off by at least one fixture, so none can break unnoticed.
    untested = sorted(set(rules.RULES) - fired)
    if untested:
        failed += 1
        print(f"FAIL no fixture sets off: {', '.join(untested)}")
    else:
        print(f"ok   all {len(rules.RULES)} rules set off by at least one fixture")
    print(f"{failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
