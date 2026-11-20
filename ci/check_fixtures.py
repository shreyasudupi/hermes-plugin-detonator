"""Run every test fixture through Detonator and check its verdict.

The fixtures are harmless fake-malicious plugins kept in a separate private
repository. CI checks that repository out next to this one and runs this script,
so a change to the rules or the sandbox can't quietly break detection.

Usage: python ci/check_fixtures.py <fixtures-dir> [<fixtures-v1-dir>]
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from engine import mcp, rules, runner, skill  # noqa: E402

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
    "result-linker": "DANGEROUS",
    # Sharper rules: disguised leaks, middleware, argument changes, look-alikes, floods, claims
    "encoded-leaker": "DANGEROUS",
    "arg-swapper": "DANGEROUS",
    "request-rewriter": "DANGEROUS",
    "claim-breaker": "SUSPICIOUS",
    "lookalike-tools": "SUSPICIOUS",
    "output-flooder": "SUSPICIOUS",
    "chat-snooper": "SUSPICIOUS",
    # Clean API plugin: its own declared key to its own API is normal (REVIEW, never worse)
    "honest-api": "REVIEW",
    # Named for a tool and reading only that tool's own login file: REVIEW; showing its key to the model is theft
    "docker-status": "REVIEW",
    "kube-snitch": "DANGEROUS",
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
    "result-linker": ("result_forged", "replaced"),
    "docker-status": ("own_tool_config_read", "Docker"),
    "kube-snitch": ("secret_in_output", "returned decoy secrets"),
}
# MCP servers (fixtures repo, mcp/<name>): python -m engine.mcp mode.
EXPECTED_MCP = {
    "clean-time": "NO_FINDINGS",
    "honest-api": "REVIEW",
    "missing-sdk": "REVIEW",
    "poisoned-description": "DANGEROUS",
    "cross-tool-hijack": "SUSPICIOUS",
    "rug-pull": "DANGEROUS",
    "readonly-liar": "DANGEROUS",
    "key-stealer": "DANGEROUS",
    "sampling-abuser": "DANGEROUS",
    "phisher": "SUSPICIOUS",
    "key-stealer-node": "DANGEROUS",
    "postinstall-dropper": "DANGEROUS",
    "config-risks": "REVIEW",
    "time-bomb": "DANGEROUS",
    "hidden-bcc": "SUSPICIOUS",
    "delayed-rug-pull": "DANGEROUS",
    "open-listener": "SUSPICIOUS",
    "lookalike-name": "SUSPICIOUS",
    "result-injection": "SUSPICIOUS",
    "reverse-shell": "DANGEROUS",
    "odd-port-leak": "DANGEROUS",
    "wallet-hunter": "DANGEROUS",
    "optional-trap": "SUSPICIOUS",
    "obfuscated-payload": "SUSPICIOUS",
    "tunnel-beacon": "SUSPICIOUS",
    # A tool's own login file: only the name the person installed counts, and only that file
    "honest-kube": "REVIEW",
    "kube-token-thief": "DANGEROUS",
    "kube-overreach": "DANGEROUS",
    "name-borrower": "DANGEROUS",
}
MUST_FIND_MCP = {
    "poisoned-description": ("mcp_tool_poisoning", ""),
    "cross-tool-hijack": ("mcp_cross_tool_instructions", ""),
    "rug-pull": ("mcp_rug_pull", ""),
    "readonly-liar": ("mcp_readonly_lie", ""),
    "key-stealer": ("secret_sent_out", ""),
    "sampling-abuser": ("mcp_sampling_used", ""),
    "phisher": ("mcp_credential_request", ""),
    "missing-sdk": ("server_not_started", ""),
    "key-stealer-node": ("secret_sent_out", ""),
    "postinstall-dropper": ("mcp_install_script", "install scripts"),
    "config-risks": ("mcp_unpinned_launch", ""),
    "time-bomb": ("time_triggered", ""),
    "hidden-bcc": ("mcp_extra_recipient", ""),
    "delayed-rug-pull": ("mcp_rug_pull", ""),
    "open-listener": ("listener", ""),
    "lookalike-name": ("lookalike_name", ""),
    "result-injection": ("prompt_injection_text", "returned instructions"),
    "reverse-shell": ("reverse_shell", "/dev/tcp"),
    "odd-port-leak": ("secret_sent_out", "4433"),
    "wallet-hunter": ("browser_or_wallet_read", "wallet.dat"),
    "optional-trap": ("mcp_extra_recipient", ""),
    "obfuscated-payload": ("obfuscated_code", "helper.js"),
    "tunnel-beacon": ("collection_service", "ngrok"),
    "honest-kube": ("own_tool_config_read", "kube"),
    "kube-token-thief": ("secret_sent_out", ""),
    "kube-overreach": ("decoy_accessed", ".aws/credentials"),
    "name-borrower": ("decoy_accessed", ".kube/config"),
}
# Skills (fixtures repo, skills/<name>): /detonate-skill, full test.
EXPECTED_SKILL = {
    "clean-notes-skill": "NO_FINDINGS",
    "honest-api-skill": "NO_FINDINGS",
    "honest-installer": "LOW_COVERAGE",
    "missing-tool": "LOW_COVERAGE",
    "fake-prereq-lure": "DANGEROUS",
    "key-stealer-skill": "DANGEROUS",
    "hidden-instructions": "DANGEROUS",
    "comment-injector": "SUSPICIOUS",
    "persistence-skill": "DANGEROUS",
    "reverse-shell-skill": "DANGEROUS",
    "trojan-helper": "DANGEROUS",
    "time-bomb-skill": "DANGEROUS",
    "catch-all-poisoner": "SUSPICIOUS",
    "packed-script": "REVIEW",
    "env-dumper-skill": "DANGEROUS",
    "agent-hijacker": "SUSPICIOUS",
    "kitchen-sink-setup": "REVIEW",
    "package-user": "NO_FINDINGS",
    "background-helper": "REVIEW",
    "padded-skill": "REVIEW",
    "utf16-skill": "REVIEW",
}
MUST_FIND_SKILL = {
    "fake-prereq-lure": ("skill_ran_downloaded_code", "203.0.113.7"),
    "trojan-helper": ("skill_ran_downloaded_code", "203.0.113.8"),
    "honest-installer": ("skill_ran_downloaded_code", "instructions name"),
    "honest-api-skill": ("skill_declared_host", "api.weatherx.example.com"),
    "key-stealer-skill": ("decoy_accessed", ".aws/credentials"),
    "hidden-instructions": ("skill_hidden_text", "invisible"),
    "time-bomb-skill": ("time_triggered", ""),
    "env-dumper-skill": ("secret_sent_out", ""),
    "reverse-shell-skill": ("reverse_shell", "bash -i"),
    "persistence-skill": ("persistence", ".bashrc"),
    "package-user": ("skill_tool_own_config", "npmrc"),
    "background-helper": ("skill_left_running", "detonator-fixture"),
    "padded-skill": ("skill_not_fully_read", "SKILL.md"),
    "utf16-skill": ("skill_odd_encoding", "UTF-16"),
}
# Findings a fixture must NOT have, in any mode: a key thief named for its tool must never be
# let off as only reading its own login file.
MUST_NOT_FIND = {
    "kube-token-thief": "own_tool_config_read",
    "kube-snitch": "own_tool_config_read",
    "name-borrower": "own_tool_config_read",
}
# The trojan's first version (an older commit) must look clean.
EXPECTED_V1 = {"trojan-update": "NO_FINDINGS"}


def run(path: pathlib.Path) -> dict:
    return rules.evaluate(runner.detonate(runner.local_target(str(path))))


def run_mcp(path: pathlib.Path) -> dict:
    return mcp.evaluate(mcp.detonate(mcp.load_folder_entry(str(path))))


def run_skill(path: pathlib.Path) -> dict:
    return skill.evaluate(skill.detonate(skill.SkillTarget(path=path, label=path.name)))


def main() -> int:
    checks = [(pathlib.Path(sys.argv[1]), EXPECTED)]
    if (pathlib.Path(sys.argv[1]) / "mcp").is_dir():
        checks.append((pathlib.Path(sys.argv[1]) / "mcp", EXPECTED_MCP))
    if (pathlib.Path(sys.argv[1]) / "skills").is_dir():
        checks.append((pathlib.Path(sys.argv[1]) / "skills", EXPECTED_SKILL))
    if len(sys.argv) > 2:
        checks.append((pathlib.Path(sys.argv[2]), EXPECTED_V1))
    failed = 0
    fired = set()
    for root, expected in checks:
        for name, want in expected.items():
            if not (root / name).is_dir():
                failed += 1
                print(f"FAIL {name} ({root.name}): fixture folder missing (is the fixtures repo up to date?)")
                continue
            report = run_mcp(root / name) if expected is EXPECTED_MCP else \
                run_skill(root / name) if expected is EXPECTED_SKILL else run(root / name)
            got = report["verdict"]
            fired |= {f["rule"] for f in report["findings"]}
            ok = got == want
            must = MUST_FIND.get(name) if expected is EXPECTED else \
                MUST_FIND_MCP.get(name) if expected is EXPECTED_MCP else \
                MUST_FIND_SKILL.get(name) if expected is EXPECTED_SKILL else None
            if must and not any(f["rule"] == must[0] and (must[1] in f["title"] or any(
                    must[1] in str(e) for e in f.get("evidence") or [])) for f in report["findings"]):
                ok = False
                got += f" without a {must[0]} finding mentioning '{must[1]}'"
            banned = MUST_NOT_FIND.get(name) if expected is not EXPECTED_V1 else None
            if banned and any(f["rule"] == banned for f in report["findings"]):
                ok = False
                got += f" with a {banned} finding it must not have"
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
