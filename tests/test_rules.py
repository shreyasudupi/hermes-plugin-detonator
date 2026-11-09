"""Rule tests on synthetic harness results (no plugin code runs here)."""

from engine import rules

DECOY_ENV = "/tmp/home/.hermes/.env"
MEMORY = "/tmp/home/.hermes/memories/MEMORY.md"
DATA = "/tmp/home/.hermes/plugin-data/demo"


def base(**over):
    r = {
        "manifest": {"name": "demo", "provides_tools": ["t"], "provides_hooks": ["post_tool_call"]},
        "secret_markers": ["DETONATOR-CANARY-0002"],
        "decoy_paths": [DECOY_ENV, MEMORY],
        "decoy_dirs": ["/tmp/home/.hermes", "/tmp/home/.hermes/memories"],
        "memory_paths": [MEMORY],
        "allowed_write_dirs": [DATA],
        "plugin_dir": "/plugin",
        "registered": {"tools": ["t"], "hooks": ["post_tool_call"]},
        "import": {"ok": True}, "register": {"ok": True},
        "hook_runs": [], "tool_runs": [], "events": [], "decoy_changes": [],
    }
    r.update(over)
    return r


def ev(kind, **data):
    return {"t": 0, "phase": "hook:post_tool_call", "kind": kind, **data}


def rule_names(out):
    return {f["rule"] for f in out["findings"]}


def test_clean_run_has_no_findings():
    out = rules.evaluate(base(events=[ev("file_write", path=DATA + "/log.txt")]))
    assert out["verdict"] == "NO_FINDINGS"
    assert out["findings"] == []


def test_decoy_file_read_is_dangerous():
    out = rules.evaluate(base(events=[ev("file_read", path=DECOY_ENV)]))
    assert out["verdict"] == "DANGEROUS"
    assert "decoy_accessed" in rule_names(out)


def test_undeclared_env_read_is_dangerous_but_declared_is_info():
    out = rules.evaluate(base(events=[ev("env_read", name="OPENAI_API_KEY")]))
    assert out["verdict"] == "DANGEROUS"
    m = base(events=[ev("env_read", name="OPENAI_API_KEY")])
    m["manifest"]["requires_env"] = ["OPENAI_API_KEY"]
    assert rules.evaluate(m)["verdict"] == "NO_FINDINGS"


def test_network_attempt_is_suspicious():
    out = rules.evaluate(base(events=[ev("network", op="socket.connect", address="('203.0.113.10', 443)")]))
    assert out["verdict"] == "SUSPICIOUS"
    assert "undeclared_network" in rule_names(out)


def test_prompt_injection_via_honoured_hook():
    run = {"hook": "pre_llm_call", "attempt": 0, "honoured_return": True,
           "returned": {"context": "do something else"}, "mutated_args": []}
    out = rules.evaluate(base(hook_runs=[run], registered={"tools": ["t"], "hooks": ["pre_llm_call"]}))
    assert out["verdict"] == "SUSPICIOUS"
    assert {"content_altered", "undeclared_registration"} <= rule_names(out)


def test_observer_hook_return_is_ignored():
    run = {"hook": "post_tool_call", "attempt": 0, "honoured_return": False,
           "returned": "whatever", "mutated_args": []}
    assert rules.evaluate(base(hook_runs=[run]))["verdict"] == "NO_FINDINGS"


def test_secret_leak_into_tool_result_is_dangerous():
    run = {"tool": "t", "returned": '{"x": "sk-DETONATOR-CANARY-0002"}'}
    out = rules.evaluate(base(tool_runs=[run]))
    assert out["verdict"] == "DANGEROUS"
    assert "secret_in_output" in rule_names(out)


def test_memory_change_and_command():
    out = rules.evaluate(base(decoy_changes=[MEMORY],
                              events=[ev("process", op="subprocess.Popen", detail="id")]))
    assert out["verdict"] == "SUSPICIOUS"
    assert {"content_altered", "command_run"} <= rule_names(out)


def test_write_outside_folder_vs_tmp():
    out = rules.evaluate(base(events=[ev("file_write", path="/tmp/scratch.txt")]))
    assert out["verdict"] == "NO_FINDINGS"  # low severity only
    out = rules.evaluate(base(events=[ev("file_write", path="/tmp/home/.bashrc")]))
    assert out["verdict"] == "SUSPICIOUS"


def test_harness_failure_is_error():
    assert rules.evaluate({"fatal": "boom"})["verdict"] == "ERROR"


def test_load_error_without_stand_ins_needs_review():
    out = rules.evaluate(base(register={"ok": False, "error": "boom"}))
    assert out["verdict"] == "REVIEW"
    assert "load_error" in rule_names(out)


def test_load_error_from_stand_in_is_a_coverage_note():
    out = rules.evaluate(base(register={"ok": False, "error": "TypeError: dataclass"},
                              stubbed_modules=["gateway"]))
    assert out["verdict"] == "NO_FINDINGS"
    assert {"coverage_incomplete", "coverage_stubbed_imports"} <= rule_names(out)


def test_load_error_does_not_hide_bad_behaviour():
    out = rules.evaluate(base(register={"ok": False, "error": "x"}, stubbed_modules=["gateway"],
                              events=[ev("file_read", path=DECOY_ENV)]))
    assert out["verdict"] == "DANGEROUS"


def test_env_scan_by_library_is_info_only():
    out = rules.evaluate(base(events=[ev("env_read", name="OPENAI_API_KEY", how="enumerated", by="library")]))
    assert out["verdict"] == "NO_FINDINGS"
    assert "env_enumerated" in rule_names(out)


def test_env_scan_by_plugin_needs_review():
    out = rules.evaluate(base(events=[ev("env_read", name="OPENAI_API_KEY", how="enumerated", by="plugin")]))
    assert out["verdict"] == "REVIEW"


def test_targeted_env_read_is_still_critical():
    out = rules.evaluate(base(events=[ev("env_read", name="OPENAI_API_KEY", how="direct", by="plugin")]))
    assert out["verdict"] == "DANGEROUS"


HOME = "/tmp/home"


def test_memory_read_is_review_but_secret_read_is_dangerous():
    assert rules.evaluate(base(events=[ev("file_read", path=MEMORY)]))["verdict"] == "REVIEW"
    assert rules.evaluate(base(events=[ev("file_read", path=DECOY_ENV)]))["verdict"] == "DANGEROUS"


def test_write_severity_by_location():
    def verdict(path, kind="file_write", **kw):
        return rules.evaluate(base(events=[ev(kind, path=path, **kw)]))["verdict"]
    assert verdict(HOME + "/.myplugin/state.json") == "REVIEW"          # own folder in home
    assert verdict(HOME + "/.hermes/myplugin/log.jsonl") == "REVIEW"    # own folder in Hermes home
    assert verdict(HOME + "/.hermes/plugin-data/other-name/x") == "NO_FINDINGS"
    assert verdict(HOME + "/.bashrc") == "SUSPICIOUS"
    assert verdict(HOME + "/.ssh/authorized_keys") == "SUSPICIOUS"
    assert verdict(HOME + "/.hermes/config.yaml") == "SUSPICIOUS"
    assert verdict(HOME + "/.hermes/plugins/other/__init__.py") == "SUSPICIOUS"
    assert verdict("/etc/cron.d/x") == "SUSPICIOUS"
    assert verdict("/tmp/scratch") == "NO_FINDINGS"                     # low only
    assert verdict(HOME + "/.config/autostart/x", kind="file_modify", op="os.chmod") == "SUSPICIOUS"


def test_declared_prompt_hook_is_review_undeclared_is_suspicious():
    run = {"hook": "pre_llm_call", "attempt": 0, "honoured_return": True, "returned": {"context": "time"}}
    declared = base(hook_runs=[run], registered={"tools": ["t"], "hooks": ["pre_llm_call"]},
                    manifest={"name": "d", "provides_tools": ["t"], "provides_hooks": ["pre_llm_call"]})
    assert rules.evaluate(declared)["verdict"] == "REVIEW"
    hidden = base(hook_runs=[run])
    assert rules.evaluate(hidden)["verdict"] == "SUSPICIOUS"


def test_network_by_phase_and_target():
    def verdict(address, phase):
        return rules.evaluate(base(events=[{"t": 0, "phase": phase, "kind": "network",
                                            "op": "socket.connect", "address": address}]))["verdict"]
    assert verdict("('203.0.113.10', 443)", "hook:post_tool_call") == "SUSPICIOUS"
    assert verdict("('203.0.113.10', 443)", "import") == "SUSPICIOUS"
    assert verdict("('api.example.com', 443)", "tool:t") == "REVIEW"
    assert verdict("('127.0.0.1', 23119)", "tool:t") == "REVIEW"
    assert verdict("https://x.example/?k=DETONATOR-CANARY-0002", "tool:t") == "DANGEROUS"
