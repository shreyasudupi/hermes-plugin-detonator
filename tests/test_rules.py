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
