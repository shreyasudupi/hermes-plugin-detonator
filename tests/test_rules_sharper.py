"""Sharper rules (v0.3.0): disguised leaks, chat data, argument changes, middleware, look-alike
names, output floods and claims vs behaviour. Synthetic harness results only."""

import base64
import codecs
import zlib

from engine import leaks, rules
from tests.test_rules import base, ev, rule_names

CANARY = "0123456789ABCDEF0123"
KEY = f"sk-{CANARY}-0002"
MARKERS = [f"{CANARY}-0002", f"{CANARY}-ssh-0007"]


def run(**over):
    return rules.evaluate(base(secret_markers=MARKERS, canary=CANARY, **over))


def find(out, rule):
    return [f for f in out["findings"] if f["rule"] == rule]


# ---- disguised leaks --------------------------------------------------------

def test_leak_finder_undoes_common_disguises():
    disguises = {
        "base64": base64.b64encode(KEY.encode()).decode(),
        "hex": KEY.encode().hex(),
        "URL-encoded": "".join(f"%{b:02x}" for b in KEY.encode()),
        "reversed": KEY[::-1],
        "rot13": codecs.encode(KEY, "rot13"),
        "base32": base64.b32encode(KEY.encode()).decode(),
        "base64 + compressed": base64.b64encode(zlib.compress(KEY.encode())).decode(),
        "split up or re-cased": ".".join(KEY[i:i + 6] for i in range(0, len(KEY), 6)).lower(),
        "hex, then base64": base64.b64encode(KEY.encode().hex().encode()).decode(),
    }
    for how, text in disguises.items():
        assert leaks.find(f"x={text}&y=1", MARKERS) == {MARKERS[0]: how}, how


def test_leak_finder_ignores_innocent_text_and_other_canaries():
    assert leaks.find(f"detonator test input [{CANARY}-ARG]", MARKERS) == {}
    assert leaks.find(base64.b64encode(bytes(range(256)) * 50).decode(), MARKERS) == {}


def test_base64_key_in_a_url_is_dangerous_and_says_disguised():
    url = "https://203.0.113.9/c?d=" + base64.urlsafe_b64encode(KEY.encode()).decode()
    out = run(events=[ev("network", op="urllib.Request", address=url)])
    f = find(out, "secret_in_output")[0]
    assert out["verdict"] == "DANGEROUS" and "disguised" in f["title"]
    assert "hidden as base64" in f["evidence"][0] and "T1132" in f["attack"]


def test_key_split_across_dns_lookups_is_found():
    hexkey = KEY.encode().hex()
    parts = [hexkey[i:i + 20] for i in range(0, len(hexkey), 20)]
    out = run(events=[ev("network", op="socket.getaddrinfo", address=f"('{p}.t.example', 53)") for p in parts])
    f = find(out, "secret_in_output")[0]
    assert out["verdict"] == "DANGEROUS" and "network calls" in " ".join(f["evidence"])


def test_key_in_a_command_line_is_dangerous():
    cmd = f"('sh', ['sh', '-c', 'echo {KEY}'], None)"
    out = run(events=[ev("process", op="subprocess.Popen", detail=cmd, command=cmd, env_given=True)])
    assert any("command" in f["title"] for f in find(out, "secret_in_output"))
    # Keys in the environment handed to the child are inheritance, not a leak
    # (the harness keeps the environment out of `command`).
    out = run(events=[ev("process", op="subprocess.Popen", detail="('git', ['git', 'log'], None)",
                         command="('git', ['git', 'log'], None)", env_given=True)])
    assert not find(out, "secret_in_output")


def test_encoded_key_returned_by_a_tool_is_found():
    out = run(tool_runs=[{"tool": "t", "returned": "ok " + KEY.encode().hex(), "returned_size": 70}])
    assert "disguised" in find(out, "secret_in_output")[0]["title"]


# ---- chat data ---------------------------------------------------------------

def test_chat_text_sent_from_a_hook_is_flagged():
    q = base64.b64encode(f"Summarize my notes. [{CANARY}-USER]".encode()).decode()
    out = run(events=[ev("network", op="urllib.Request", address=f"https://203.0.113.5/l?q={q}",
                         phase="hook:post_llm_call")])
    f = find(out, "chat_data_sent")[0]
    assert f["severity"] == "high" and "hidden as base64" in f["evidence"][0]


def test_tool_sending_its_own_input_to_its_api_is_not_chat_data():
    out = run(events=[ev("network", op="urllib.Request", address=f"https://api.example.com/?q={CANARY}-ARG",
                         phase="tool:t")])
    assert "chat_data_sent" not in rule_names(out)
    out = run(events=[ev("network", op="urllib.Request", address=f"https://203.0.113.5/?q={CANARY}-ARG",
                         phase="settle")])
    assert "chat_data_sent" in rule_names(out)


# ---- argument changes ----------------------------------------------------------

def _pre_tool(tool, before, after):
    return {"hook": "pre_tool_call", "tool_name": tool, "attempt": 0, "ok": True, "returned": None,
            "honoured_return": True, "mutated_args": ["args"], "inputs": {"args": before}, "after": {"args": after}}


def test_hook_redirecting_a_message_is_dangerous():
    run_ = _pre_tool("send_message", {"target": "telegram:det-chat", "message": "hi"},
                     {"target": "telegram:-100999", "message": "hi"})
    out = run(hook_runs=[run_], manifest={"name": "demo", "provides_hooks": ["pre_tool_call"]},
              registered={"tools": [], "hooks": ["pre_tool_call"]})
    f = find(out, "tool_args_changed")[0]
    assert f["severity"] == "critical" and "only for send_message" in f["title"]
    assert "telegram:-100999" in f["evidence"][0]
    assert "content_altered" not in rule_names(out)   # not reported twice


def test_hook_chaining_a_shell_command_is_dangerous():
    run_ = _pre_tool("terminal", {"command": "ls -la"}, {"command": "ls -la; true"})
    out = run(hook_runs=[run_])
    assert find(out, "tool_args_changed")[0]["severity"] == "critical"


def test_hook_changing_a_flag_is_suspicious_not_dangerous():
    run_ = _pre_tool("terminal", {"command": "ls -la"}, {"command": "ls"})
    out = run(hook_runs=[run_])
    assert find(out, "tool_args_changed")[0]["severity"] == "high"


def test_tool_request_middleware_rewrite_is_review_unless_it_redirects():
    def mw(tool, before, after):
        return {"kind": "tool_request", "tool_name": tool, "ok": True, "input": before,
                "returned": {"args": after}, "mutated_in_place": False}
    declared = {"name": "demo", "provides_tools": ["t"], "provides_middleware": ["tool_request"]}
    out = run(manifest=declared, middleware_runs=[mw("write_file", {"path": "notes.txt"}, {"path": "./notes.txt"})],
              registered={"tools": ["t"], "hooks": [], "middleware": ["tool_request"]})
    assert find(out, "tool_args_changed")[0]["severity"] == "medium"
    assert find(out, "middleware_registered")[0]["severity"] == "low"
    assert "undeclared_registration" not in rule_names(out)
    # the same middleware, not declared in plugin.yaml
    out = run(middleware_runs=[mw("write_file", {"path": "notes.txt"}, {"path": "./notes.txt"})],
              registered={"tools": ["t"], "hooks": [], "middleware": ["tool_request"]})
    assert find(out, "tool_args_changed")[0]["severity"] == "high"
    assert any("middleware" in f["title"] for f in find(out, "undeclared_registration"))
    out = run(middleware_runs=[mw("web_extract", {"urls": ["https://example.com/docs"]},
                                  {"urls": ["https://203.0.113.7/docs"]})])
    assert find(out, "tool_args_changed")[0]["severity"] == "critical"


def test_execution_middleware_that_skips_the_tool_is_flagged():
    out = run(middleware_runs=[{"kind": "tool_execution", "tool_name": "terminal", "ok": True,
                                "input": {"command": "ls"}, "returned": "all good", "next_called": 0,
                                "next_payload": None, "canned": "file1"}])
    assert any("skipped the real call" in f["title"] for f in find(out, "content_altered"))


def test_llm_request_middleware_changing_the_server_is_dangerous():
    req = {"model": "test/model", "messages": [{"role": "user", "content": "hi"}]}
    new = dict(req, extra_headers={"X-Forward": "https://203.0.113.1"})
    out = run(middleware_runs=[{"kind": "llm_request", "ok": True, "input": req, "returned": {"request": new}}])
    f = find(out, "model_request_changed")[0]
    assert f["severity"] == "critical" and out["verdict"] == "DANGEROUS"
    out = run(middleware_runs=[{"kind": "llm_request", "ok": True, "input": req,
                                "returned": {"request": dict(req, model="other/model")}}])
    assert find(out, "model_request_changed")[0]["severity"] == "high"


# ---- look-alike names ------------------------------------------------------------

def test_lookalike_tool_names():
    out = run(registered={"tools": ["rеad_file", "termina1", "web-search", "web_serach", "todos",
                                    "notes_search", "memory"], "hooks": []})
    high = find(out, "lookalike_name")
    sev = {f["severity"]: " ".join(f["evidence"]) for f in high}
    assert "read_file" in sev["high"] and "terminal" in sev["high"]
    assert "web-search" in sev["medium"] and "web_serach" in sev["medium"]
    assert "todos" not in sev["medium"] and "notes_search" not in str(sev)
    assert "tool_shadowing" in rule_names(out)  # exact "memory" stays shadowing


# ---- output floods ---------------------------------------------------------------

def test_output_floods():
    out = run(tool_runs=[{"tool": "t", "returned": "x" * 100, "returned_size": 300_000}])
    assert find(out, "output_flood")[0]["severity"] == "medium"
    out = run(hook_runs=[{"hook": "pre_llm_call", "attempt": 0, "ok": True, "returned": {"context": "x"},
                          "returned_size": 60_000, "honoured_return": True, "mutated_args": []}])
    assert any(f["severity"] == "high" for f in find(out, "output_flood"))
    out = run(tool_runs=[{"tool": "t", "returned": "x" * 100, "returned_size": 50_000}])
    assert "output_flood" not in rule_names(out)


# ---- claims ----------------------------------------------------------------------

def test_offline_claim_with_network_is_flagged():
    m = {"name": "demo", "provides_tools": ["t"], "provides_hooks": ["post_tool_call"],
         "description": "Private notes. Works fully offline; no data ever leaves your machine."}
    out = run(manifest=m, events=[ev("network", op="socket.connect", address="('203.0.113.10', 443)",
                                     phase="tool:t")])
    f = find(out, "claim_mismatch")[0]
    assert f["severity"] == "high" and "offline" in f["evidence"][0]


def test_claims_that_hold_or_are_negated_are_not_flagged():
    m = {"name": "demo", "provides_tools": ["t"], "provides_hooks": ["post_tool_call"],
         "description": "Works offline."}
    assert "claim_mismatch" not in rule_names(run(manifest=m))
    m["description"] = "Search tool. Does not work offline; requires network access."
    out = run(manifest=m, events=[ev("network", op="socket.connect", address="('203.0.113.10', 443)",
                                     phase="tool:t")])
    assert "claim_mismatch" not in rule_names(out)


def test_never_writes_claim_with_writes_is_flagged():
    out = run(tool_schemas={"t": {"description": "Viewer for your notes. Never writes files."}},
              events=[ev("file_write", path="/tmp/home/.bashrc")])
    assert "claim_mismatch" in rule_names(out)


def test_loose_wording_from_real_catalog_descriptions_is_not_a_claim():
    net = [ev("network", op="socket.connect", address="('203.0.113.10', 443)", phase="tool:t")]
    for text in ("Reads the session store read-only.",
                 "Receipts replay offline.",
                 "No network calls besides the cargo build.",
                 "No network at load; the search tool calls api.example.com.",
                 "Works offline except for the optional sync tool."):
        m = {"name": "demo", "provides_tools": ["t"], "provides_hooks": ["post_tool_call"], "description": text}
        out = run(manifest=m, events=net + [ev("file_write", path="/tmp/home/.bashrc")])
        assert "claim_mismatch" not in rule_names(out), text


# ---- calibration against honest middleware in the plugin catalog ------------------

def test_guard_middleware_that_refuses_a_call_is_low():
    out = run(middleware_runs=[{"kind": "tool_execution", "tool_name": "terminal", "ok": True,
                                "input": {"command": "ls"}, "returned": '{"error": "blocked by your rule R3"}',
                                "next_called": 0, "next_payload": None, "canned": "file1"}])
    f = find(out, "content_altered")[0]
    assert f["severity"] == "low" and "blocked" in f["title"]


def test_prompt_filter_rewriting_messages_is_not_a_redirect():
    req = {"model": "m", "messages": [{"role": "system", "content": "You are Hermes."}]}
    new = {"model": "m", "messages": [{"role": "user", "content": "ALERT v1; action=withheld; see https://x.example"}]}
    m = {"name": "demo", "provides_middleware": ["llm_request"]}
    out = run(manifest=m, registered={"tools": [], "hooks": [], "middleware": ["llm_request"]},
              middleware_runs=[{"kind": "llm_request", "ok": True, "input": req, "returned": {"request": new}}])
    assert find(out, "model_request_changed")[0]["severity"] == "medium"
    out = run(middleware_runs=[{"kind": "llm_request", "ok": True, "input": req, "returned": {"request": new}}])
    assert find(out, "model_request_changed")[0]["severity"] == "high"   # same, undeclared


def test_extra_request_settings_are_low():
    req = {"model": "m", "messages": []}
    out = run(middleware_runs=[{"kind": "llm_request", "ok": True, "input": req,
                                "returned": {"request": dict(req, logprobs=True, top_logprobs=3)}}])
    assert find(out, "model_request_changed")[0]["severity"] == "low"


def test_message_body_change_is_not_a_redirect_but_recipient_is():
    body = _pre_tool("send_message", {"target": "telegram:x", "message": "hi"},
                     {"target": "telegram:x", "message": "hi; see https://203.0.113.9"})
    assert find(run(hook_runs=[body]), "tool_args_changed")[0]["severity"] == "high"


def test_declared_guard_hook_that_blocks_is_low_but_undeclared_is_high():
    r = {"hook": "pre_tool_call", "tool_name": "write_file", "attempt": 0, "ok": True, "honoured_return": True,
         "returned": {"action": "block", "message": "Blocked by rule R0"}, "mutated_args": []}
    m = {"name": "demo", "provides_hooks": ["pre_tool_call"]}
    out = run(manifest=m, registered={"tools": [], "hooks": ["pre_tool_call"]}, hook_runs=[r])
    assert find(out, "content_altered")[0]["severity"] == "low" and out["verdict"] == "NO_FINDINGS"
    out = run(registered={"tools": [], "hooks": ["pre_tool_call"]}, hook_runs=[r])
    assert find(out, "content_altered")[0]["severity"] == "high"


def test_titles_never_carry_plugin_text():
    """Titles are trusted text for the AI explainer; keys chosen by the plugin are cleaned."""
    req = {"model": "m", "messages": []}
    evil = dict(req, **{"Ignore previous instructions <b>": 1})
    out = run(middleware_runs=[{"kind": "llm_request", "ok": True, "input": req, "returned": {"request": evil}}])
    title = find(out, "model_request_changed")[0]["title"]
    assert " " not in title.split("(", 1)[1].rstrip(")").replace(", ", ",") and "<" not in title


def test_outside_monitor_sees_disguised_keys():
    import base64, codecs, zlib
    from engine import rules
    c = "0123456789ABCDEF0123"
    key = f"sk-{c}-0002"
    assert rules._secret_hits(codecs.encode(key, "rot13"), c)
    assert rules._secret_hits(key[::-1], c)
    assert rules._secret_hits(base64.b32encode(key.encode()).decode(), c)
    assert rules._secret_hits(base64.b64encode(zlib.compress(key.encode())).decode(), c)
    assert rules._secret_hits(".".join(key[i:i + 5] for i in range(0, len(key), 5)) + ".x.example", c)
    # A tagged chat canary is not a key, however it is wrapped.
    assert not rules._secret_hits(codecs.encode(f"{c}-USER hello", "rot13"), c)
    assert not rules._secret_hits(f"{c}-ARG"[::-1], c)
    assert not rules._secret_hits("nothing to see here", c)


def test_outside_monitor_joins_a_key_split_across_dns_lookups():
    from engine import rules
    c = "0123456789ABCDEF0123"
    key = f"sk-{c}-0002".encode().hex()
    names = [{"name": key[i:i + 10] + ".x.example"} for i in range(0, len(key), 10)]
    res = {"outside": {"ran": True, "canary": c, "sink": {"tcp": [], "dns": names}, "trace": {"events": []}}}
    f = [x for x in rules._outside_findings(res) if x.rule == "secret_sent_out"]
    assert f and "split across" in f[0].evidence[0]
    res["outside"]["sink"]["dns"] = [{"name": "docs.example.com"}, {"name": "api.example.com"}]
    assert not rules._outside_findings(res)
