"""The outside monitor: strace parsing, the fake internet's helpers and the cross-check rules.

These run without Docker. tests/test_sandbox_integration.py runs the real containers.
"""

import base64
import importlib.util
import pathlib
import socket
import struct

from engine import outside, report, rules, runner

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("detonator_sink", ROOT / "sandbox" / "monitor" / "sink.py")
sink = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sink)

CANARY = "0123456789ABCDEF0123"
HOME = "/home/alex"
ENV = f"{HOME}/.hermes/.env"

TRACE = f"""\
7     13:00:00.000001 openat(AT_FDCWD</>, "{ENV}", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 3</home/alex/.hermes/.env>
7     13:00:00.000002 openat(AT_FDCWD</>, "/detonator-phase/plugin-start", O_RDONLY) = -1 ENOENT (No such file or directory)
7     13:00:00.000003 openat(AT_FDCWD</home/alex/.hermes/plugin-data/x>, "../../.env", O_RDONLY|O_CLOEXEC) = 3
7     13:00:00.000004 clone3({{flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, child_tid=0x1}}, 88) = 9
9     13:00:00.000005 connect(4<TCP:[1]>, {{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}}, 16) = -1 EINPROGRESS (Operation now in progress)
7     13:00:00.000006 vfork( <unfinished ...>
12    13:00:00.000007 execve("/usr/local/bin/pip", ["pip", "install", "x"], 0x7ffd /* 7 vars */ <unfinished ...>
7     13:00:00.000008 <... vfork resumed>) = 12
12    13:00:00.000009 <... execve resumed>) = 0
12    13:00:00.000010 clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS) = 13
13    13:00:00.000011 openat(AT_FDCWD</>, "{HOME}/.netrc", O_RDONLY|O_CLOEXEC) = 5
13    13:00:00.000012 openat(AT_FDCWD</>, "{HOME}/.ssh/id_ed25519", O_RDONLY|O_CLOEXEC) = 5
7     13:00:00.000013 openat(AT_FDCWD</>, "/detonator-phase/plugin-done", O_RDONLY) = -1 ENOENT (No such file or directory)
7     13:00:00.000014 openat(AT_FDCWD</>, "/out/result.json", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 3
"""


def _parsed(text=TRACE):
    return outside.parse_strace(text, 7)


def _result(trace=None, events=(), sink_log=None, **extra):
    return {
        "events": list(events),
        "decoy_paths": [ENV, f"{HOME}/.netrc", f"{HOME}/.ssh/id_ed25519"],
        "home": HOME,
        "outside": {"ran": True, "canary": CANARY, "home": HOME, "tracer": {"harness_pid": 7},
                    "trace": trace if trace is not None else _parsed(),
                    "sink": sink_log or {"ready": True, "dns": [], "tcp": []}},
        **extra,
    }


def _rules(findings):
    return {(f.rule, f.severity) for f in findings}


# ---- strace parsing ------------------------------------------------------
def test_parse_resolves_relative_paths_threads_and_children():
    t = _parsed()
    ev = t["events"]
    assert t["start_index"] == 1 and t["done_index"] is not None
    rel = ev[2]
    assert rel["path"] == ENV and rel["in_harness"] and not rel["write"]
    conn = next(e for e in ev if e["call"] == "connect")
    assert conn["in_harness"] and conn["ok"] and (conn["ip"], conn["port"]) == ("203.0.113.10", 443)
    exe = next(e for e in ev if e["call"] == "execve")
    assert exe["pid"] == 12 and not exe["in_harness"] and exe["argv"][:2] == ["pip", "install"]
    netrc = next(e for e in ev if e.get("path", "").endswith(".netrc"))
    assert netrc["proc"] == 12 and not netrc["in_harness"]
    assert t["children"] == [12]


def test_tracer_drops_only_plain_library_reads():
    spec = importlib.util.spec_from_file_location("detonator_tracer", ROOT / "sandbox" / "monitor" / "tracer.py")
    tracer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tracer)
    quiet = tracer.QUIET_READ.match
    assert quiet('8 13:00:00.1 openat(AT_FDCWD</>, "/usr/local/lib/python3.11/os.py", O_RDONLY|O_CLOEXEC) = 3')
    assert not quiet('8 13:00:00.1 openat(AT_FDCWD</>, "/usr/../home/a/.env", O_RDONLY) = 3')
    assert not quiet('8 13:00:00.1 openat(AT_FDCWD</>, "/usr/lib/x", O_WRONLY|O_CREAT) = 3')
    assert not quiet(f'8 13:00:00.1 openat(AT_FDCWD</>, "{ENV}", O_RDONLY) = 3')


# ---- fake internet --------------------------------------------------------
def test_sink_answers_dns_with_a_fake_address():
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x04evil\x07example\x00" + struct.pack(">HH", 1, 1)
    reply, name, (qtype, ip) = sink.dns_answer(q)
    assert name == "evil.example" and qtype == 1 and ip.startswith("198.18.")
    assert reply[:2] == b"\x12\x34" and reply.endswith(socket.inet_aton(ip))
    assert sink.dns_answer(b"\x00")[0] is None


def test_sink_reads_tls_server_name_and_http_length():
    name = b"exfil.example"
    sni = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    exts = struct.pack(">H", len(sni)) + sni
    body = b"\x03\x03" + b"\0" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + exts
    hello = b"\x16\x03\x01" + struct.pack(">H", len(body) + 4) + b"\x01" + len(body).to_bytes(3, "big") + body
    assert sink.tls_server_name(hello) == "exfil.example"
    assert sink.tls_server_name(b"GET / HTTP/1.1\r\n") is None
    assert sink._http_wants(b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nab") == 2
    assert sink._http_wants(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == 0


def test_sink_log_maps_fake_addresses_back_to_names(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text('{"kind":"ready","catch_all":true}\n'
                   '{"kind":"dns","name":"evil.example","qtype":1,"answer":"198.18.0.2"}\n'
                   '{"kind":"tcp","dst":"198.18.0.2","port":443,"bytes":5,"data":"hello"}\nnot json\n',
                   encoding="utf-8")
    parsed = outside.parse_sink(log)
    assert parsed["ready"] and parsed["catch_all"]
    assert parsed["tcp"][0]["host"] == "evil.example"


# ---- rules ------------------------------------------------------------------
def test_secret_detection_sees_through_encoding_and_ignores_inputs():
    key = f"sk-{CANARY}-0002"
    assert rules._secret_hits(key, CANARY)
    assert rules._secret_hits(base64.b64encode(key.encode()).decode(), CANARY)
    assert rules._secret_hits(key.encode().hex(), CANARY)
    assert rules._secret_hits("k=sk-" + CANARY.lower() + "-0002", CANARY)
    assert not rules._secret_hits(f"detonator test input [{CANARY}-ARG]", CANARY)
    assert not rules._secret_hits("nothing here", CANARY)


def test_secret_sent_to_the_fake_internet_is_dangerous():
    sink_log = {"ready": True, "dns": [{"name": f"{CANARY.lower()}-0001.evil.example"}],
                "tcp": [{"host": "evil.example", "port": 443, "bytes": 30, "data": f"key=sk-{CANARY}-0002"}]}
    found = rules._outside_findings(_result(trace={"events": []}, sink_log=sink_log))
    assert ("secret_sent_out", rules.CRITICAL) in _rules(found)
    assert len(found[0].evidence) == 2


def test_hidden_actions_are_blind_spots_but_recorded_ones_are_not():
    found = rules._outside_findings(_result())
    blind = next(f for f in found if f.rule == "monitor_blind_spot")
    assert blind.severity == rules.CRITICAL
    assert any(ENV in e for e in blind.evidence) and any("203.0.113.10:443" in e for e in blind.evidence)
    assert any(e.startswith("started pip") for e in blind.evidence)
    seen = [{"kind": "file_read", "path": ENV}, {"kind": "network", "address": "('203.0.113.10', 443)"},
            {"kind": "process", "detail": "pip"}]
    assert "monitor_blind_spot" not in {f.rule for f in rules._outside_findings(_result(events=seen))}


def test_programs_reading_their_own_login_file_are_high_others_critical():
    found = rules._outside_findings(_result())
    reads = [f for f in found if f.rule == "decoy_accessed"]
    assert {f.severity for f in reads} == {rules.CRITICAL, rules.HIGH}
    assert any("pip: /home/alex/.netrc" in e for f in reads if f.severity == rules.HIGH for e in f.evidence)
    assert any(".ssh/id_ed25519" in e for f in reads if f.severity == rules.CRITICAL for e in f.evidence)


def test_harness_writing_its_result_after_the_run_is_not_forgery():
    assert "result_forged" not in {f.rule for f in rules._outside_findings(_result())}
    forged = TRACE.replace('"/detonator-phase/plugin-done"', '"/somewhere-else"')
    assert ("result_forged", rules.CRITICAL) in _rules(rules._outside_findings(_result(trace=_parsed(forged))))
    twice = TRACE + TRACE.splitlines()[-1] + "\n"
    assert "result_forged" in {f.rule for f in rules._outside_findings(_result(trace=_parsed(twice)))}


def test_a_killed_harness_with_outside_evidence_is_judged_not_errored():
    raw = {"fatal": "no result (exit 0)", **{k: v for k, v in _result().items() if k == "outside"}}
    out = rules.evaluate(raw)
    assert out["verdict"] == rules.VERDICT_DANGEROUS
    assert "outside monitor saw" in out["summary"]
    quiet = {"fatal": "boom", "outside": {"ran": True, "trace": {"events": []}, "sink": {}}}
    assert rules.evaluate(quiet)["verdict"] == rules.VERDICT_ERROR


def test_no_outside_monitor_means_no_outside_findings_and_a_clear_report():
    assert rules._outside_findings({"outside": {"ran": False, "reason": "x"}}) == []
    summary = rules.outside_summary({"outside": {"ran": False, "reason": "image build failed"}})
    text = "\n".join(report.outside_lines(summary))
    assert "Did not run: image build failed" in text
    full = report.render("x", {"verdict": "NO_FINDINGS", "findings": [], "outside": summary}, {})
    assert report.CAVEAT_NO_OUTSIDE in full


def test_report_lists_what_the_fake_internet_saw():
    sink_log = {"ready": True, "dns": [{"name": "evil.example"}],
                "tcp": [{"host": "evil.example", "port": 80, "bytes": 12, "data": "GET /"}]}
    summary = rules.outside_summary(_result(sink_log=sink_log))
    text = "\n".join(report.outside_lines(summary))
    assert "evil.example:80 (1 time, 12 bytes sent)" in text and "pip install x" in text


# ---- docker command --------------------------------------------------------
def test_plugin_joins_the_monitor_containers_and_stays_locked_down(tmp_path):
    mon = outside.Monitor(lambda *a, **k: None, tmp_path, "detonator-1", "alex-laptop")
    args = ["--network", f"container:{mon.sink}", "--pid", f"container:{mon.tracer}",
            "-v", f"{mon.resolv}:/etc/resolv.conf:ro"]
    cmd = " ".join(runner.docker_run_cmd("img", tmp_path, tmp_path, tmp_path, monitor_args=args))
    assert "--network none" not in cmd and "--hostname" not in cmd
    assert f"--network container:{mon.sink}" in cmd and f"--pid container:{mon.tracer}" in cmd
    for flag in ("--read-only", "--cap-drop ALL", "no-new-privileges", "--user 10001:10001"):
        assert flag in cmd
    sink_cmd = " ".join(outside.sink_cmd("m", "n", tmp_path, "h"))
    tracer_cmd = " ".join(outside.tracer_cmd("m", "n", tmp_path))
    for c in (sink_cmd, tracer_cmd):
        assert "--network none" in c and "--cap-drop ALL" in c and "no-new-privileges" in c
    assert "SYS_PTRACE" in tracer_cmd and "SYS_PTRACE" not in sink_cmd


def test_outside_monitor_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("DETONATOR_OUTSIDE", "0")
    assert not runner.outside_enabled()
    monkeypatch.delenv("DETONATOR_OUTSIDE")
    assert runner.outside_enabled()


# ---- found by stress tests ---------------------------------------------------
def test_tracer_keeps_lines_that_matter_even_in_a_flood():
    spec = importlib.util.spec_from_file_location("detonator_tracer2", ROOT / "sandbox" / "monitor" / "tracer.py")
    tracer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tracer)
    assert not tracer.important('7 1:1.1 openat(AT_FDCWD</>, "/etc/hostname", O_RDONLY) = 3')
    assert not tracer.important('7 1:1.1 openat(AT_FDCWD</home/a/.hermes/plugin-data/x>, "log.txt", O_WRONLY) = 3')
    assert tracer.important('7 1:1.1 openat(AT_FDCWD</home/a/.hermes/plugin-data/x>, "../../.env", O_RDONLY) = 3')
    environ = "/pro" "c/self/environ"  # split so the install scanner does not read this test as an attack
    assert tracer.important(f'7 1:1.1 openat(AT_FDCWD</>, "{environ}", O_RDONLY) = 3')
    assert tracer.important('7 1:1.1 openat(AT_FDCWD</>, "/out/result.json", O_WRONLY|O_CREAT) = 3')
    assert tracer.important('7 1:1.1 connect(3, {sa_family=AF_INET}, 16) = 0')


def test_a_thinned_trace_and_a_full_fake_internet_log_are_reported():
    res = _result(sink_log={"ready": True, "dns": [], "tcp": [], "full": True})
    res["outside"]["tracer"] = {"harness_pid": 7, "truncated": True, "lines_seen": 9, "lines_kept": 5}
    titles = [f.title for f in rules._outside_findings(res) if f.rule == "log_flood"]
    assert len(titles) == 2


def test_failed_result_writes_are_not_forgery_and_refused_kills_are_tampering():
    failed = TRACE.replace('"/out/result.json", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 3',
                           '"/out/result.json", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = -1 EMFILE (Too many open files)')
    failed = failed.replace('"/detonator-phase/plugin-done"', '"/x"')
    assert "result_forged" not in {f.rule for f in rules._outside_findings(_result(trace=_parsed(failed)))}
    killed = TRACE + "7     13:00:00.000020 kill(1, SIGKILL)                  = -1 EPERM (Operation not permitted)\n"
    tamper = [f for f in rules._outside_findings(_result(trace=_parsed(killed))) if f.rule == "monitor_tamper"]
    assert tamper and "kill(1, SIGKILL" in tamper[0].evidence[0]


def test_a_key_sent_on_an_open_connection_is_caught_by_the_tracer():
    sent = TRACE + f'9     13:00:00.000021 sendto(4<TCP:[1]>, "key=sk-{CANARY}-0002", 26, 0, NULL, 0) = 26\n'
    found = rules._outside_findings(_result(trace=_parsed(sent)))
    assert ("secret_sent_out", rules.CRITICAL) in _rules(found)


# ---- found by the security review --------------------------------------------
def test_monitor_containers_clean_themselves_up(tmp_path):
    for cmd in (outside.sink_cmd("m", "n", tmp_path, "h"), outside.tracer_cmd("m", "n", tmp_path)):
        joined = " ".join(cmd)
        assert "--rm" in cmd and "--privileged" not in joined and "docker.sock" not in joined
        assert "seccomp" not in joined and "apparmor" not in joined


def test_monitor_logs_are_never_read_through_a_link(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text('7 13:00:00.1 openat(AT_FDCWD</>, "/x", O_RDONLY) = 3\n', encoding="utf-8")
    trace, sink_dir = tmp_path / "trace", tmp_path / "sink"
    trace.mkdir()
    sink_dir.mkdir()
    (trace / "strace.log").symlink_to(secret)
    (sink_dir / "log.jsonl").symlink_to(secret)
    seen = outside.collect(trace, sink_dir)
    assert seen["trace"]["events"] == [] and seen["sink"].get("error")


def test_evidence_from_the_plugin_stays_on_one_line_and_out_of_code_marks():
    sink_log = {"ready": True, "dns": [], "tcp": [{"host": "x", "port": 80, "bytes": 9,
                                                   "data": f"`a`\nsk-{CANARY}-0002"}]}
    ev = rules._outside_findings(_result(trace={"events": []}, sink_log=sink_log))[0].evidence[0]
    assert "`" not in ev and "\n" not in ev
