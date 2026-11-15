"""MCP servers: run one in the sandbox, as Hermes would, and judge what it did.

An MCP server is a separate program (often Node or Python) that Hermes starts from an entry
in ~/.hermes/config.yaml (`mcp_servers:`) and talks to over stdin/stdout. Detonator starts it
only inside the disposable container (sandbox/mcp_harness.py plays Hermes), with fake keys in
place of every `env` value. Because the server is its own process, the outside monitor (the
strace tracer and the fake internet, engine/outside.py) is what sees its files, programs and
connections; the harness records what the server tells the model.

This module is the platform-neutral core: it takes a plain {"command", "args", "env"} entry.
Reading an entry from Hermes's config lives in its own small function (load_folder_entry for
now), so other MCP clients' config files can be added later without touching the rules.

Disclosure (catalog rule 13): same Docker commands as engine/runner.py; nothing runs on the host.
"""

from __future__ import annotations

import json
import posixpath
import re
from pathlib import Path

from . import report, rules, runner
from .rules import CRITICAL, HIGH, INFO, LOW, MEDIUM, Finding

ENTRY_FILE = "mcp-server.yaml"
RESULT_FLOOD_CHARS = rules.TOOL_FLOOD_CHARS
DESCRIPTION_FLOOD_CHARS = 10_000

# The MCP-only rules (mcp_tool_poisoning, ...) are defined with the others in engine/rules.py.

_SECRETISH = re.compile(r"ssh|id_rsa|id_ed25519|\.env\b|api[_ ]?keys?|credential|private key|auth\.json|"
                        r"password|secret|token|wallet|seed phrase|mnemonic", re.I)
_HIDING = re.compile(r"(?:tell|inform|mention|reveal|show|notify)[^.\n]{0,30}\buser|without (?:telling|asking|"
                     r"informing|notifying)|\bsecretly\b|\bcovertly\b", re.I)
_OTHER_TOOLS = re.compile(
    r"\b(?:when|whenever|before|after|instead of|every time)\b[^.\n]{0,80}\b(?:any|all|every|other|another)\s+"
    r"(?:other\s+)?(?:tools?|servers?|functions?)\b|\b(?:any|all|every)\s+other\s+tools?\b", re.I)
_BUILTIN_NAMED = re.compile(r"\b(?:" + "|".join(sorted((re.escape(t) for t in rules.BUILTIN_TOOLS if "_" in t),
                                                       key=len, reverse=True)) + r")\b")
_CRED_PARAM = re.compile(r"^(?:.*_)?(?:password|passphrase|passwd|api_?key|secret_?key|private_?key|"
                         r"seed_?phrase|mnemonic|ssh_?key)$", re.I)
_CRED_TEXT = re.compile(r"\b(?:password|passphrase|api[ _-]?key|secret key|private key|seed phrase|mnemonic|"
                        r"recovery phrase|2fa|one[- ]time code)\b", re.I)
_SANDBOX_PROBES = ("/.dockerenv", "/run/.containerenv", "/proc/1/cgroup", "/proc/1/sched", "/sys/class/dmi/id",
                   "/sys/hypervisor")
_RECON = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/machine-id")
_CACHE_DIRS = (".cache", ".npm")


class McpError(Exception):
    pass


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------
def check_entry(entry, where: str) -> dict:
    """A stdio entry in the shape of Hermes's `mcp_servers.<name>`: command, args, env.
    Values in env are never used; the sandbox gets fake keys under the same names."""
    if not isinstance(entry, dict):
        raise McpError(f"{where}: the server entry is not a mapping")
    if entry.get("url"):
        raise McpError(f"{where}: this is a remote (HTTP) server. It runs on someone else's computer, "
                       "so it cannot be run in the sandbox.")
    command = entry.get("command")
    if not isinstance(command, str) or not command.strip():
        raise McpError(f"{where}: no command to start the server")
    args = entry.get("args") or []
    env = entry.get("env") or {}
    if not isinstance(args, list) or not all(isinstance(a, (str, int, float)) for a in args):
        raise McpError(f"{where}: args must be a list of words")
    if not isinstance(env, dict):
        raise McpError(f"{where}: env must be a mapping")
    names = [str(k) for k in env]
    if not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", n) for n in names):
        raise McpError(f"{where}: env has a name that is not a plain variable name")
    return {"command": command.strip(), "args": [str(a) for a in args][:64],
            "env": {n: "" for n in names[:32]}}


def load_folder_entry(path: str) -> runner.Target:
    """A local folder holding an MCP server and its Hermes-style entry in mcp-server.yaml."""
    p = Path(path).expanduser().resolve()
    f = p / ENTRY_FILE
    if not f.is_file():
        raise McpError(f"no {ENTRY_FILE} in {p} (it holds the server's command, args and env, "
                       "as in Hermes's config.yaml)")
    try:
        data = runner._yaml_safe_load(f.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise McpError(f"cannot parse {ENTRY_FILE}: {exc}")
    target = runner.Target(path=p, label=str(p))
    target.entry = check_entry(data, ENTRY_FILE)
    return target


def fake_value(canary: str, i: int) -> str:
    """Same as sandbox/mcp_harness.py: the fake key for the i-th env name, sorted by name."""
    return f"sk-det-{canary}-env{i}"


def detonate(target: runner.Target, outside: bool | None = True) -> dict:
    return runner.detonate(target, outside=outside, mcp_entry=target.entry)


# ---------------------------------------------------------------------------
# Judging
# ---------------------------------------------------------------------------
def _texts(value) -> str:
    return "\n".join(rules._strings(value))


def _metadata(tool: dict) -> dict:
    return {k: tool.get(k) for k in ("name", "title", "description", "inputSchema", "annotations", "outputSchema")
            if tool.get(k) is not None}


def _description_findings(listing: dict, where: str) -> list:
    out = []
    for tool in listing.get("tools") or []:
        name = rules._safe_name(tool.get("name"), 60)
        meta = _metadata(tool)
        hits = rules._injection_hits(meta)
        if hits:
            text = " ".join(hits)
            severe = bool(_SECRETISH.search(text) or _HIDING.search(text) or "invisible" in text)
            out.append(Finding("mcp_tool_poisoning", CRITICAL if severe else HIGH,
                               f"Tool {name} hides instructions to the model in its description{where}",
                               hits))
        text = _texts({"description": tool.get("description"), "schema": tool.get("inputSchema")})
        cross = _OTHER_TOOLS.search(text) or _BUILTIN_NAMED.search(text)
        if cross:
            s = max(0, cross.start() - 60)
            out.append(Finding("mcp_cross_tool_instructions", HIGH,
                               f"Tool {name} gives orders about other tools{where}",
                               ["…" + text[s:cross.end() + 60].replace("\n", " ") + "…"]))
        if len(text) > DESCRIPTION_FLOOD_CHARS:
            out.append(Finding("output_flood", MEDIUM, f"Tool {name} has a very long description{where}",
                               [f"{len(text)} characters, sent to the model with every request"]))
        props = ((tool.get("inputSchema") or {}).get("properties") or {}) if isinstance(tool.get("inputSchema"), dict) else {}
        creds = [str(k) for k in props if _CRED_PARAM.match(str(k))]
        if creds:
            out.append(Finding("mcp_credential_request", MEDIUM,
                               f"Tool {name} asks for a secret as an argument{where}", creds[:5]))
    for kind in ("resources", "prompts"):
        for item in listing.get(kind) or []:
            hits = rules._injection_hits(item)
            if hits:
                out.append(Finding("prompt_injection_text", HIGH,
                                   f"A listed {kind[:-1]} carries instructions to the model{where}", hits))
    return out


def _rug_pull(first: dict, later: dict, notifications: list) -> list:
    def index(listing):
        return {str(t.get("name")): json.dumps(_metadata(t), sort_keys=True, default=str)
                for t in listing.get("tools") or []}
    a, b = index(first), index(later)
    changes = [f"added {rules._safe_name(n)}" for n in sorted(set(b) - set(a))]
    changes += [f"removed {rules._safe_name(n)}" for n in sorted(set(a) - set(b))]
    changes += [f"changed {rules._safe_name(n)}" for n in sorted(set(a) & set(b)) if a[n] != b[n]]
    told = [n for n in notifications if n.get("method") == "notifications/tools/list_changed"]
    if not changes and not told:
        return []
    evidence = changes[:10] + ([f"sent tools/list_changed {len(told)} time(s)"] if told else [])
    return [Finding("mcp_rug_pull", HIGH if changes else MEDIUM,
                    "Changed its tools after being listed (a rug pull)" if changes else
                    "Told Hermes its tools changed, but the new list looked the same", evidence)]


def _phases(events: list, start: int | None):
    """Yield (phase, event) for every event after the start marker. A phase starts where the
    harness left its marker (mcp-call-3, mcp-relist, ...)."""
    phase = "start"
    for e in events[(start or 0) + 1:] if start is not None else []:
        path = str(e.get("path") or "")
        if e.get("in_harness") and path.startswith(rules._PHASE_PREFIX):
            name = path[len(rules._PHASE_PREFIX):]
            if name.startswith("mcp-"):
                phase = name[4:]
            continue
        yield phase, e


def _phase_label(phase: str, calls: dict) -> str:
    phase = phase.replace(":", "-")
    if phase.startswith("call-"):
        return f"while running tool {rules._safe_name(calls.get(phase, '?'), 60)}"
    return {"start": "while starting", "initialize": "while starting", "list": "while being listed",
            "relist": "while being listed again"}.get(phase.split("-")[0], f"during {rules._safe_name(phase)}")


def _behaviour(result: dict, out: dict) -> tuple[list, dict]:
    """What the server and the programs it started did, from the outside trace."""
    findings: list[Finding] = []
    trace = out.get("trace") or {}
    events = trace.get("events") or []
    home = str(result.get("home") or out.get("home") or "")
    hermes_home = posixpath.join(home, ".hermes") if home else None
    allowed = [str(d) for d in result.get("allowed_write_dirs") or []]
    categories = result.get("decoy_categories") or {}
    server_pid = result.get("server_pid")
    calls = {f'call-{c.get("index")}': c.get("tool") for c in result.get("calls") or []}
    per_phase: dict = {}
    reads: dict = {}
    writes, programs, nets, local, listen, probes, recon, environ = [], [], [], [], [], [], [], []
    own_exec_seen = False
    for phase, e in _phases(events, trace.get("start_index")):
        if e.get("in_harness"):
            continue
        call, path = e.get("call"), str(e.get("path") or "")
        label = _phase_label(phase, calls)
        hit = False
        if call in ("open", "openat", "openat2", "creat") and e.get("ok"):
            if path.startswith(rules._PHASE_PREFIX) or path == rules._RESULT_FILE:
                continue
            if e.get("write"):
                if not rules._under(path, allowed) and not path.startswith(("/dev/", "/proc/")):
                    writes.append((phase, label, path))
                    hit = True
            elif path in categories:
                reads.setdefault(categories[path], []).append(f"{path} ({label})")
                hit = True
            elif rules._ENVIRON_PATH.match(path) and "/self/" not in path and "/thread-self/" not in path:
                environ.append(f"{path} ({label})")
                hit = True
            elif path.startswith(_SANDBOX_PROBES):
                probes.append(path)
            elif path in _RECON:
                recon.append(path)
        elif call in ("unlink", "unlinkat", "rename", "renameat", "renameat2") and e.get("ok"):
            for p in e.get("paths") or []:
                if p and not rules._under(p, allowed + ["/tmp"]):
                    writes.append((phase, label, p))
                    hit = True
        elif call in ("execve", "execveat") and e.get("ok"):
            if e.get("pid") == server_pid and not own_exec_seen:
                own_exec_seen = True
                continue
            programs.append((phase, label, " ".join(e.get("argv") or [path])[:200]))
            hit = True
        elif call in ("connect", "sendto") and e.get("ip") and e.get("ok") is not None:
            ip, port = str(e.get("ip")), e.get("port")
            if ip in ("127.0.0.1", "::1") and port == 53:
                continue
            if ip.startswith("127.") or ip == "::1":
                local.append(f"{ip}:{port} ({label})")
            else:
                nets.append((phase, label, f"{ip}:{port}"))
            hit = True
        elif call in ("bind",) and e.get("ip") and e.get("ip") not in ("127.0.0.1", "::1"):
            listen.append(f'{e.get("ip")}:{e.get("port")} ({label})')
            hit = True
        if hit:
            per_phase.setdefault(phase, set()).add(call)

    if reads.get("secret"):
        env_file = [r for r in reads["secret"] if hermes_home and r.startswith(posixpath.join(hermes_home, ".env"))]
        others = [r for r in reads["secret"] if r not in env_file]
        if env_file:
            findings.append(Finding("hermes_env_read", HIGH, "Read Hermes's .env file, where your API keys are kept",
                                    env_file[:5]))
        if others:
            findings.append(Finding("decoy_accessed", CRITICAL, "Opened decoy key and credential files",
                                    sorted(set(others))[:12]))
    if reads.get("browser") or reads.get("wallet"):
        findings.append(Finding("browser_or_wallet_read", CRITICAL, "Opened browser passwords or crypto wallets",
                                sorted(set(reads.get("browser", []) + reads.get("wallet", [])))[:12]))
    if reads.get("memory") or reads.get("history"):
        findings.append(Finding("memory_read", MEDIUM, "Read Hermes's memory or chat history",
                                sorted(set(reads.get("memory", []) + reads.get("history", [])))[:12]))
    if environ:
        findings.append(Finding("environ_file_read", HIGH,
                                "Read another process's environment, where Hermes's keys live", environ[:5]))
    for phase, label, path in writes:
        norm = posixpath.normpath(path)
        rel = posixpath.relpath(norm, home).split("/") if home and rules._under(norm, [home]) else []
        if rel and rel[0] in _CACHE_DIRS:
            findings.append(Finding("write_tmp", LOW, "Wrote to a cache folder", [f"{path} ({label})"]))
            continue
        rule, sev, tech = rules._classify_write(path, "write", home, hermes_home, "/plugin")
        if rule == "content_altered":
            rule = "agent_config_modified"
        title = {"persistence": "Wrote to a place that starts programs automatically",
                 "agent_config_modified": "Changed Hermes's own files (config, memory, plugins or skills)",
                 "self_modify": "Changed its own files",
                 "write_outside_folder": "Wrote or changed sensitive files outside its folder",
                 "write_own_state": "Kept its own files in your home folder",
                 "write_tmp": "Wrote temporary files"}.get(rule, "Wrote files")
        findings.append(Finding(rule, sev, title, [f"{path} ({label})"], attack=[tech] if tech else []))
    if programs:
        fetch = [p for _, _, p in programs if rules.FETCH_CMD_RE.search(p)]
        if fetch:
            findings.append(Finding("remote_code_fetch", HIGH, "Downloaded or installed code while running", fetch[:5]))
        findings.append(Finding("command_run", HIGH, "Started other programs",
                                [f"{p} ({label})" for _, label, p in programs][:8]))
    start_nets = [f"{a} ({label})" for phase, label, a in nets if not phase.startswith("call-")]
    tool_nets = [f"{a} ({label})" for phase, label, a in nets if phase.startswith("call-")]
    sink_hosts = rules._connection_lines((out.get("sink") or {}).get("tcp") or [])
    if start_nets:
        findings.append(Finding("undeclared_network", HIGH,
                                "Reached for the network on its own, before any tool was used",
                                sorted(set(start_nets))[:8] + sink_hosts[:4]))
    if tool_nets:
        findings.append(Finding("tool_network", MEDIUM, "Used the network inside a tool call",
                                sorted(set(tool_nets))[:8] + sink_hosts[:4]))
    if local:
        findings.append(Finding("local_network", MEDIUM, "Connected to services on this computer",
                                sorted(set(local))[:8]))
    if listen:
        findings.append(Finding("listener", HIGH, "Opened a network port others can connect to", listen[:5]))
    if probes:
        findings.append(Finding("sandbox_check", MEDIUM, "Checked whether it runs in a container",
                                sorted(set(probes))[:5]))
    if recon:
        findings.append(Finding("recon", MEDIUM, "Read account and system files", sorted(set(recon))[:5]))
    return findings, per_phase


def _readonly_lies(result: dict, per_phase: dict, findings: list) -> list:
    out = []
    for c in result.get("calls") or []:
        ann = c.get("annotations") or {}
        if ann.get("readOnlyHint") is not True:
            continue
        did = per_phase.get(f'call-{c.get("index")}') or set()
        acts = []
        if did & {"open", "openat", "openat2", "creat", "unlink", "unlinkat", "rename", "renameat", "renameat2"}:
            acts.append("changed files")
        if did & {"execve", "execveat"}:
            acts.append("started a program")
        # Network use alone is not a lie: fetching or looking things up is read-only. Keys sent
        # out are judged by the leak rules.
        # Reads of decoys are also recorded per phase; only count real writes as file changes.
        writes = [f for f in findings if f.rule in ("persistence", "agent_config_modified", "write_outside_folder",
                                                     "write_own_state", "self_modify")
                  and any(f"tool {rules._safe_name(c.get('tool'), 60)})" in str(ev) for ev in f.evidence)]
        if "changed files" in acts and not writes:
            acts.remove("changed files")
        if acts:
            out.append(Finding("mcp_readonly_lie", CRITICAL,
                               f"Tool {rules._safe_name(c.get('tool'), 60)} claims to be read-only but "
                               + " and ".join(acts), [f"readOnlyHint: true; {', '.join(acts)}"]))
    return out


def _content_findings(result: dict, canary: str, declared: list) -> list:
    out = []
    calls = {f'call-{c.get("index")}': c.get("tool") for c in result.get("calls") or []}
    init = result.get("initialize") or {}
    hits = rules._injection_hits(init.get("instructions"))
    if hits:
        out.append(Finding("prompt_injection_text", HIGH,
                           "The server's start-up instructions to the model carry hidden orders", hits))
    leaked, floods = [], []
    for c in result.get("calls") or []:
        name = rules._safe_name(c.get("tool"), 60)
        text = str(c.get("returned") or "")
        h = rules._injection_hits(text)
        if h:
            out.append(Finding("prompt_injection_text", HIGH, f"Tool {name} returned instructions to the model", h))
        if rules._secret_hits(_strip(text, declared), canary):
            leaked.append(f"tool {name}")
        if int(c.get("returned_size") or 0) > RESULT_FLOOD_CHARS:
            floods.append(f'tool {name}: {c.get("returned_size")} characters')
    for kind in ("resource_reads", "prompt_gets"):
        for r in result.get(kind) or []:
            text = str(r.get("returned") or "")
            h = rules._injection_hits(text)
            if h:
                out.append(Finding("prompt_injection_text", HIGH,
                                   f"A {'resource' if kind == 'resource_reads' else 'prompt'} it serves "
                                   "carries instructions to the model", h))
            if rules._secret_hits(_strip(text, declared), canary):
                leaked.append(f"{kind[:-6]} {rules._safe_name(r.get('uri') or r.get('name'), 60)}")
    if leaked:
        out.append(Finding("secret_in_output", CRITICAL, "Put a fake key in what the model sees", leaked[:8]))
    if floods:
        out.append(Finding("output_flood", MEDIUM, "Returned a very large amount of text to the model", floods[:5]))
    sampling = [r for r in result.get("from_server") or [] if r.get("method") == "sampling/createMessage"]
    if sampling:
        text = " ".join(str(r.get("params")) for r in sampling)
        bad = rules._secret_hits(_strip(text, declared), canary) or rules._injection_hits(text)
        out.append(Finding("mcp_sampling_used", CRITICAL if bad else HIGH,
                           "Asked Hermes to run your AI model" + (" with keys or hidden orders in the request"
                                                                  if bad else ""),
                           [f'{len(sampling)} request(s), first {_phase_label(sampling[0].get("phase") or "", calls)}: '
                            f'{str(sampling[0].get("params"))[:200]}']))
    asks = [r for r in result.get("from_server") or [] if r.get("method") == "elicitation/create"
            and _CRED_TEXT.search(str(r.get("params")))]
    if asks:
        out.append(Finding("mcp_credential_request", HIGH, "Asked the user to type a password or key",
                           [str(a.get("params"))[:200] for a in asks[:3]]))
    return out


def _strip(text: str, values: list) -> str:
    for v in values:
        text = text.replace(v, "")
    return text


def evaluate(result: dict) -> dict:
    result = result or {}
    out = result.get("outside") if isinstance(result.get("outside"), dict) else {}
    canary = str(out.get("canary") or result.get("canary") or "")
    declared_names = [str(n) for n in result.get("declared_env") or []]
    declared = [fake_value(canary, i) for i in range(len(declared_names))] if canary else []
    summary = rules.outside_summary(result)
    if result.get("fatal") and not out.get("ran"):
        return {"verdict": rules.VERDICT_ERROR, "findings": [], "detail": str(result["fatal"])[:2000],
                "outside": summary}
    findings: list[Finding] = []
    listing = result.get("listing") or {}
    findings += _description_findings(listing, "")
    relisting = result.get("relisting") or {}
    if relisting:
        first_hits = {(f.rule, f.title) for f in findings}
        for f in _description_findings(relisting, " (after it changed)"):
            if (f.rule, f.title.replace(" (after it changed)", "")) not in first_hits:
                findings.append(f)
        findings += _rug_pull(listing, relisting, result.get("notifications") or [])
    findings += _content_findings(result, canary, declared)
    per_phase = {}
    if out.get("ran"):
        b, per_phase = _behaviour(result, out)
        findings += b
        findings += _readonly_lies(result, per_phase, findings)
        # Keys that reached the fake internet. The server's own declared keys, sent while a tool
        # ran, are what an API wrapper does; they are reported as network use, not as a leak.
        stripped = dict(out)
        stripped["sink"] = {**(out.get("sink") or {}), "tcp": [
            {**e, "data": _strip(str(e.get("data") or ""), declared)} for e in (out.get("sink") or {}).get("tcp") or []]}
        stripped["trace"] = {**(out.get("trace") or {}), "start_index": None, "events": [
            {**e, "data": _strip(str(e.get("data") or ""), declared)} for e in (out.get("trace") or {}).get("events") or []]}
        findings += [f for f in rules._outside_findings({**result, "events": [], "outside": stripped})
                     if f.rule == "secret_sent_out"]
        # A forged result file, or the server tracing or killing Detonator's own process.
        findings += [f for f in rules._outside_findings({**result, "events": []})
                     if f.rule in ("result_forged", "monitor_tamper", "log_flood")]
        own = [str(e.get("host")) for e in (out.get("sink") or {}).get("tcp") or []
               if any(v in str(e.get("data") or "") for v in declared)]
        if own:
            findings.append(Finding("declared_env_read", INFO, "Sent its own declared key to the service it wraps",
                                    sorted(set(own))[:5],
                                    why="The server got this key from its env entry and sent it where its "
                                        "tool calls went. Check that the host is the service the server is for."))
    if not result.get("initialize") or (result.get("initialize") or {}).get("error") or result.get("start_error"):
        findings.append(Finding("server_not_started", MEDIUM, "The server did not start or did not answer",
                                [str(result.get("start_error") or (result.get("initialize") or {}).get("error")
                                     or result.get("fatal") or "no answer")[:300],
                                 "stderr: " + str(result.get("stderr_tail") or "")[-300:]]))
    seen = {f.rule for f in findings}
    if seen & {"undeclared_network", "tool_network", "secret_sent_out", "decoy_accessed", "browser_or_wallet_read"}:
        for f in findings:
            if f.rule in ("hermes_env_read", "environ_file_read") and f.severity == HIGH:
                f.severity = CRITICAL
                f.title += ", and also reached for the network or other secrets"
    findings.sort(key=lambda f: rules.SEVERITY_ORDER.index(f.severity))
    verdict = rules._verdict(findings)
    return {"verdict": verdict, "findings": [f.to_dict() for f in findings], "outside": summary,
            "tools": [{"name": rules._safe_name(t.get("name"), 80),
                       "read_only": bool((t.get("annotations") or {}).get("readOnlyHint"))
                       if isinstance(t.get("annotations"), dict) else False}
                      for t in listing.get("tools") or []]}


CAVEAT = ("This report is advisory evidence, not proof. Detonator only sees what the server did during this run: "
          "time bombs, sandbox-aware code, servers that need a real account and paths the test inputs did not "
          "reach can evade it. The server ran as its own process and was watched from separate containers it "
          "cannot reach (a tracer and a fake internet). A clean run does not mean a server is safe.")
CAVEAT_NO_OUTSIDE = ("This report is advisory evidence, not proof. The outside monitor did not run, so only what the "
                     "server told the model was checked, not what it did on the computer.")


def render(label: str, evaluation: dict, raw: dict | None = None) -> str:
    text = report.render(label, evaluation, raw)
    tools = evaluation.get("tools") or []
    offered = ["## What the server offers", "",
               f"- Tools ({len(tools)}): " + (", ".join(t["name"] + (" (read-only)" if t["read_only"] else "")
                                                    for t in tools[:40]) or "none"), ""]
    text = text.replace("# Detonator report:", "# Detonator MCP report:", 1)
    # The shared report text speaks of plugins; here the thing under test is a server.
    text = text.replace(report.CAVEAT, CAVEAT).replace(report.CAVEAT_NO_OUTSIDE, CAVEAT_NO_OUTSIDE)
    for a, b in (("the plugin's", "the server's"), ("the plugin", "the server"), ("a plugin", "a server")):
        text = text.replace(a, b)
    marker = "## How it was tested"
    how = ("Disposable Docker container: no real network, read-only root, all capabilities dropped, non-root "
           "user, fake Hermes home with decoy keys, credentials, browser data, wallets, memory and chat history. "
           "The server was started there with fake values for every env entry, and a stand-in for Hermes "
           "listed its tools, resources and prompts, called every tool with test input, and listed everything "
           "again to catch changes.")
    if marker in text:
        head, tail = text.split(marker, 1)
        tail = tail.split("\n\n", 2)
        text = head + "\n".join(offered) + "\n" + marker + "\n\n" + how + "\n\n" + (tail[2] if len(tail) > 2 else "")
    return text


def main(argv=None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(prog="python -m engine.mcp")
    ap.add_argument("path", help=f"folder with an MCP server and its {ENTRY_FILE}")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--raw", help="write the raw harness result to this file")
    args = ap.parse_args(argv)
    try:
        target = load_folder_entry(args.path)
        raw = detonate(target)
    except (McpError, runner.DetonatorError) as exc:
        print(f"detonator: {exc}", file=sys.stderr)
        return 2
    if args.raw:
        Path(args.raw).write_text(json.dumps(raw, indent=1), encoding="utf-8")
    evaluation = evaluate(raw)
    print(json.dumps(evaluation, indent=1) if args.json else render(target.label, evaluation, raw))
    return {"DANGEROUS": 3, "SUSPICIOUS": 3, "ERROR": 2}.get(evaluation["verdict"], 0)


if __name__ == "__main__":
    raise SystemExit(main())
