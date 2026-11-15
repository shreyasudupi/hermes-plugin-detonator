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

from . import mcp_sources as sources
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
_BUILD_TOOLS = {"npm", "npm-cli.js", "node", "sh", "dash", "bash", "node-gyp", "node-gyp.js", "make", "cc", "gcc",
                "g++", "c++", "python3", "python", "uname"}
_RISKY_RULES = {"decoy_accessed", "hermes_env_read", "browser_or_wallet_read", "environ_file_read", "memory_read",
                "persistence", "agent_config_modified", "write_outside_folder", "command_run", "remote_code_fetch",
                "undeclared_network", "listener", "secret_sent_out", "sandbox_check", "recon"}


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


INSTALL_CMD = ["npm", "rebuild", "--foreground-scripts"]


def _finish_target(target: runner.Target, entry: dict, checks: list) -> runner.Target:
    """Add the install step (when packages have npm install scripts) and the entry checks."""
    scripts = sources.npm_install_scripts(target.path)
    if scripts:
        entry["install"] = [INSTALL_CMD]
    target.entry = entry
    target.install_scripts = scripts
    target.checks = checks
    return target


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
    cfg = data.get("_detonator_config") if isinstance(data, dict) else None
    if cfg:    # a config.yaml plus a server name: check that entry only, run nothing
        name = str(data.get("_detonator_server") or "")
        raw = sources.read_servers(p / str(cfg)).get(name)
        if raw is None:
            raise McpError(f"no server named '{name}' in {cfg}")
        try:
            plan = sources.plan_entry(name, raw)
        except sources.SourceError:
            plan = None
        target = runner.Target(path=p, label=f"{name} (config only)")
        target.entry, target.plan, target.install_scripts = None, plan, []
        target.checks = sources.config_checks(name, raw, plan)
        target.config_only = True
        return target
    target = runner.Target(path=p, label=str(p))
    return _finish_target(target, check_entry(data, ENTRY_FILE), sources.config_checks(p.name, data, None))


def load_config_target(name: str, work: Path, config: Path | None = None) -> runner.Target:
    """One server from Hermes's config.yaml, by name: plan it, check its entry, and get its code
    (downloaded in the fetch container, or copied from its folder). Nothing runs here."""
    try:
        servers = sources.read_servers(config)
        if name not in servers:
            known = ", ".join(sorted(str(k) for k in servers)[:20]) or "none"
            raise McpError(f"no MCP server named '{name}' in Hermes's config.yaml (servers there: {known})")
        raw = servers[name]
        plan = sources.plan_entry(name, raw)
        checks = sources.config_checks(name, raw, plan)
        if plan.kind == "remote":
            target = runner.Target(path=work, label=f"{name} (remote: {plan.url})")
            target.entry, target.checks, target.plan, target.install_scripts = None, checks, plan, []
            return target
        if plan.kind == "npm":
            folder = sources.fetch_npm(plan, work / "pkg")
            entry = sources.npm_entry(plan, folder)
            label = f"{name} (npm {plan.package}@{plan.version})"
        elif plan.kind == "pypi":
            folder = sources.fetch_pypi(plan, work / "pkg")
            entry = sources.pypi_entry(plan, folder)
            label = f"{name} (PyPI {plan.package}=={plan.version})"
        else:
            folder, entry = sources.local_folder(plan, work)
            label = f"{name} ({plan.script})"
    except sources.SourceError as exc:
        raise McpError(str(exc))
    target = _finish_target(runner.Target(path=folder, label=label), check_entry(entry, name) | {
        k: entry[k] for k in ("extra_env",) if k in entry}, checks)
    target.plan = plan
    return target


def fake_value(canary: str, i: int) -> str:
    """Same as sandbox/mcp_harness.py: the fake key for the i-th env name, sorted by name."""
    return f"sk-det-{canary}-env{i}"


def detonate(target: runner.Target, outside: bool | None = True) -> dict:
    """Run the server in the sandbox. A remote server is not run: only its entry is checked."""
    checks = [list(c) for c in getattr(target, "checks", [])]
    if getattr(target, "config_only", False):
        return {"mode": "mcp", "config_only": True, "config_checks": checks, "outside": {"ran": False,
                "reason": "config only: the entry's settings were checked; the server was not downloaded or run"}}
    if target.entry is None:
        return {"mode": "mcp", "remote": True, "config_checks": checks, "outside": {"ran": False,
                "reason": "remote server: it runs on someone else's computer, so only its entry was checked"}}
    raw = runner.detonate(target, outside=outside, mcp_entry=target.entry)
    raw["config_checks"] = checks
    raw["install_scripts"] = getattr(target, "install_scripts", [])
    return raw


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
    # The second listing failed (a tool hung, the server died): no answer is not a change.
    a, b = index(first), index(first if later.get("errors") else later)
    changes = [f"added {rules._safe_name(n)}" for n in sorted(set(b) - set(a))]
    changes += [f"removed {rules._safe_name(n)}" for n in sorted(set(a) - set(b))]
    changes += [f"changed {rules._safe_name(n)}" for n in sorted(set(a) & set(b)) if a[n] != b[n]]
    told = [n for n in notifications if n.get("method") == "notifications/tools/list_changed"]
    if not changes and not told:
        return []
    evidence = changes[:10] + ([f"sent tools/list_changed {len(told)} time(s)"] if told else [])
    # Saying "my tools changed" with nothing changed is noise (test servers do it), not a rug pull.
    return [Finding("mcp_rug_pull", HIGH if changes else LOW,
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
    return {"install": "while installing", "start": "while starting", "initialize": "while starting", "list": "while being listed",
            "relist": "while being listed again"}.get(phase.split("-")[0], f"during {rules._safe_name(phase)}")


# Lookups Python and Node make for themselves (ctypes.util.find_library runs `ldconfig -p`).
_HARMLESS_PROGRAM = re.compile(r"^(?:/usr)?(?:/s?bin/)?ldconfig -p$")
_GENERIC_NAMES = {"mcp", "server", "servers", "node", "modules", "node_modules", "dist", "build", "index", "main",
                  "src", "lib", "bin", "js", "mjs", "cjs", "py", "python", "plugin", "site", "run", "cli", "app"}


def _own_names(result: dict) -> set:
    """Words naming the server (from its command line and the name it gave), for its own settings folder."""
    words = set()
    texts = [str(a) for a in (result.get("argv") or [])[:4]]
    texts.append(str(((result.get("initialize") or {}).get("serverInfo") or {}).get("name") or ""))
    for t in texts:
        for w in re.split(r"[^A-Za-z0-9]+", t.lower()):
            if len(w) >= 3 and w not in _GENERIC_NAMES:
                words.add(w)
    return words


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
    exe_of: dict = {}    # process (thread group) -> program it last started, from execve
    for phase, e in _phases(events, trace.get("start_index")):
        if e.get("in_harness"):
            continue
        call, path = e.get("call"), str(e.get("path") or "")
        if call in ("execve", "execveat") and e.get("ok"):
            words = [posixpath.basename(str(w)) for w in (e.get("argv") or [path])[:2]]
            # npm starts as /usr/local/bin/npm, then its #! line re-runs it as `node .../npm`
            exe_of[e.get("proc") or e.get("pid")] = "npm" if {"npm", "npm-cli.js"} & set(words) else words[0]
        if phase == "install" and exe_of.get(e.get("proc") or e.get("pid")) == "npm" and posixpath.basename(path) == ".npmrc" \
                and not e.get("write"):
            continue    # npm itself reads its settings file on every run; a script reading it is still caught
        label = _phase_label(phase, calls)
        hit = False
        if call in ("open", "openat", "openat2", "creat") and e.get("ok"):
            if path.startswith(rules._PHASE_PREFIX) or path == rules._RESULT_FILE:
                continue
            if e.get("write"):
                if phase == "install" and (rules._under(path, ["/plugin"]) or rules._under(path, [
                        posixpath.join(home, ".npm"), posixpath.join(home, ".cache")])):
                    continue    # npm building into the package's own folder, or its cache
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
            if phase == "install" and posixpath.basename(path) in _BUILD_TOOLS:
                continue    # npm running the package's scripts, and the usual build tools
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
    own_names = _own_names(result)
    grouped: dict = {}
    for phase, label, path in writes:
        norm = posixpath.normpath(path)
        rel = posixpath.relpath(norm, home).split("/") if home and rules._under(norm, [home]) else []
        if rel and rel[0] in _CACHE_DIRS:
            grouped.setdefault(("write_tmp", LOW, "Wrote to a cache folder", None), []).append(f"{path} ({label})")
            continue
        rule, sev, tech = rules._classify_write(path, "write", home, hermes_home, "/plugin")
        app = rel[1] if len(rel) > 2 and rel[0] == ".config" else \
            rel[2] if len(rel) > 3 and rel[:2] in ([".local", "share"], [".local", "state"]) else ""
        if rule == "write_outside_folder" and app and app.lower().lstrip(".") in own_names:
            # Its own settings folder (like ~/.config/sentry for the Sentry server): normal, but listed.
            # Only plain writes: start-up places and Hermes's files keep their own rules whatever its name.
            grouped.setdefault(("write_own_state", LOW, "Kept its own settings in your home folder", None),
                               []).append(f"{path} ({label})")
            continue
        if rule == "content_altered":
            rule = "agent_config_modified"
        title = {"persistence": "Wrote to a place that starts programs automatically",
                 "agent_config_modified": "Changed Hermes's own files (config, memory, plugins or skills)",
                 "self_modify": "Changed its own files",
                 "write_outside_folder": "Wrote or changed sensitive files outside its folder",
                 "write_own_state": "Kept its own files in your home folder",
                 "write_tmp": "Wrote temporary files"}.get(rule, "Wrote files")
        grouped.setdefault((rule, sev, title, tech), []).append(f"{path} ({label})")
    for (rule, sev, title, tech), paths in grouped.items():    # one finding per kind, not per file
        uniq = list(dict.fromkeys(paths))
        findings.append(Finding(rule, sev, title, uniq[:8] + ([f"and {len(uniq) - 8} more"] if len(uniq) > 8 else []),
                                attack=[tech] if tech else []))
    programs = [x for x in programs if not _HARMLESS_PROGRAM.match(x[2])]
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
        # Many honest servers check for updates or load their service's settings at start-up. That is
        # worth a look; taking keys or decoys (caught by their own rules) is what makes it an alarm.
        findings.append(Finding("undeclared_network", MEDIUM,
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
    for o in result.get("oversized") or []:
        floods.append(f'a {int(o.get("bytes") or 0) // 1_000_000} MB message {_phase_label(str(o.get("phase") or ""), calls)} '
                      "(too big to read; Hermes would try to)")
    if floods:
        out.append(Finding("output_flood", MEDIUM, "Returned a very large amount of text to the model", floods[:5]))
    sampling = [r for r in result.get("from_server") or [] if r.get("method") == "sampling/createMessage"]
    if sampling:
        text = " ".join(str(r.get("params")) for r in sampling)
        bad = rules._secret_hits(_strip(text, declared), canary) or rules._injection_hits(text)
        # Sampling is a normal MCP feature (on by default in Hermes), so a plain request is worth a
        # look, not an alarm; keys or hidden orders in it make it critical.
        out.append(Finding("mcp_sampling_used", CRITICAL if bad else MEDIUM,
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
    findings: list[Finding] = [Finding(rule, sev, title, list(ev))
                               for rule, sev, title, ev in (result.get("config_checks") or [])]
    if result.get("remote") or result.get("config_only"):
        findings.sort(key=lambda f: rules.SEVERITY_ORDER.index(f.severity))
        extra = {"remote": True} if result.get("remote") else {"config_only": True}
        return {"verdict": rules._verdict(findings), "findings": [f.to_dict() for f in findings],
                "outside": summary, "tools": [], **extra}
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
        # The server is its own process here, so signals it sends to the stand-in for Hermes are
        # checked directly (in plugin mode the plugin runs inside the harness instead).
        trace = out.get("trace") or {}
        hp = str(trace.get("harness_pid") or "")
        killed = [f'{e.get("call")}({str(e.get("detail")).split(")")[0][:40]}): stopped the stand-in for Hermes'
                  for e in trace.get("events") or []
                  if e.get("call") in ("kill", "tkill", "tgkill") and not e.get("in_harness") and hp
                  and not e.get("error") and str(e.get("detail") or "").split(",")[0].strip() == hp
                  and rules._kill_signal(e) not in ("0", "SIGCHLD", "")]
        if killed and not any(f.rule == "monitor_tamper" for f in findings):
            findings.append(Finding("monitor_tamper", HIGH, "Tried to interfere with runtime monitoring", killed[:3]))
        own = [str(e.get("host")) for e in (out.get("sink") or {}).get("tcp") or []
               if any(v in str(e.get("data") or "") for v in declared)]
        if own:
            findings.append(Finding("declared_env_read", INFO, "Sent its own declared key to the service it wraps",
                                    sorted(set(own))[:5],
                                    why="The server got this key from its env entry and sent it where its "
                                        "tool calls went. Check that the host is the service the server is for."))
    scripts = result.get("install_scripts") or []
    if scripts:
        during = [str(ev) for f in findings if f.rule in _RISKY_RULES for ev in f.evidence if "while installing" in str(ev)]
        names = [f'{s.get("package")}: {", ".join(sorted(s.get("scripts") or {}))}' for s in scripts[:6]]
        runs = result.get("install_runs") or []
        if during:
            findings.append(Finding("mcp_install_script", HIGH, "Its install scripts did risky things",
                                    during[:6] + names[:3]))
        else:
            findings.append(Finding("mcp_install_script", INFO,
                                    "Has install scripts; they ran in the sandbox and did nothing risky"
                                    if runs else "Has install scripts (they did not run)", names))
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
    detail = None
    if not out.get("ran") and verdict in (rules.VERDICT_NO_FINDINGS, rules.VERDICT_REVIEW):
        # The server is its own process: only the outside monitor sees what it does. Without
        # it a clean verdict would only mean "its descriptions look fine", so say that instead.
        verdict = rules.VERDICT_ERROR
        detail = ("The outside monitor did not run (" + str(out.get("reason") or "unknown reason")[:300] +
                  "), so what the server did was not watched. Only what it told the model was checked. "
                  "Run /detonate check, fix what it reports, and try again.")
    return {"verdict": verdict, "findings": [f.to_dict() for f in findings], "outside": summary,
            **({"detail": detail} if detail else {}),
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
    if raw and raw.get("path_args"):
        how += (f" Its {len(raw['path_args'])} folder or file argument(s) from the config were swapped for "
                "empty test ones, so it never saw your real files.")
    if marker in text:
        head, tail = text.split(marker, 1)
        tail = tail.split("\n\n", 2)
        text = head + "\n".join(offered) + "\n" + marker + "\n\n" + how + "\n\n" + (tail[2] if len(tail) > 2 else "")
    return text


def main(argv=None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(prog="python -m engine.mcp")
    ap.add_argument("path", nargs="?", help=f"folder with an MCP server and its {ENTRY_FILE}")
    ap.add_argument("--server", help="a server name from Hermes's config.yaml (mcp_servers)")
    ap.add_argument("--config", help="config.yaml to read (default: $HERMES_HOME/config.yaml)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--raw", help="write the raw harness result to this file")
    args = ap.parse_args(argv)
    import tempfile
    try:
        with tempfile.TemporaryDirectory(prefix="detonator-mcp-") as work:
            if args.server:
                target = load_config_target(args.server, Path(work), Path(args.config) if args.config else None)
            elif args.path:
                target = load_folder_entry(args.path)
            else:
                ap.error("give a folder or --server <name>")
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
