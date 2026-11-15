"""Detonator's MCP mode: plays Hermes towards one MCP server, inside the disposable container.

Started by harness.py when the host asks for an MCP run (/in/run.json has "mode": "mcp"),
so the outside tracer finds and follows it exactly as for plugins. It:
  1. plants the same decoy Hermes home as a plugin run,
  2. starts the server (command, args and env from /in/mcp.json, env values are fake keys),
  3. speaks MCP to it over stdin/stdout (JSON-RPC, one message per line), as Hermes would:
     initialize, list tools/resources/prompts, call every tool with canary arguments,
     read resources and prompts, then list everything again to catch changes,
  4. answers what the server asks of the client (sampling, elicitation, roots) and records it,
  5. writes everything it saw to /out/result.json.

It makes no decisions. The host-side rules (engine/mcp.py) judge the result together with
what the outside monitor saw. The server is a separate process, often not Python, so this
file cannot watch inside it; the tracer and the fake internet do that.
"""

import json
import os
import queue
import signal
import subprocess
import threading
import time

MCP_PATH = "/in/mcp.json"
PROTOCOL_VERSION = "2025-06-18"
REQUEST_TIMEOUT_S = 10
START_TIMEOUT_S = 20
RUN_BUDGET_S = 120          # the host stops an MCP container after 240 s (45 s install + this + start)
MAX_TOOLS = 40
MAX_ITEMS = 10              # resources and prompts read
MAX_PAGES = 5
MAX_LINE = 2_000_000        # one JSON-RPC message
MAX_KEEP = 200_000          # characters of any one result kept for the rules
MAX_RECORDS = 200           # server-to-client requests and notifications kept
STDERR_KEEP = 4000
SETTLE_S = 1.0


def _short(value, limit=MAX_KEEP):
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text if len(text) <= limit else text[:limit] + f"…[{len(text) - limit} more]"


def _schema_args(h, schema):
    """Canary arguments for an MCP inputSchema (the harness builds them for the Hermes shape)."""
    return h.sample_args({"parameters": schema if isinstance(schema, dict) else {}})


class Server:
    """One MCP server over stdio. Messages the server sends on its own (requests to the
    client, notifications) are answered and recorded while we wait for our replies."""

    def __init__(self, h, argv, env, cwd, started):
        self.h = h
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, cwd=cwd, env=env, start_new_session=True)
        self.inbox = queue.Queue()
        self.next_id = 0
        self.from_server = []      # requests the server sent to us
        self.notifications = []
        self.bad_lines = 0
        self.oversized = []        # messages over MAX_LINE, skipped unread
        self.stderr = b""
        self.started = started
        threading.Thread(target=self._read_out, daemon=True).start()
        threading.Thread(target=self._read_err, daemon=True).start()

    def _read_out(self):
        while True:
            try:
                line = self.proc.stdout.readline(MAX_LINE)
            except (OSError, ValueError):
                break
            if not line:
                break
            if len(line) >= MAX_LINE and not line.endswith(b"\n"):
                # Too big to read as one message: skip the rest of it and remember that it happened.
                size = len(line)
                while True:
                    try:
                        more = self.proc.stdout.readline(MAX_LINE)
                    except (OSError, ValueError):
                        more = b""
                    size += len(more)
                    if not more or more.endswith(b"\n") or size > 2_000_000_000:
                        break
                if len(self.oversized) < MAX_RECORDS:
                    self.oversized.append({"phase": self.h._PHASE, "bytes": size})
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                self.bad_lines += 1
                continue
            if isinstance(msg, dict):
                self.inbox.put(msg)
        self.inbox.put(None)

    def _read_err(self):
        while True:
            try:
                chunk = self.proc.stderr.read(4096)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            self.stderr = (self.stderr + chunk)[-STDERR_KEEP:]

    def send(self, msg):
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode())
            self.proc.stdin.flush()
            return True
        except (OSError, ValueError):
            return False

    def _answer(self, msg):
        method = str(msg.get("method"))
        params = msg.get("params")
        rec = {"method": method[:100], "params": _short(params, 20_000), "phase": self.h._PHASE}
        if len(self.from_server) < MAX_RECORDS:
            self.from_server.append(rec)
        canary = self.h.CANARY
        if method == "sampling/createMessage":
            result = {"role": "assistant", "model": "test/model", "stopReason": "endTurn",
                      "content": {"type": "text", "text": f"Done. [{canary}-ASSISTANT]"}}
        elif method == "elicitation/create":
            result = {"action": "decline"}
        elif method == "roots/list":
            result = {"roots": []}
        elif method == "ping":
            result = {}
        else:
            self.send({"jsonrpc": "2.0", "id": msg.get("id"),
                       "error": {"code": -32601, "message": "Method not found"}})
            return
        self.send({"jsonrpc": "2.0", "id": msg.get("id"), "result": result})

    def request(self, method, params=None, timeout=REQUEST_TIMEOUT_S):
        self.next_id += 1
        rid = self.next_id
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        if not self.send(msg):
            return {"error": "the server closed its input"}
        deadline = min(time.monotonic() + timeout, self.started + RUN_BUDGET_S)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return {"error": f"no answer within {timeout}s", "timeout": True}
            try:
                got = self.inbox.get(timeout=left)
            except queue.Empty:
                continue
            if got is None:
                self.inbox.put(None)
                return {"error": "the server exited"}
            if "method" in got and "id" in got:
                self._answer(got)
            elif "method" in got:
                if len(self.notifications) < MAX_RECORDS:
                    self.notifications.append({"method": str(got.get("method"))[:100],
                                               "params": _short(got.get("params"), 2000),
                                               "phase": self.h._PHASE})
            elif got.get("id") == rid:
                if "error" in got:
                    return {"error": _short(got.get("error"), 2000)}
                return {"result": got.get("result")}

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)

    def drain(self, seconds):
        """Keep answering the server for a moment after our last request."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                got = self.inbox.get(timeout=max(0.01, end - time.monotonic()))
            except queue.Empty:
                break
            if got is None:
                self.inbox.put(None)
                break
            if "method" in got and "id" in got:
                self._answer(got)
            elif "method" in got and len(self.notifications) < MAX_RECORDS:
                self.notifications.append({"method": str(got.get("method"))[:100],
                                           "params": _short(got.get("params"), 2000), "phase": self.h._PHASE})

    def stop(self):
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            pass
        return self.proc.returncode


def _list_all(server, method, key):
    items, cursor, errors = [], None, []
    for _ in range(MAX_PAGES):
        r = server.request(method, {"cursor": cursor} if cursor else {})
        if "error" in r:
            errors.append(str(r["error"])[:300])
            break
        res = r.get("result") or {}
        page = res.get(key) if isinstance(res, dict) else None
        if isinstance(page, list):
            items.extend(x for x in page if isinstance(x, dict))
        cursor = res.get("nextCursor") if isinstance(res, dict) else None
        if not cursor:
            break
    return [json.loads(_short(x, 50_000)) if len(json.dumps(x, default=str)) <= 50_000
            else {"name": str(x.get("name"))[:200], "oversized": True, "description": _short(x, 50_000)}
            for x in items], errors


def fake_value(canary, i):
    """The fake key for the server's i-th env entry (sorted by name). The host computes the same
    value, so it knows which leaks are the server's own declared keys."""
    return f"sk-det-{canary}-env{i}"


def load_entry(canary):
    with open(MCP_PATH) as f:
        entry = json.load(f)
    argv = [str(entry["command"])] + [str(a) for a in entry.get("args") or []]
    names = sorted(str(k) for k in (entry.get("env") or {}))
    extra = {str(k): str(v) for k, v in (entry.get("extra_env") or {}).items()}   # set by Detonator, no secrets
    install = [[str(a) for a in cmd] for cmd in entry.get("install") or [] if isinstance(cmd, list)]
    return argv, {k: fake_value(canary, i) for i, k in enumerate(names)}, extra, install[:1]


def swap_path_args(argv, data_dir, plugin_dir):
    """Folders and files from the person's computer (like a filesystem server's allowed folder or a
    database file) do not exist here. Each absolute or ~ path argument becomes its own empty folder
    under mcp-data (or a not-yet-existing file in one, when it looks like a file), so the server
    starts and works on a harmless copy. The program and its script are left alone."""
    out, swapped = list(argv[:1]), []
    for a in argv[1:]:
        flag, sep, val = a.partition("=") if a.startswith("--") else ("", "", a)
        if not (val.startswith("/") or val.startswith("~")) or val.startswith(plugin_dir) \
                or val.startswith("/usr/") or val.startswith("/opt/") or len(swapped) >= 8:
            out.append(a)
            continue
        new = os.path.join(data_dir, f"folder-{len(swapped)}")
        os.makedirs(new, exist_ok=True)
        base = os.path.basename(val.rstrip("/"))
        if os.path.splitext(base)[1] and not val.endswith("/"):
            new = os.path.join(new, base)    # looks like a file (test.db): a new file in an empty folder
        swapped.append(new)
        out.append(flag + sep + new if sep else new)
    return out, swapped


INSTALL_TIMEOUT_S = 45


def run_install(h, commands, result):
    """Run the package's install scripts (npm lifecycle scripts) offline, watched by the tracer.
    They get the environment of a person's shell, decoy API keys included, as a real install would."""
    runs = []
    env = dict(os.environ)
    env.update({"npm_config_offline": "true", "npm_config_update_notifier": "false",
                "npm_config_fund": "false", "npm_config_audit": "false"})
    for argv in commands:
        try:
            p = subprocess.run(argv, cwd=h.PLUGIN_DIR, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                               timeout=INSTALL_TIMEOUT_S, start_new_session=True)
            runs.append({"argv": argv, "exit": p.returncode,
                         "output": (p.stdout + p.stderr).decode("utf-8", "replace")[-STDERR_KEEP:]})
        except subprocess.TimeoutExpired:
            runs.append({"argv": argv, "exit": None, "output": f"stopped after {INSTALL_TIMEOUT_S}s"})
        except OSError as exc:
            runs.append({"argv": argv, "exit": None, "output": f"{type(exc).__name__}: {exc}"[:300]})
    result["install_runs"] = runs


def run(h):
    """Called by harness.py with itself as `h`, after the tracer is attached."""
    result = {"harness_version": 2, "mode": "mcp", "errors": []}
    argv, declared, extra_env, install = load_entry(h.CANARY)
    home = h.HOME
    result.update({
        "home": home, "plugin_dir": h.PLUGIN_DIR,
        "allowed_write_dirs": [os.path.join(h.HERMES_HOME, "mcp-data")],
        "decoy_paths": sorted(h.ALL_DECOY_PATHS), "decoy_categories": h.DECOY_CATEGORIES,
        "decoy_dirs": h.DECOY_DIRS, "memory_paths": sorted(set(h.MEMORY_FILES) | set(h.HISTORY_FILES)),
        "canary": h.CANARY, "secret_markers": h.SECRET_MARKERS + sorted(declared.values()),
        "declared_env": sorted(declared), "argv": argv,
    })
    h.plant_decoys()
    os.makedirs(result["allowed_write_dirs"][0], exist_ok=True)
    argv, result["path_args"] = swap_path_args(argv, result["allowed_write_dirs"][0], h.PLUGIN_DIR)
    result["argv"] = argv
    # What Hermes hands a stdio server: its own env entries plus a small safe baseline.
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home, "TERM": "xterm-256color",
           "USER": os.environ.get("USER", ""), "LANG": "C.UTF-8", **extra_env, **declared}
    if h.TRACED:
        result["traced"] = h.wait_for_tracer()
    h.reserve_fd()
    h.phase_marker("plugin-start")
    started = time.monotonic()

    if install:
        h._PHASE = "install"
        h.phase_marker("mcp-install")
        run_install(h, install, result)
        started = time.monotonic()   # the run budget below is for the server itself

    h._PHASE = "start"
    h.phase_marker("mcp-start")
    try:
        server = Server(h, argv, env, h.PLUGIN_DIR, started)
    except OSError as exc:
        result["start_error"] = f"{type(exc).__name__}: {exc}"[:500]
        return _finish(h, result, None)
    result["server_pid"] = server.proc.pid

    h._PHASE = "initialize"
    h.phase_marker("mcp-initialize")
    init = server.request("initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"sampling": {}, "elicitation": {}, "roots": {"listChanged": True}},
        "clientInfo": {"name": "hermes-agent", "version": "0.9.0"},
    }, timeout=START_TIMEOUT_S)
    result["initialize"] = {"error": init.get("error")} if "error" in init else _short_dict(init.get("result"))
    if "error" in init:
        return _finish(h, result, server)
    server.notify("notifications/initialized")
    caps = (init.get("result") or {}).get("capabilities") or {}

    def listing(phase):
        h._PHASE = phase
        h.phase_marker("mcp-" + phase)
        tools, errs = _list_all(server, "tools/list", "tools")
        out = {"tools": tools[:MAX_TOOLS * 2], "errors": errs}
        if caps.get("resources"):
            out["resources"], out["resource_errors"] = _list_all(server, "resources/list", "resources")
        if caps.get("prompts"):
            out["prompts"], out["prompt_errors"] = _list_all(server, "prompts/list", "prompts")
        return out

    first = listing("list")
    result["listing"] = first

    calls = []
    for i, tool in enumerate(first["tools"][:MAX_TOOLS]):
        if time.monotonic() - started > RUN_BUDGET_S:
            result["over_time_budget"] = True
            break
        name = str(tool.get("name") or "")
        h._PHASE = f"call:{i}"
        h.phase_marker(f"mcp-call-{i}")
        args = _schema_args(h, tool.get("inputSchema"))
        r = server.request("tools/call", {"name": name, "arguments": args})
        res = r.get("result") if isinstance(r.get("result"), dict) else {}
        text = json.dumps(res.get("content"), default=str) if res else ""
        calls.append({"index": i, "tool": name[:200], "args": args, "ok": "error" not in r,
                      "error": r.get("error"), "is_error": bool(res.get("isError")),
                      "returned": _short(res.get("content"), MAX_KEEP) if res else None,
                      "returned_size": len(text),
                      "annotations": tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}})
    result["calls"] = calls

    reads = []
    for i, res in enumerate((first.get("resources") or [])[:MAX_ITEMS]):
        h._PHASE = f"resource:{i}"
        h.phase_marker(f"mcp-resource-{i}")
        r = server.request("resources/read", {"uri": str(res.get("uri") or "")})
        reads.append({"index": i, "uri": str(res.get("uri"))[:300], "error": r.get("error"),
                      "returned": _short(r.get("result"), MAX_KEEP) if "result" in r else None})
    result["resource_reads"] = reads

    gets = []
    for i, p in enumerate((first.get("prompts") or [])[:MAX_ITEMS]):
        h._PHASE = f"prompt:{i}"
        h.phase_marker(f"mcp-prompt-{i}")
        args = {str(a.get("name")): f"detonator test input [{h.CANARY}-ARG]"
                for a in p.get("arguments") or [] if isinstance(a, dict)}
        r = server.request("prompts/get", {"name": str(p.get("name") or ""), "arguments": args})
        gets.append({"index": i, "name": str(p.get("name"))[:200], "error": r.get("error"),
                     "returned": _short(r.get("result"), MAX_KEEP) if "result" in r else None})
    result["prompt_gets"] = gets

    # Hermes keeps a server running and lists again when told the tools changed; a second
    # listing after real use catches descriptions that turn bad later (a rug pull).
    server.drain(SETTLE_S)
    result["relisting"] = listing("relist")
    return _finish(h, result, server)


def _short_dict(value):
    if not isinstance(value, dict):
        return {"value": _short(value, 20_000)}
    text = json.dumps(value, default=str)
    return value if len(text) <= 50_000 else {"oversized": _short(text, 50_000)}


def _finish(h, result, server):
    h._PHASE = "done"
    if server:
        server.drain(0.2)
        result["from_server"] = server.from_server
        result["notifications"] = server.notifications
        result["bad_lines"] = server.bad_lines
        result["oversized"] = server.oversized
        result["server_exit"] = server.proc.poll()
        result["server_stopped"] = server.stop()
        result["stderr_tail"] = server.stderr.decode("utf-8", "replace")
    h.release_fd()
    h.phase_marker("plugin-done")
    with open(h.OUT_PATH, "w") as f:
        json.dump(result, f, indent=1, default=str)
    os._exit(0)
