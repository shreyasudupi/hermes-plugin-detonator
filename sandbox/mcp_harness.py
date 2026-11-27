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
import re
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
REPEAT_ROUNDS = 3           # extra calls of every tool, for servers that turn bad after a few uses
REPEAT_BUDGET_S = 25
CLOCK_DAYS = 400            # the later pass: the server restarted with its clock this far ahead
LATE_MIN_LEFT_S = 30        # skip the later pass when less run budget than this is left


def _short(value, limit=MAX_KEEP):
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text if len(text) <= limit else text[:limit] + f"…[{len(text) - limit} more]"


def test_address(canary):
    """The one email address tools are given. Every test value carries the canary followed by the
    input tag (-ARG), so the host never mistakes it for a fake key."""
    return f"det-{canary.lower()}-arg@example.com"


def _kind(key, spec):
    """What a string field holds, from its JSON Schema format or its name."""
    fmt = str(spec.get("format") or "").lower()
    words = set(re.split(r"[^a-z]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", str(key)).lower()))
    if fmt == "email" or words & {"email", "to", "cc", "bcc", "recipient", "recipients"}:
        return "email"
    if fmt in ("uri", "url", "iri") or words & {"url", "uri", "link", "href", "website"}:
        return "url"
    if words & {"path", "file", "filename", "filepath", "dir", "directory", "folder"}:
        return "path"
    return "text"


def _value(h, key, spec, data_dir, depth=0):
    spec = spec if isinstance(spec, dict) else {}
    if spec.get("enum"):
        return spec["enum"][0]
    t = spec.get("type", "string")
    t = t[0] if isinstance(t, list) and t else t
    if t == "array":
        return [_value(h, key, spec.get("items") or {}, data_dir, depth + 1)] if depth < 3 else []
    if t == "object":
        props = spec.get("properties") or {}
        return {k: _value(h, k, v, data_dir, depth + 1) for k, v in list(props.items())[:20]} if depth < 3 else {}
    if t in ("integer", "number"):
        low = spec.get("minimum")
        return low if isinstance(low, (int, float)) else (1 if t == "integer" else 1.0)
    if t == "boolean":
        return False
    kind = _kind(key, spec)
    if kind == "email":
        return test_address(h.CANARY)
    if kind == "url":
        return f"https://example.com/detonator-{h.CANARY}-ARG"
    if kind == "path":
        return os.path.join(data_dir, f"detonator-{h.CANARY}-ARG.txt")
    return f"detonator test input [{h.CANARY}-ARG]"


def _schema_args(h, schema, data_dir, required_only=False):
    """Test arguments for an MCP inputSchema that look like what each field wants (an email
    address, a link, a file in the server's test folder), so tools get past their own input
    checks and do their real work. Every value carries this run's canary.
    required_only: just the fields the schema requires, the way a person usually calls a tool.
    A server can reject a made-up optional value (an attachment link) before it does its real
    work, as a real hidden-Bcc backdoor did, so some calls leave the optional ones out."""
    props = (schema or {}).get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return {}
    need = schema.get("required") if isinstance(schema.get("required"), list) else []
    return {k: _value(h, k, v, data_dir) for k, v in list(props.items())[:40]
            if not required_only or k in need}


def _has_optional(schema):
    props = (schema or {}).get("properties") if isinstance(schema, dict) else None
    need = schema.get("required") if isinstance(schema, dict) and isinstance(schema.get("required"), list) else []
    return isinstance(props, dict) and any(k not in need for k in list(props)[:40])


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


_PY_CLOCK = """\
# Detonator test: this server's clock runs {days} days ahead, to wake code that waits for a date.
import datetime as _d, time as _t
_S = {seconds}
_rt, _rtn = _t.time, _t.time_ns
_lt, _gt, _ct, _sf = _t.localtime, _t.gmtime, _t.ctime, _t.strftime
_t.time = lambda: _rt() + _S
_t.time_ns = lambda: _rtn() + _S * 1000000000
_t.localtime = lambda s=None: _lt(_t.time() if s is None else s)
_t.gmtime = lambda s=None: _gt(_t.time() if s is None else s)
_t.ctime = lambda s=None: _ct(_t.time() if s is None else s)
_t.strftime = lambda f, v=None: _sf(f, _t.localtime() if v is None else v)
_RD, _RT = _d.date, _d.datetime


class _M(type):
    def __instancecheck__(cls, obj):
        return isinstance(obj, cls._real)

    def __subclasscheck__(cls, sub):
        return issubclass(sub, cls._real)


class date(_RD, metaclass=_M):
    _real = _RD

    @classmethod
    def today(cls):
        return cls.fromtimestamp(_t.time())


class datetime(_RT, metaclass=_M):
    _real = _RT

    @classmethod
    def now(cls, tz=None):
        return cls.fromtimestamp(_t.time(), tz)

    @classmethod
    def today(cls):
        return cls.fromtimestamp(_t.time())

    @classmethod
    def utcnow(cls):
        return cls.fromtimestamp(_t.time(), _d.timezone.utc).replace(tzinfo=None)


_d.date, _d.datetime = date, datetime
"""

_JS_CLOCK = """\
// Detonator test: this server's clock runs {days} days ahead, to wake code that waits for a date.
(() => {{
  const S = {seconds} * 1000, R = Date;
  class D extends R {{
    constructor(...a) {{ if (a.length === 0) super(R.now() + S); else super(...a); }}
    static now() {{ return R.now() + S; }}
  }}
  globalThis.Date = new Proxy(D, {{ apply() {{ return new D().toString(); }} }});
}})();
"""


def clock_env(env, folder, days):
    """The server's env for the later pass: Python and Node load a small file first that moves
    their clock `days` ahead. Other languages keep the real clock (the report says which ran)."""
    seconds = days * 86400
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "sitecustomize.py"), "w") as f:
        f.write(_PY_CLOCK.format(days=days, seconds=seconds))
    js = os.path.join(folder, "clock.cjs")
    with open(js, "w") as f:
        f.write(_JS_CLOCK.format(days=days, seconds=seconds))
    env = dict(env)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (folder, env.get("PYTHONPATH")) if p)
    env["NODE_OPTIONS"] = " ".join(p for p in (env.get("NODE_OPTIONS"), f"--require={js}") if p)
    return env


# A declared variable whose name says it holds an address (SIYUAN_URL, ES_HOST, API_BASE) gets a
# fake address, not a fake key. Same list as engine/mcp.py (ADDRESS_NAME_RE, fake_address).
_ADDRESS_NAME_RE = re.compile(r"(?:^|_)(?:URL|URI|ENDPOINT|BASE|BASEURL|ORIGIN|HOST|HOSTNAME|SERVER|DOMAIN|ADDR|ADDRESS)$",
                              re.IGNORECASE)
_HOST_ONLY_RE = re.compile(r"(?:HOST|HOSTNAME|SERVER|DOMAIN|ADDR|ADDRESS)$", re.IGNORECASE)


def fake_address(name):
    host = (re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")[:40].strip("-") or "service") + ".example.com"
    return host if _HOST_ONLY_RE.search(str(name)) else "https://" + host


def fake_value(canary, i, name=""):
    """The fake value for the server's i-th env entry (sorted by name). The host computes the same
    value, so it knows which leaks are the server's own declared keys."""
    if name and _ADDRESS_NAME_RE.search(str(name)):
        return fake_address(name)
    return f"sk-det-{canary}-env{i}"


def load_entry(canary):
    with open(MCP_PATH) as f:
        entry = json.load(f)
    argv = [str(entry["command"])] + [str(a) for a in entry.get("args") or []]
    names = sorted(str(k) for k in (entry.get("env") or {}))
    extra = {str(k): str(v) for k, v in (entry.get("extra_env") or {}).items()}   # set by Detonator, no secrets
    install = [[str(a) for a in cmd] for cmd in entry.get("install") or [] if isinstance(cmd, list)]
    return argv, {k: fake_value(canary, i, k) for i, k in enumerate(names)}, extra, install[:1]


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
        "canary": h.CANARY, "secret_markers": h.SECRET_MARKERS + sorted(v for v in declared.values() if h.CANARY in v),
        "declared_env": sorted(declared), "argv": argv,
    })
    h.plant_decoys()
    os.makedirs(result["allowed_write_dirs"][0], exist_ok=True)
    argv, result["path_args"] = swap_path_args(argv, result["allowed_write_dirs"][0], h.PLUGIN_DIR)
    # A file for tools that read one: test values name it, and it holds nothing of the person's.
    with open(os.path.join(result["allowed_write_dirs"][0], f"detonator-{h.CANARY}-ARG.txt"), "w") as f:
        f.write(f"detonator test file [{h.CANARY}]\n")
    result["test_address"] = test_address(h.CANARY)
    result["argv"] = argv
    # What Hermes hands a stdio server: its own env entries plus a small safe baseline.
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home, "TERM": "xterm-256color",
           "USER": os.environ.get("USER", ""), "LANG": "C.UTF-8", **extra_env, **declared,
           # This run's test certificate authority (from the fake internet), as a person's own
           # proxy or company network would set it, so HTTPS from the server can be read.
           **{k: os.environ[k] for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
                                         "CURL_CA_BUNDLE") if os.environ.get(k)}}
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
    first = _session(h, server, result, "", started)
    if first is None:
        return _finish(h, result, server)
    result.update(first)

    # The later pass: the same server started again with its clock moved forward, used once more
    # and listed again. Code that waits for a date, or for weeks after install, shows itself here.
    if time.monotonic() - started > RUN_BUDGET_S - LATE_MIN_LEFT_S:
        result["late"] = {"skipped": "not enough time left in the run"}
        return _finish(h, result, server)
    _collect(server, result)
    server.stop()
    h._PHASE = "late-start"
    h.phase_marker("mcp-late-start")
    late = {"clock_days": CLOCK_DAYS, "started_at": time.time()}
    try:
        # Not named after the canary: env-dumping tools show this path, and it must not read as a key.
        late["clock_dir"] = f"/tmp/clock-{os.urandom(6).hex()}"
        server = Server(h, argv, clock_env(env, late["clock_dir"], CLOCK_DAYS), h.PLUGIN_DIR, started)
    except OSError as exc:
        late["start_error"] = f"{type(exc).__name__}: {exc}"[:500]
        result["late"] = late
        return _finish(h, result, None)
    late["server_pid"] = server.proc.pid
    got = _session(h, server, late, "late-", started, repeat=False)
    if got:
        late.update(got)
    result["late"] = late
    return _finish(h, result, server, into=late)


def _session(h, server, result, prefix, started, repeat=True):
    """Initialize, list, call every tool, read resources and prompts, list again. Returns what
    was seen, or None (after recording why in `result`) when the server did not start."""
    h._PHASE = prefix + "initialize"
    h.phase_marker("mcp-" + prefix + "initialize")
    init = server.request("initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"sampling": {}, "elicitation": {}, "roots": {"listChanged": True}},
        "clientInfo": {"name": "hermes-agent", "version": "0.9.0"},
    }, timeout=START_TIMEOUT_S)
    result["initialize"] = {"error": init.get("error")} if "error" in init else _short_dict(init.get("result"))
    if "error" in init:
        return None
    server.notify("notifications/initialized")
    caps = (init.get("result") or {}).get("capabilities") or {}
    seen = {}

    def listing(phase):
        h._PHASE = prefix + phase
        h.phase_marker("mcp-" + prefix + phase)
        tools, errs = _list_all(server, "tools/list", "tools")
        out = {"tools": tools[:MAX_TOOLS * 2], "errors": errs}
        if caps.get("resources"):
            out["resources"], out["resource_errors"] = _list_all(server, "resources/list", "resources")
        if caps.get("prompts"):
            out["prompts"], out["prompt_errors"] = _list_all(server, "prompts/list", "prompts")
        return out

    first = listing("list")
    seen["listing"] = first
    data_dir = os.path.join(h.HERMES_HOME, "mcp-data")

    def call(i, tool, phase, round_=1):
        name = str(tool.get("name") or "")
        h._PHASE = phase
        h.phase_marker("mcp-" + phase)
        # Even repeat rounds (2, 4) send only the required fields when the tool has optional ones.
        args = _schema_args(h, tool.get("inputSchema"), data_dir,
                            required_only=round_ % 2 == 0 and _has_optional(tool.get("inputSchema")))
        r = server.request("tools/call", {"name": name, "arguments": args})
        res = r.get("result") if isinstance(r.get("result"), dict) else {}
        text = json.dumps(res.get("content"), default=str) if res else ""
        return {"index": i, "round": round_, "tool": name[:200], "args": args, "ok": "error" not in r,
                "error": r.get("error"), "is_error": bool(res.get("isError")),
                "returned": _short(res.get("content"), MAX_KEEP) if res else None,
                "returned_size": len(text),
                "annotations": tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}}

    tools = first["tools"][:MAX_TOOLS]
    calls = []
    for i, tool in enumerate(tools):
        if time.monotonic() - started > RUN_BUDGET_S:
            seen["over_time_budget"] = True
            break
        calls.append(call(i, tool, f"{prefix}call-{i}"))
    # Every tool a few more times: some servers behave until they have been used a while.
    if repeat:
        until = time.monotonic() + REPEAT_BUDGET_S
        for round_ in range(2, REPEAT_ROUNDS + 2):
            for i, tool in enumerate(tools[:len(calls)]):
                if time.monotonic() > until or time.monotonic() - started > RUN_BUDGET_S:
                    break
                calls.append(call(i, tool, f"again-{i}", round_))
    seen["calls"] = calls

    reads = []
    for i, res in enumerate((first.get("resources") or [])[:MAX_ITEMS]):
        h._PHASE = f"{prefix}resource:{i}"
        h.phase_marker(f"mcp-{prefix}resource-{i}")
        r = server.request("resources/read", {"uri": str(res.get("uri") or "")})
        reads.append({"index": i, "uri": str(res.get("uri"))[:300], "error": r.get("error"),
                      "returned": _short(r.get("result"), MAX_KEEP) if "result" in r else None})
    seen["resource_reads"] = reads

    gets = []
    for i, p in enumerate((first.get("prompts") or [])[:MAX_ITEMS]):
        h._PHASE = f"{prefix}prompt:{i}"
        h.phase_marker(f"mcp-{prefix}prompt-{i}")
        args = {str(a.get("name")): f"detonator test input [{h.CANARY}-ARG]"
                for a in p.get("arguments") or [] if isinstance(a, dict)}
        r = server.request("prompts/get", {"name": str(p.get("name") or ""), "arguments": args})
        gets.append({"index": i, "name": str(p.get("name"))[:200], "error": r.get("error"),
                     "returned": _short(r.get("result"), MAX_KEEP) if "result" in r else None})
    seen["prompt_gets"] = gets

    # Hermes keeps a server running and lists again when told the tools changed; a second
    # listing after real use catches descriptions that turn bad later (a rug pull).
    server.drain(SETTLE_S)
    seen["relisting"] = listing("relist")
    return seen


def _short_dict(value):
    if not isinstance(value, dict):
        return {"value": _short(value, 20_000)}
    text = json.dumps(value, default=str)
    return value if len(text) <= 50_000 else {"oversized": _short(text, 50_000)}


def _collect(server, into):
    server.drain(0.2)
    into["from_server"] = server.from_server
    into["notifications"] = server.notifications
    into["bad_lines"] = server.bad_lines
    into["oversized"] = server.oversized
    into["server_exit"] = server.proc.poll()
    into["stderr_tail"] = server.stderr.decode("utf-8", "replace")


def _finish(h, result, server, into=None):
    h._PHASE = "done"
    if server:
        _collect(server, result if into is None else into)
        (result if into is None else into)["server_stopped"] = server.stop()
    h.release_fd()
    h.phase_marker("plugin-done")
    h.write_result(result, indent=1, default=str)
    os._exit(0)
