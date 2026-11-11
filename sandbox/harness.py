"""Plugin Detonator sandbox harness.

Runs INSIDE the disposable container only. It:
  1. builds a throwaway Hermes home full of decoys (fake keys, SSH key, memory),
  2. installs a Python audit hook that logs file, process and socket activity,
  3. imports the plugin under test with a mock Hermes ``ctx``,
  4. fires synthetic hooks and tool calls carrying canary strings,
  5. writes everything it observed to /out/result.json.

It makes no decisions. The host-side rules turn observations into findings.
Audit hooks run in-process, so a determined plugin can evade them; the report
says so.
"""

import copy
import hashlib
import importlib.util
import json
import secrets
import os
import re
import signal
import sys
import time
import traceback

PLUGIN_DIR = "/plugin"
OUT_PATH = "/out/result.json"
MANIFEST_PATH = "/in/manifest.json"
HOME = os.environ.get("HOME", "/tmp/home")
HERMES_HOME = os.path.join(HOME, ".hermes")
CALL_TIMEOUT_S = 5
HOOK_REPEATS = 3
SETTLE_S = 2.0
CLOCK_SETTLE_S = 0.5
MAX_EVENTS = 5000

# Random on every run, so the fake keys don't carry a fixed word a plugin could
# look for. The rules find leaks through the markers the harness reports.
CANARY = secrets.token_hex(10).upper()

# --------------------------------------------------------------------------
# Decoys. All values are fake and contain the canary marker.
# --------------------------------------------------------------------------
DECOY_ENV = {
    "OPENROUTER_API_KEY": f"sk-or-v1-{CANARY}-0001",
    "OPENAI_API_KEY": f"sk-{CANARY}-0002",
    "ANTHROPIC_API_KEY": f"sk-ant-{CANARY}-0003",
    "GITHUB_TOKEN": f"ghp_{CANARY}0004",
    "AWS_SECRET_ACCESS_KEY": f"{CANARY}-0005",
}

DECOY_FILES = {
    os.path.join(HERMES_HOME, ".env"): "".join(
        f"{k}={v}\n" for k, v in DECOY_ENV.items()
    ),
    os.path.join(HERMES_HOME, "auth.json"): json.dumps(
        {"nous": {"access_token": f"{CANARY}-auth-0006"}}
    ),
    os.path.join(HOME, ".ssh", "id_ed25519"): (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"{CANARY}-ssh-0007\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    ),
    os.path.join(HOME, ".aws", "credentials"): (
        f"[default]\naws_access_key_id = AKIA{CANARY}\n"
        f"aws_secret_access_key = {CANARY}-0008\n"
    ),
}

# More places real stealers look (PyPI/npm malware reports): git, package
# registries, cloud CLIs, browsers and crypto wallets.
DECOY_FILES.update({
    os.path.join(HOME, ".git-credentials"): f"https://user:{CANARY}-git-0011@github.com\n",
    os.path.join(HOME, ".netrc"): f"machine api.example.com login user password {CANARY}-netrc-0012\n",
    os.path.join(HOME, ".docker", "config.json"): json.dumps({"auths": {"ghcr.io": {"auth": f"{CANARY}-docker-0013"}}}),
    os.path.join(HOME, ".kube", "config"): f"users:\n- name: admin\n  user:\n    token: {CANARY}-kube-0014\n",
    os.path.join(HOME, ".npmrc"): f"//registry.npmjs.org/:_authToken={CANARY}-npm-0015\n",
    os.path.join(HOME, ".pypirc"): f"[pypi]\nusername = __token__\npassword = pypi-{CANARY}-0016\n",
    os.path.join(HOME, ".config", "gh", "hosts.yml"): f"github.com:\n  oauth_token: gho_{CANARY}-0017\n",
})

BROWSER_FILES = {
    os.path.join(HOME, ".config", "google-chrome", "Default", "Login Data"): f"SQLite format 3 {CANARY}-chrome-0018",
    os.path.join(HOME, ".config", "google-chrome", "Default", "Cookies"): f"SQLite format 3 {CANARY}-cookie-0019",
    os.path.join(HOME, "Library", "Application Support", "Google", "Chrome", "Default", "Login Data"):
        f"SQLite format 3 {CANARY}-chrome-0020",
    os.path.join(HOME, ".mozilla", "firefox", "default", "logins.json"): json.dumps({"logins": [f"{CANARY}-ff-0021"]}),
}

WALLET_FILES = {
    os.path.join(HOME, ".config", "solana", "id.json"): f"[{CANARY}-sol-0022]",
    os.path.join(HOME, ".ethereum", "keystore", "UTC--2026-01-01--wallet"): json.dumps({"crypto": f"{CANARY}-eth-0023"}),
}

MEMORY_FILES = {
    os.path.join(HERMES_HOME, "memories", "MEMORY.md"): (
        f"# Memory\n- The user prefers concise answers. ({CANARY}-mem-0009)\n"
    ),
    os.path.join(HERMES_HOME, "memories", "USER.md"): (
        f"# User\n- Name: Test User ({CANARY}-user-0010)\n"
    ),
}

HISTORY_FILES = {
    os.path.join(HERMES_HOME, "sessions", "det-old-session.jsonl"): json.dumps(
        {"role": "user", "content": f"my bank pin is 0000 ({CANARY}-hist-0024)"}) + "\n",
}

# Substrings that only appear in decoy secrets / memory, never in synthetic args.
SECRET_MARKERS = [f"{CANARY}-{tag}" for tag in (
    "0001", "0002", "0003", "0005", "auth-0006", "ssh-0007", "0008", "mem-0009", "user-0010",
    "git-0011", "netrc-0012", "docker-0013", "kube-0014", "npm-0015", "0016", "0017",
    "chrome-0018", "cookie-0019", "chrome-0020", "ff-0021", "sol-0022", "eth-0023", "hist-0024",
)] + [f"ghp_{CANARY}0004"]

DECOY_CATEGORIES = {
    **{p: "secret" for p in DECOY_FILES},
    **{p: "browser" for p in BROWSER_FILES},
    **{p: "wallet" for p in WALLET_FILES},
    **{p: "memory" for p in MEMORY_FILES},
    **{p: "history" for p in HISTORY_FILES},
}
ALL_DECOY_PATHS = set(DECOY_CATEGORIES)
DECOY_DIRS = sorted({os.path.dirname(p) for p in ALL_DECOY_PATHS} | {HOME})

# Files malware reads to tell a sandbox or debugger from a real machine.
SANDBOX_PROBES = ("/.dockerenv", "/run/.containerenv", "/proc/1/cgroup", "/proc/self/cgroup",
                  "/proc/self/mountinfo", "/proc/1/sched", "/proc/self/status", "/sys/class/dmi/id",
                  "/proc/cpuinfo", "/sys/hypervisor")
# Account and host files under /etc (matched by name inside /etc).
# The process's own environment as a file under /proc. Reading it gets every API key
# at once without touching os.environ, so the env watch would not see it. (Pattern is
# split so Hermes's install scanner does not mistake this detector for an attack.)
ENVIRON_FILE = re.compile(r"^/pro" r"c/(?:self|thread-self|\d+)(?:/task/\d+)?/environ$")

RECON_NAMES = {"passwd", "shadow", "group", "gshadow", "sudoers", "hosts", "os-release", "machine-id"}

# --------------------------------------------------------------------------
# Observation log
# --------------------------------------------------------------------------
EVENTS = []
_ACTIVE = False
_PHASE = "setup"
_CLOCK_DAYS = 0
_IN_HOOK = False

_STD_PREFIXES = tuple(
    {os.path.realpath(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix)}
) + ("/opt/detonator",)

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def _record(kind, **data):
    event = {"t": round(time.monotonic(), 4), "phase": _PHASE, "kind": kind, **data}
    if _CLOCK_DAYS:
        event["clock_days"] = _CLOCK_DAYS
    EVENTS.append(event)


def _short(value, limit=300):
    try:
        text = value if isinstance(value, str) else repr(value)
    except Exception:
        text = "<unrepresentable>"
    return text if len(text) <= limit else text[:limit] + "..."


def _is_write(mode, flags):
    if isinstance(mode, str) and any(c in mode for c in "wax+"):
        return True
    if isinstance(flags, int) and flags & _WRITE_FLAGS:
        return True
    return False


def _target_path(arg):
    """Absolute path for a path or an open file descriptor (os.chmod(fd) etc.)."""
    try:
        if isinstance(arg, int):
            return os.readlink(f"/dev/fd/{arg}")
        if isinstance(arg, (str, bytes)):
            return os.path.realpath(os.fsdecode(arg))
    except OSError:
        pass
    return _short(arg)


def _audit(event, args):
    global _IN_HOOK
    if not _ACTIVE or _IN_HOOK:
        return
    _IN_HOOK = True
    try:
        if event == "open":
            path, mode, flags = (list(args) + [None, None, None])[:3]
            if not isinstance(path, (str, bytes)):
                return
            path = os.fsdecode(path)
            real = os.path.realpath(path)
            write = _is_write(mode, flags)
            if not write and (real.startswith(_STD_PREFIXES) or real.startswith(PLUGIN_DIR)):
                return  # normal imports / reading its own files
            if not write and (real.startswith(SANDBOX_PROBES) or path.startswith(SANDBOX_PROBES)):
                _record("sandbox_probe", path=path, by=_caller())
                return
            if ENVIRON_FILE.match(path) or ENVIRON_FILE.match(real):
                _record("environ_file_read", path=path, by=_caller())
                return
            if not write and os.path.dirname(real) == "/etc" and os.path.basename(real) in RECON_NAMES:
                _record("recon_read", path=real, by=_caller())
                return
            _record("file_write" if write else "file_read", path=real)
        elif event in ("os.putenv", "os.unsetenv"):
            key = os.fsdecode(args[0]) if args and isinstance(args[0], (str, bytes)) else _short(args)
            _record("env_write", op=event, name=key, by=_caller())
        elif event == "sys.addaudithook":
            _record("monitor_tamper", op=event, by=_caller())
        elif event in ("gc.get_objects", "gc.get_referrers", "gc.get_referents"):
            if _caller() == "plugin":
                _record("monitor_tamper", op=event, by="plugin")
        elif event in ("marshal.loads", "marshal.load"):
            if _caller() == "plugin":
                _record("hidden_code", op=event)
        elif event == "pickle.find_class":
            mod, attr = (list(args) + [None, None])[:2]
            if str(mod).split(".")[0] in ("os", "posix", "nt", "subprocess", "builtins", "sys", "socket",
                                          "importlib", "shutil", "pty", "runpy", "code", "ctypes"):
                _record("hidden_code", op=event, detail=f"{mod}.{attr}")
        elif event in ("os.remove", "os.rename", "os.unlink", "shutil.rmtree", "os.rmdir", "os.truncate", "os.chmod"):
            _record("file_modify", op=event, path=_target_path(args[0] if args else None))
        elif event in ("os.listdir", "os.scandir"):
            path = os.fsdecode(args[0]) if args and isinstance(args[0], (str, bytes)) else "."
            real = os.path.realpath(path)
            if not (real.startswith(_STD_PREFIXES) or real.startswith(PLUGIN_DIR)):
                _record("dir_list", path=real)
        elif event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty", "pty.spawn"):
            _record("process", op=event, detail=_short(args))
        elif event in ("socket.connect", "socket.sendto", "socket.bind"):
            _record("network", op=event, address=_short(args[1] if len(args) > 1 else args))
        elif event == "socket.getaddrinfo":
            _record("network", op=event, address=_short(args[:2]))
        elif event == "urllib.Request":
            _record("network", op=event, address=_short(args[0] if args else None))
        elif event in ("ctypes.dlopen", "ctypes.dlsym"):
            _record("native", op=event, detail=_short(args))
        elif event == "compile":
            source, filename = (list(args) + [None, None])[:2]
            fname = os.fsdecode(filename) if isinstance(filename, (str, bytes)) else ""
            by = _caller()
            # Code compiled from a string gets a pseudo file name like <string>; real
            # module files (stdlib imported without .pyc caches) do not count.
            if by == "plugin" and isinstance(source, (str, bytes)) and fname.startswith("<") \
                    and not fname.startswith("<frozen"):
                # exec()/eval()/compile() of a string written by the plugin itself
                _record("dynamic_code", op=event, by="plugin", detail=_short(source, 200))
                return
            if _PHASE == "import":
                return
            if not os.path.realpath(fname or "/").startswith(_STD_PREFIXES + (PLUGIN_DIR,)) \
                    or fname in ("<string>", "<unknown>"):
                if fname.startswith("<frozen"):
                    return
                _record("dynamic_code", op=event, by=by, detail=_short(source, 120))
        elif event == "exec" and _PHASE != "import":
            code = args[0] if args else None
            fname = getattr(code, "co_filename", "") or ""
            if not os.path.realpath(fname or "/").startswith(_STD_PREFIXES + (PLUGIN_DIR,)):
                _record("dynamic_code", op=event, detail=_short(fname or code, 120))
        elif event == "import":
            name = args[0] if args else ""
            if isinstance(name, str) and name.split(".")[0] in {
                "socket", "ssl", "http", "urllib", "requests", "httpx", "subprocess",
                "ctypes", "pty", "shutil", "smtplib", "ftplib", "paramiko", "pickle",
            }:
                _record("import", module=name)
    except Exception:
        pass
    finally:
        _IN_HOOK = False


def _caller(depth=2):
    """'plugin' when the nearest real Python frame is plugin code, else 'library'."""
    frame = sys._getframe(depth)
    while frame is not None:
        name = frame.f_code.co_filename
        if not name.startswith("<frozen") and name != __file__:
            return "plugin" if name == PLUGIN_DIR or name.startswith(PLUGIN_DIR + "/") else "library"
        frame = frame.f_back
    return "library"


def _env_caller():
    """How the variable was read ("direct" or "enumerated", i.e. while walking the
    whole environment, as urllib does to find proxy settings) and by whom
    ("plugin" for code under /plugin, otherwise "library")."""
    how = "direct"
    frame = sys._getframe(2)
    while frame is not None and frame.f_globals.get("__name__") in ("os", "_collections_abc", "collections.abc"):
        if frame.f_code.co_name in ("__iter__", "items", "values", "copy", "__eq__", "__contains__"):
            how = "enumerated"
        frame = frame.f_back
    name = frame.f_code.co_filename if frame is not None else ""
    by = "plugin" if name == PLUGIN_DIR or name.startswith(PLUGIN_DIR + "/") else "library"
    return how, by


class _EnvWatch:
    """Logs reads of decoy environment variables."""

    def install(self):
        cls = type(os.environ)
        original = cls.__getitem__

        def __getitem__(env_self, key):
            if _ACTIVE and not _IN_HOOK and key in DECOY_ENV:
                how, by = _env_caller()
                _record("env_read", name=key, how=how, by=by)
            return original(env_self, key)

        cls.__getitem__ = __getitem__



# --------------------------------------------------------------------------
# Stand-ins for modules the sandbox does not have
# --------------------------------------------------------------------------
# The container has no Hermes and no third-party packages. Real plugins import
# Hermes's public modules (tools.registry, agent.*, ...) and their own deps, so
# any module that cannot be found is replaced by an inert stand-in that accepts
# attribute access, calls and subclassing. Every stand-in is recorded: activity
# that goes through a stand-in (e.g. an HTTP call via a stubbed `requests`) is
# NOT observed, and the report says so.
STUBBED_MODULES = []


HERMES_MODULES = {"tools", "agent", "gateway", "hermes_cli", "hermes_state", "run_agent",
                  "model_tools", "toolsets", "cli", "hermes_constants", "plugins", "acp_adapter"}


def _note_override(target, name):
    if _ACTIVE and _caller(3) == "plugin":
        _record("hermes_override", target=f"{target}.{name}")


class _StubMeta(type):
    def __setattr__(cls, name, value):
        if cls.__dict__.get("_detonator_stub"):
            _note_override(cls.__dict__.get("_detonator_path", cls.__name__), name)
        super().__setattr__(name, value)

    def __getattr__(cls, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return _new_stub(name)

    def __iter__(cls):
        return iter(())

    def __bool__(cls):
        return False


class _Stub(metaclass=_StubMeta):
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return _new_stub(name)

    def __call__(self, *args, **kwargs):
        # Behave like a pass-through decorator when given a single callable.
        if len(args) == 1 and not kwargs and callable(args[0]):
            return args[0]
        return _Stub()

    def __iter__(self):
        return iter(())

    def __bool__(self):
        return False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _new_stub(name, path=None):
    return _StubMeta(str(name), (_Stub,), {"_detonator_stub": True, "_detonator_path": path or str(name)})


class _StubModule(type(sys)):
    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        value = _new_stub(name, f"{self.__name__}.{name}")
        object.__setattr__(self, name, value)
        return value

    def __setattr__(self, name, value):
        if (not name.startswith("__") and self.__name__.split(".")[0] in HERMES_MODULES
                and not isinstance(value, type(sys))):  # the import system binding a submodule
            _note_override(self.__name__, name)
        object.__setattr__(self, name, value)


class _StubLoader:
    def create_module(self, spec):
        mod = _StubModule(spec.name)
        mod.__path__ = []  # lets submodules be stubbed too
        return mod

    def exec_module(self, module):
        if module.__name__ not in STUBBED_MODULES:
            STUBBED_MODULES.append(module.__name__)


def _imported_by_plugin() -> bool:
    frame = sys._getframe(1)
    while frame is not None:
        name = frame.f_code.co_filename
        if not name.startswith("<frozen") and name != __file__:
            return name == PLUGIN_DIR or name.startswith(PLUGIN_DIR + "/")
        frame = frame.f_back
    return False


class _StubFinder:
    """Last-resort finder: only used when no real module exists."""

    def find_spec(self, fullname, path=None, target=None):
        if not _ACTIVE:
            return None
        # Never fake a standard-library module: the stdlib probes for platform
        # modules (subprocess tries msvcrt/_winapi), and a stand-in there would
        # change how Python itself behaves and could hide what the plugin does.
        if fullname.split(".")[0] in sys.stdlib_module_names:
            return None
        # Only stand in for imports the plugin's own code asks for (or children
        # of a module we already faked), not optional imports inside libraries.
        parent = fullname.rpartition(".")[0]
        if not (parent and isinstance(sys.modules.get(parent), _StubModule)) and not _imported_by_plugin():
            return None
        import importlib.machinery

        return importlib.machinery.ModuleSpec(fullname, _StubLoader(), is_package=True)

# --------------------------------------------------------------------------
# Monkeypatch watch: functions malware swaps out to spy on or redirect traffic
# --------------------------------------------------------------------------
PATCH_TARGETS = {
    "builtins": ["open", "exec", "eval", "compile", "__import__", "print", "input"],
    "os": ["system", "popen", "open", "getenv", "putenv", "listdir", "remove"],
    "subprocess": ["Popen", "run", "call", "check_output"],
    "socket": ["socket", "create_connection", "getaddrinfo"],
    "ssl": ["create_default_context", "SSLContext"],
    "json": ["dumps", "loads"],
    "urllib.request": ["urlopen", "Request", "OpenerDirector"],
    "http.client": ["HTTPConnection", "HTTPSConnection"],
    "sys": ["audit", "addaudithook", "excepthook", "displayhook", "settrace", "setprofile"],
    "importlib": ["import_module"],
    "logging": ["Logger", "getLogger"],
}


def snapshot_patch_targets():
    import importlib as _il
    snap = {}
    for modname, attrs in PATCH_TARGETS.items():
        try:
            mod = _il.import_module(modname)
        except Exception:
            continue
        for attr in attrs:
            if hasattr(mod, attr):
                snap[f"{modname}.{attr}"] = (mod, attr, id(getattr(mod, attr)))
    return snap


def changed_patch_targets(snap):
    out = []
    for key, (mod, attr, ident) in snap.items():
        try:
            if id(getattr(mod, attr)) != ident:
                out.append(key)
        except Exception:
            out.append(key)
    return sorted(out)


def install_thread_watch():
    import threading
    original = threading.Thread.start

    def start(self, *args, **kwargs):
        if _ACTIVE and _caller() == "plugin":
            target = getattr(self, "_target", None)
            _record("thread_start", name=self.name, target=getattr(target, "__qualname__", _short(target, 80)))
        return original(self, *args, **kwargs)

    threading.Thread.start = start


# --------------------------------------------------------------------------
# Clock jump: after the normal pass, move the plugin's clock forward and fire
# its hooks and tools again, so code that waits for a date, or for time to pass
# after it was installed, shows itself. time.sleep follows the moved clock, so a
# background loop that sleeps for hours wakes up when the clock jumps.
# --------------------------------------------------------------------------
CLOCK_JUMPS = (30, 400, 1900)   # days: a month, a year and a bit, about five years
SLEEP_CAP_S = 0.05
_CLOCK_OFFSET = 0.0
_real_time = time.time
_real_time_ns = time.time_ns
_real_sleep = time.sleep


def install_clock():
    import datetime as _dt

    real_localtime, real_gmtime, real_ctime, real_strftime = time.localtime, time.gmtime, time.ctime, time.strftime

    def now():
        return _real_time() + _CLOCK_OFFSET

    time.time = now
    time.time_ns = lambda: _real_time_ns() + int(_CLOCK_OFFSET * 1e9)
    time.localtime = lambda secs=None: real_localtime(now() if secs is None else secs)
    time.gmtime = lambda secs=None: real_gmtime(now() if secs is None else secs)
    time.ctime = lambda secs=None: real_ctime(now() if secs is None else secs)
    time.strftime = lambda fmt, t=None: real_strftime(fmt, time.localtime() if t is None else t)

    def sleep(seconds):
        # Sleep on the plugin's clock: a jump forward wakes sleepers whose time has come,
        # so a background loop waiting hours or days runs on during the jumped passes.
        if seconds <= SLEEP_CAP_S:
            return _real_sleep(max(seconds, 0))
        wake = now() + seconds
        while now() < wake:
            _real_sleep(SLEEP_CAP_S)

    time.sleep = sleep

    class _Date(_dt.date):
        @classmethod
        def today(cls):
            return cls.fromtimestamp(now())

    class _DateTime(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(now(), tz)

        @classmethod
        def today(cls):
            return cls.fromtimestamp(now())

        @classmethod
        def utcnow(cls):
            return cls.fromtimestamp(now(), _dt.timezone.utc).replace(tzinfo=None)

    _Date.__name__ = _Date.__qualname__ = "date"
    _DateTime.__name__ = _DateTime.__qualname__ = "datetime"
    _dt.date = _Date
    _dt.datetime = _DateTime


def set_clock(days):
    global _CLOCK_OFFSET, _CLOCK_DAYS
    _CLOCK_DAYS = days
    _CLOCK_OFFSET = days * 86400.0


# --------------------------------------------------------------------------
# Mock Hermes context
# --------------------------------------------------------------------------
class MockCtx:
    def __init__(self, plugin_name):
        self.plugin_name = plugin_name
        self.tools = {}
        self.hooks = {}
        self.cli_commands = []
        self.commands = []
        self.other_calls = []
        self._config = {}
        self.state = {}

    def register_tool(self, name=None, toolset=None, schema=None, handler=None, **kwargs):
        self.tools[name] = {"toolset": toolset, "schema": schema, "handler": handler}

    def register_hook(self, hook_name, callback, *args, **kwargs):
        self.hooks.setdefault(hook_name, []).append(callback)

    def register_cli_command(self, *args, **kwargs):
        self.cli_commands.append(_short((args, sorted(kwargs))))

    def register_command(self, *args, **kwargs):
        self.commands.append(_short((args, sorted(kwargs))))

    def get_config(self, key=None, default=None):
        return self._config.get(key, default) if key else dict(self._config)

    def set_config(self, key, value):
        self._config[key] = value

    def has_capability(self, *args, **kwargs):
        return False

    def has_plugin(self, *args, **kwargs):
        return False

    def dispatch_tool(self, name, args=None, **kwargs):
        _record("dispatch_tool", tool=name, args=_short(args))
        return json.dumps({"error": "dispatch disabled in sandbox"})

    def __getattr__(self, name):
        def _noop(*args, **kwargs):
            self.other_calls.append(name)
            return None

        return _noop


# --------------------------------------------------------------------------
# Synthetic inputs
# --------------------------------------------------------------------------
def _history():
    return [
        {"role": "system", "content": f"You are Hermes. [{CANARY}-SYSTEM]"},
        {"role": "user", "content": f"Summarize my notes. [{CANARY}-USER]"},
    ]


def hook_kwargs(hook):
    base = {
        "session_id": "det-session",
        "task_id": "det-task",
        "turn_id": "det-turn",
        "conversation_id": "det-conv",
        "tool_call_id": "det-call",
        "api_request_id": "det-req",
        "platform": "cli",
        "model": "test/model",
        "telemetry_schema_version": 1,
    }
    tool_args = {"command": "ls -la", "path": "notes.txt"}
    specific = {
        "pre_tool_call": {"tool_name": "terminal", "args": tool_args},
        "post_tool_call": {"tool_name": "terminal", "args": tool_args,
                           "result": f"file1\nfile2 [{CANARY}-TOOLRESULT]",
                           "duration_ms": 5, "status": "ok"},
        "transform_tool_result": {"tool_name": "web_extract", "args": {"url": "https://example.com"},
                                  "result": f"Example page text [{CANARY}-TOOLRESULT]",
                                  "duration_ms": 5, "status": "ok"},
        "transform_terminal_output": {"command": "ls -la", "output": f"file1\n[{CANARY}-TERMINAL]",
                                      "returncode": 0, "env_type": "local"},
        "pre_llm_call": {"user_message": f"Summarize my notes. [{CANARY}-USER]",
                         "conversation_history": _history(), "is_first_turn": True},
        "post_llm_call": {"user_message": f"Summarize my notes. [{CANARY}-USER]",
                          "assistant_response": f"Here is a summary. [{CANARY}-ASSISTANT]",
                          "conversation_history": _history()},
        "transform_llm_output": {"response_text": f"Here is a summary. [{CANARY}-ASSISTANT]"},
        "pre_approval_request": {"command": "rm -rf build", "description": "delete build dir",
                                 "pattern_key": "rm", "pattern_keys": ["rm"], "surface": "cli"},
        "post_approval_response": {"command": "rm -rf build", "description": "delete build dir",
                                   "pattern_key": "rm", "pattern_keys": ["rm"], "surface": "cli",
                                   "choice": "deny"},
        "pre_command": {"surface": "cli", "command": "help", "args_raw": ""},
        "on_session_start": {},
        "on_session_end": {"completed": True, "failed": False, "interrupted": False},
    }
    out = dict(base)
    out.update(specific.get(hook, {}))
    return out


# Hooks whose return value Hermes honours (see Hermes hook docs).
MODIFYING_HOOKS = {
    "pre_tool_call", "transform_tool_result", "transform_terminal_output",
    "pre_llm_call", "transform_llm_output", "pre_verify", "pre_gateway_dispatch",
    "post_gateway_admission", "pre_transcription", "transform_api_error_classification",
    "on_session_finalize",
}


def sample_args(schema):
    params = (schema or {}).get("parameters") or {}
    props = params.get("properties") or {}
    args = {}
    for key, spec in props.items():
        spec = spec or {}
        if "enum" in spec and spec["enum"]:
            args[key] = spec["enum"][0]
            continue
        t = spec.get("type", "string")
        if isinstance(t, list):
            t = t[0]
        args[key] = {
            "string": f"detonator test input [{CANARY}-ARG]",
            "integer": 1,
            "number": 1.0,
            "boolean": False,
            "array": [],
            "object": {},
        }.get(t, "detonator")
    return args


class _Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise _Timeout()


def call_plugin(fn, *args, **kwargs):
    """Call plugin code with the monitor on and a timeout. Never raises."""
    global _ACTIVE
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(CALL_TIMEOUT_S)
    _ACTIVE = True
    try:
        return {"ok": True, "value": fn(*args, **kwargs)}
    except _Timeout:
        return {"ok": False, "error": "timeout"}
    except BaseException as exc:  # includes SystemExit from hostile plugins
        return {"ok": False, "error": f"{type(exc).__name__}: {_short(str(exc), 200)}"}
    finally:
        _ACTIVE = False
        signal.alarm(0)


def _jsonable(value):
    try:
        json.dumps(value)
        return value
    except Exception:
        return _short(value)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def _digest(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return None


def plant_decoys():
    for path, content in {**DECOY_FILES, **BROWSER_FILES, **WALLET_FILES, **MEMORY_FILES,
                          **HISTORY_FILES}.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    os.environ.update(DECOY_ENV)
    os.environ["HERMES_HOME"] = HERMES_HOME
    return {p: _digest(p) for p in ALL_DECOY_PATHS}


def trim_events(events, limit=None):
    """Cut an over-long log down to `limit` events by thinning the noisiest kinds first.

    Events are grouped by kind (and, for file events, by whether they touch a decoy).
    Small groups are kept whole; the biggest groups share what is left, keeping their
    first and last events. So one decoy read hidden among thousands of harmless
    listings survives, in every clock pass, instead of falling out of the middle."""
    limit = limit or MAX_EVENTS
    if len(events) <= limit:
        return events
    groups = {}
    for i, e in enumerate(events):
        groups.setdefault((e.get("kind"), e.get("path") in ALL_DECOY_PATHS), []).append(i)
    keep, left = set(), limit
    ordered = sorted(groups.values(), key=len)
    for n, idx in enumerate(ordered):
        quota = min(len(idx), left // (len(ordered) - n))
        head = (quota + 1) // 2
        keep.update(idx[:head] + (idx[len(idx) - (quota - head):] if quota - head else []))
        left -= quota
    return [e for i, e in enumerate(events) if i in keep]


def unsafe_name(name):
    """True for a name that would not stay one folder inside plugin-data."""
    return any(c in name for c in ("/", "\\", "\0")) or name.strip() in ("", ".", "..") or len(name) > 200


def load_manifest():
    # The host parses plugin.yaml (the sandbox has no YAML library) and mounts
    # the result read-only.
    with open(MANIFEST_PATH) as f:
        return json.load(f) or {}


def main():
    global _PHASE
    result = {"harness_version": 1, "errors": []}
    try:
        manifest = load_manifest()
    except Exception as exc:
        manifest = {}
        result["errors"].append(f"manifest: {exc}")
    result["manifest"] = _jsonable(manifest)
    name = str(manifest.get("name") or "plugin_under_test")
    if unsafe_name(name):
        # A name made of dot-dot steps would turn the plugin's own data folder (where writes
        # are allowed) into the whole home folder. Use a fixed safe folder instead;
        # the rules report the bad name.
        result["unsafe_name"] = name[:200]
        name = "plugin_under_test"
    pkg = re.sub(r"\W", "_", name) or "plugin_under_test"

    data_dir = os.path.join(HERMES_HOME, "plugin-data", name)
    os.makedirs(data_dir, exist_ok=True)
    result["allowed_write_dirs"] = [data_dir]
    result["plugin_dir"] = PLUGIN_DIR
    result["home"] = HOME
    result["decoy_paths"] = sorted(ALL_DECOY_PATHS)
    result["decoy_categories"] = DECOY_CATEGORIES
    result["decoy_dirs"] = DECOY_DIRS
    result["memory_paths"] = sorted(set(MEMORY_FILES) | set(HISTORY_FILES))
    result["decoy_env"] = sorted(DECOY_ENV)
    result["canary"] = CANARY
    result["secret_markers"] = SECRET_MARKERS

    before = plant_decoys()
    install_clock()
    _EnvWatch().install()
    install_thread_watch()
    sys.addaudithook(_audit)
    sys.meta_path.append(_StubFinder())
    patch_snapshot = snapshot_patch_targets()
    os.chdir(data_dir)

    ctx = MockCtx(name)

    # 1. import
    _PHASE = "import"
    init = os.path.join(PLUGIN_DIR, "__init__.py")
    spec = importlib.util.spec_from_file_location(pkg, init, submodule_search_locations=[PLUGIN_DIR])
    module = importlib.util.module_from_spec(spec)
    sys.modules[pkg] = module
    r = call_plugin(spec.loader.exec_module, module)
    result["import"] = {"ok": r["ok"], "error": r.get("error")}

    # 2. register
    _PHASE = "register"
    register = getattr(module, "register", None)
    if r["ok"] and callable(register):
        r = call_plugin(register, ctx)
        result["register"] = {"ok": r["ok"], "error": r.get("error")}
    else:
        result["register"] = {"ok": False, "error": "no register(ctx)"}

    result["tool_schemas"] = {t: _jsonable(v.get("schema")) for t, v in ctx.tools.items() if t}
    result["registered"] = {
        "tools": sorted(t for t in ctx.tools if t),
        "hooks": sorted(ctx.hooks),
        "cli_commands": ctx.cli_commands,
        "commands": ctx.commands,
        "other_ctx_calls": sorted(set(ctx.other_calls)),
    }

    # 3. synthetic hooks
    hook_runs = []
    for hook, callbacks in sorted(ctx.hooks.items()):
        for idx, cb in enumerate(callbacks):
            for attempt in range(HOOK_REPEATS):
                _PHASE = f"hook:{hook}"
                kwargs = hook_kwargs(hook)
                pristine = copy.deepcopy(kwargs)
                r = call_plugin(cb, **kwargs)
                mutated = sorted(k for k in pristine if kwargs.get(k) != pristine[k])
                hook_runs.append({
                    "hook": hook, "callback": idx, "attempt": attempt,
                    "ok": r["ok"], "error": r.get("error"),
                    "returned": _jsonable(r.get("value")) if r["ok"] else None,
                    "honoured_return": hook in MODIFYING_HOOKS,
                    "mutated_args": mutated,
                    "inputs": {k: _jsonable(pristine[k]) for k in mutated},
                    "after": {k: _jsonable(kwargs.get(k)) for k in mutated},
                })
    result["hook_runs"] = hook_runs

    # 4. synthetic tool calls
    tool_runs = []
    for tool, info in sorted((k, v) for k, v in ctx.tools.items() if k):
        handler = info.get("handler")
        if not callable(handler):
            continue
        _PHASE = f"tool:{tool}"
        args = sample_args(info.get("schema"))
        r = call_plugin(handler, args, task_id="det-task")
        tool_runs.append({
            "tool": tool, "args": args, "ok": r["ok"], "error": r.get("error"),
            "returned": _short(r.get("value"), 2000) if r["ok"] else None,
        })
    result["tool_runs"] = tool_runs

    # 5. let background threads act, still monitored
    global _ACTIVE
    _PHASE = "settle"
    _ACTIVE = True
    try:
        _real_sleep(SETTLE_S)
    except BaseException:
        pass
    _ACTIVE = False

    # 6. clock jumps: same hooks and tools again with the plugin's clock moved forward.
    # The first pass (0 days) repeats the run at the real time, so a plugin that only
    # acts on its second call (it saved something the first time) is not mistaken
    # for one that waited for a date.
    mid = None
    clock_runs = []
    for days in (0,) + CLOCK_JUMPS:
        if days and mid is None:
            mid = {p: _digest(p) for p in ALL_DECOY_PATHS}
        set_clock(days)
        for hook, callbacks in sorted(ctx.hooks.items()):
            for idx, cb in enumerate(callbacks):
                _PHASE = f"hook:{hook}"
                kwargs = hook_kwargs(hook)
                pristine = copy.deepcopy(kwargs)
                r = call_plugin(cb, **kwargs)
                mutated = sorted(k for k in pristine if kwargs.get(k) != pristine[k])
                hook_runs.append({
                    "hook": hook, "callback": idx, "attempt": 0, "clock_days": days,
                    "ok": r["ok"], "error": r.get("error"),
                    "returned": _jsonable(r.get("value")) if r["ok"] else None,
                    "honoured_return": hook in MODIFYING_HOOKS,
                    "mutated_args": mutated,
                    "inputs": {k: _jsonable(pristine[k]) for k in mutated},
                    "after": {k: _jsonable(kwargs.get(k)) for k in mutated},
                })
        for tool, info in sorted((k, v) for k, v in ctx.tools.items() if k):
            handler = info.get("handler")
            if callable(handler):
                _PHASE = f"tool:{tool}"
                r = call_plugin(handler, sample_args(info.get("schema")), task_id="det-task")
                clock_runs.append({"tool": tool, "clock_days": days, "ok": r["ok"]})
        _PHASE = "settle"
        _ACTIVE = True
        try:
            _real_sleep(CLOCK_SETTLE_S)
        except BaseException:
            pass
        _ACTIVE = False
    result["clock_jumps"] = list(CLOCK_JUMPS)
    result["clock_runs"] = clock_runs
    _PHASE = "done"

    after = {p: _digest(p) for p in ALL_DECOY_PATHS}
    result["decoy_changes_before_clock"] = sorted(p for p in ALL_DECOY_PATHS if before[p] != mid[p])
    result["patched_functions"] = changed_patch_targets(patch_snapshot)
    result["stubbed_modules"] = sorted(STUBBED_MODULES)
    result["decoy_changes"] = sorted(p for p in ALL_DECOY_PATHS if before[p] != after[p])
    # Keep the first and the last events. A plugin that floods the log to bury what
    # it does at the end is still seen, and the rules flag the flood itself.
    result["event_count"] = len(EVENTS)
    result["events_truncated"] = len(EVENTS) > MAX_EVENTS
    result["events"] = trim_events(EVENTS)

    with open(OUT_PATH, "w") as f:
        json.dump(result, f, indent=1, default=_short)
    # Exit hard so plugin threads cannot run (or rewrite the result) afterwards.
    os._exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        _ACTIVE = False
        with open(OUT_PATH, "w") as f:
            json.dump({"harness_version": 1, "fatal": traceback.format_exc()}, f)
        sys.exit(2)
