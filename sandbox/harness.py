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

CANARY = "DETONATOR-CANARY"

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

MEMORY_FILES = {
    os.path.join(HERMES_HOME, "memories", "MEMORY.md"): (
        f"# Memory\n- The user prefers concise answers. ({CANARY}-mem-0009)\n"
    ),
    os.path.join(HERMES_HOME, "memories", "USER.md"): (
        f"# User\n- Name: Test User ({CANARY}-user-0010)\n"
    ),
}

# Substrings that only appear in decoy secrets / memory, never in synthetic args.
SECRET_MARKERS = [f"{CANARY}-{tag}" for tag in (
    "0001", "0002", "0003", "0005", "auth-0006", "ssh-0007", "0008", "mem-0009", "user-0010",
)] + [f"ghp_{CANARY}0004"]

DECOY_DIRS = sorted(
    {os.path.dirname(p) for p in list(DECOY_FILES) + list(MEMORY_FILES)}
)
ALL_DECOY_PATHS = set(DECOY_FILES) | set(MEMORY_FILES)

# --------------------------------------------------------------------------
# Observation log
# --------------------------------------------------------------------------
EVENTS = []
_ACTIVE = False
_PHASE = "setup"
_IN_HOOK = False

_STD_PREFIXES = tuple(
    {os.path.realpath(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix)}
) + ("/opt/detonator",)

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def _record(kind, **data):
    EVENTS.append({"t": round(time.monotonic(), 4), "phase": _PHASE, "kind": kind, **data})


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
            _record("file_write" if write else "file_read", path=real)
        elif event in ("os.remove", "os.rename", "os.unlink", "shutil.rmtree", "os.rmdir", "os.truncate", "os.chmod"):
            _record("file_modify", op=event, path=_short(args[0] if args else None))
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
        elif event == "compile" and _PHASE != "import":
            source, filename = (list(args) + [None, None])[:2]
            fname = os.fsdecode(filename) if isinstance(filename, (str, bytes)) else ""
            if not os.path.realpath(fname or "/").startswith(_STD_PREFIXES + (PLUGIN_DIR,)) \
                    or fname in ("<string>", "<unknown>"):
                _record("dynamic_code", op=event, detail=_short(source, 120))
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


class _EnvWatch:
    """Logs reads of decoy environment variables."""

    def install(self):
        cls = type(os.environ)
        original = cls.__getitem__

        def __getitem__(env_self, key):
            if _ACTIVE and not _IN_HOOK and key in DECOY_ENV:
                _record("env_read", name=key)
            return original(env_self, key)

        cls.__getitem__ = __getitem__


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
    for path, content in {**DECOY_FILES, **MEMORY_FILES}.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    os.environ.update(DECOY_ENV)
    os.environ["HERMES_HOME"] = HERMES_HOME
    return {p: _digest(p) for p in ALL_DECOY_PATHS}


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
    pkg = re.sub(r"\W", "_", name) or "plugin_under_test"

    data_dir = os.path.join(HERMES_HOME, "plugin-data", name)
    os.makedirs(data_dir, exist_ok=True)
    result["allowed_write_dirs"] = [data_dir]
    result["plugin_dir"] = PLUGIN_DIR
    result["decoy_paths"] = sorted(ALL_DECOY_PATHS)
    result["decoy_dirs"] = DECOY_DIRS
    result["memory_paths"] = sorted(MEMORY_FILES)
    result["decoy_env"] = sorted(DECOY_ENV)
    result["canary"] = CANARY
    result["secret_markers"] = SECRET_MARKERS

    before = plant_decoys()
    _EnvWatch().install()
    sys.addaudithook(_audit)
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
        time.sleep(SETTLE_S)
    except BaseException:
        pass
    _ACTIVE = False
    _PHASE = "done"

    after = {p: _digest(p) for p in ALL_DECOY_PATHS}
    result["decoy_changes"] = sorted(p for p in ALL_DECOY_PATHS if before[p] != after[p])
    result["events"] = EVENTS[:5000]
    result["events_truncated"] = len(EVENTS) > 5000

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
