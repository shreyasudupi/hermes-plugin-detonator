"""The outside monitor: watches the plugin from containers it cannot reach.

Detonator's first monitor lives inside the plugin's own Python process, so a
determined plugin can switch it off or write a fake clean result. The outside
monitor closes that gap with two more containers that never run plugin code:

  * a tracer, whose process namespace the plugin's container joins. It attaches
    strace to the sandbox harness before the plugin is imported and records the
    files opened, programs started and connections made, by every thread and
    every child process.
  * a fake internet, whose network the plugin's container joins. There is no
    real network: every address answers locally, DNS lookups get made-up
    addresses, and whatever the plugin sends is logged.

The plugin runs as an ordinary user with no capabilities, so it cannot stop
either container or reach their logs. The rules compare what these saw with
what the in-process monitor reported (engine/rules.py).

Disclosure (catalog rule 13): this module runs `docker build` (network, once, to
build the monitor image), `docker run`, `docker wait`, `docker stop` and
`docker rm` for the two monitor containers. Neither container has a network.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import time
from pathlib import Path

MONITOR_DIR = Path(__file__).resolve().parent.parent / "sandbox" / "monitor"
IMAGE_REPO = "detonator-monitor"
SINK_READY_TIMEOUT_S = 15
TRACER_WAIT_S = 30
PHASE_PREFIX = "/detonator-phase/"
RESULT_FILE = "/out/result.json"
MAX_SINK_LINES = 21000


def image_tag() -> str:
    h = hashlib.sha256()
    for name in sorted(os.listdir(MONITOR_DIR)):
        p = MONITOR_DIR / name
        if p.is_file() and not name.startswith("."):
            h.update(name.encode())
            h.update(p.read_bytes())
    return f"{IMAGE_REPO}:{h.hexdigest()[:12]}"


def ensure_image(run) -> str:
    """Build the monitor image once. Raises RuntimeError with Docker's message on failure."""
    tag = image_tag()
    if run(["docker", "image", "inspect", tag], timeout=30).returncode == 0:
        return tag
    proc = run(["docker", "build", "-q", "-t", tag, str(MONITOR_DIR)], timeout=900)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "docker build failed").strip()[-600:])
    return tag


# --rm: Docker removes each monitor container as soon as it stops, and both stop on their own
# after a few minutes, so a run that is interrupted leaves nothing behind.
_COMMON = ["--rm", "--label", "detonator=monitor", "--network", "none", "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges"]


def sink_cmd(tag: str, name: str, sink_dir: Path, hostname: str) -> list[str]:
    # The plugin's container shares this network, so its host name is set here.
    return ["docker", "run", "-d", f"--name={name}", "--hostname", hostname, *_COMMON,
            "--cap-add", "NET_ADMIN", "--cap-add", "NET_BIND_SERVICE",
            "--pids-limit", "128", "--memory", "128m", "--cpus", "0.5",
            "-v", f"{sink_dir}:/sink:rw", tag, "python", "-I", "-B", "/opt/detonator-monitor/sink.py"]


def tracer_cmd(tag: str, name: str, trace_dir: Path) -> list[str]:
    return ["docker", "run", "-d", f"--name={name}", *_COMMON, "--cap-add", "SYS_PTRACE",
            "--pids-limit", "16", "--memory", "256m", "--cpus", "1",
            "-v", f"{trace_dir}:/trace:rw", tag, "python", "-I", "-B", "/opt/detonator-monitor/tracer.py"]


class Monitor:
    """Starts the two monitor containers around one detonation and collects what they saw."""

    def __init__(self, run, workdir: Path, name: str, hostname: str):
        self.run = run
        self.sink = f"{name}-net"
        self.tracer = f"{name}-trace"
        self.sink_dir = workdir / "sink"
        self.trace_dir = workdir / "trace"
        self.resolv = workdir / "resolv.conf"
        self.hostname = hostname
        self.started = False

    def start(self) -> list[str]:
        """Start both containers; return the extra `docker run` arguments for the plugin's container."""
        tag = ensure_image(self.run)
        for d in (self.sink_dir, self.trace_dir):
            d.mkdir()
            os.chmod(d, 0o777)  # the containers drop every capability, including overriding file permissions
        self.resolv.write_text("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n", encoding="utf-8")
        os.chmod(self.resolv, 0o644)
        self.started = True
        proc = self.run(sink_cmd(tag, self.sink, self.sink_dir, self.hostname), timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"fake internet did not start: {(proc.stderr or '').strip()[-300:]}")
        deadline = time.monotonic() + SINK_READY_TIMEOUT_S
        while not (self.sink_dir / "ready").is_file():
            if time.monotonic() > deadline:
                raise RuntimeError("fake internet did not get ready in time: " + _tail(self.sink_dir / "log.jsonl"))
            time.sleep(0.05)
        proc = self.run(tracer_cmd(tag, self.tracer, self.trace_dir), timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"tracer did not start: {(proc.stderr or '').strip()[-300:]}")
        return ["--network", f"container:{self.sink}", "--pid", f"container:{self.tracer}",
                "-v", f"{self.resolv}:/etc/resolv.conf:ro"]

    def finish(self) -> dict:
        """Wait for the tracer to write its log, stop the fake internet, and read both logs."""
        if self.started:
            try:
                self.run(["docker", "wait", self.tracer], timeout=TRACER_WAIT_S)
            except Exception:
                pass
        return collect(self.trace_dir, self.sink_dir)

    def cleanup(self) -> None:
        if self.started:
            try:
                self.run(["docker", "rm", "-f", self.tracer, self.sink], timeout=60)
            except Exception:
                pass


def _read_text(path: Path) -> str:
    """Read a monitor log, never through a link: the folder is written by a container, and a
    link there must not make Detonator read some other file on this computer."""
    if path.is_symlink() or not path.is_file():
        raise OSError(f"{path.name} is missing or not a plain file")
    return path.read_text(encoding="utf-8", errors="replace")


def _tail(path: Path, n: int = 300) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-n:]
    except OSError:
        return "(no log)"


def collect(trace_dir: Path, sink_dir: Path) -> dict:
    """Everything the two monitor containers recorded, parsed into plain data."""
    out: dict = {"ran": True}
    try:
        status = json.loads(_read_text(trace_dir / "status.json"))
    except (OSError, ValueError):
        status = {"error": "the tracer wrote no status"}
    out["tracer"] = status
    try:
        text = _read_text(trace_dir / "strace.log")
    except OSError:
        text = ""
    out["trace"] = parse_strace(text, status.get("harness_pid"))
    out["sink"] = parse_sink(sink_dir / "log.jsonl")
    return out


# --------------------------------------------------------------------------
# strace log
# --------------------------------------------------------------------------
_LINE = re.compile(r"^(\d+) +[\d:.]+ (.*)$")
_CALL = re.compile(r"^([a-z0-9_]+)\((.*)$")
_RET = re.compile(r"\) += (-?\d+|\?)(?:<[^>]*>)?(?: (E[A-Z0-9]+))?")
_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
_DIRFD = re.compile(r"^(?:AT_FDCWD|\d+)<([^>]*)>, ")
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
_INET = re.compile(r'sin_port=htons\((\d+)\), sin_addr=inet_addr\("([0-9.]+)"\)')
_INET6 = re.compile(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([0-9a-fA-F:.]+)"')
_FILE_CALLS = {"open", "openat", "openat2", "creat"}
_PROC_CALLS = {"clone", "clone3", "fork", "vfork"}


def _unescape(s: str) -> str:
    try:
        return s.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except Exception:
        return s


def parse_strace(text: str, harness_pid) -> dict:
    """Turn the tracer's log into events. Each event says which process did it and whether
    that process is the harness itself (the plugin's own Python process) or a child."""
    try:
        harness_pid = int(harness_pid)
    except (TypeError, ValueError):
        harness_pid = None
    group = {harness_pid} if harness_pid else set()   # threads of the harness process
    children: dict[int, int] = {}                      # child pid -> parent pid
    tgid: dict[int, int] = {}                          # thread id -> process id
    pending: dict[int, str] = {}                       # unfinished call text per pid
    events: list[dict] = []
    for raw in text.splitlines():
        m = _LINE.match(raw)
        if not m:
            continue
        pid, rest = int(m.group(1)), m.group(2)
        if rest.endswith("<unfinished ...>"):
            pending[pid] = rest[: -len("<unfinished ...>")].rstrip()
            continue
        if rest.startswith("<... "):
            head = pending.pop(pid, None)
            if head is None:
                continue
            rest = head + rest.split("resumed>", 1)[-1]
        cm = _CALL.match(rest)
        if not cm:
            continue
        call, args = cm.group(1), cm.group(2)
        rm = _RET.search(rest)
        ret = rm.group(1) if rm else "?"
        err = rm.group(2) if rm else None
        ok = ret not in ("?",) and not ret.startswith("-") or err == "EINPROGRESS"
        if call in _PROC_CALLS and ok and ret.lstrip("-").isdigit() and int(ret) > 0:
            child = int(ret)
            if call in ("clone", "clone3") and "CLONE_THREAD" in args:
                tgid[child] = tgid.get(pid, pid)
                if pid in group:
                    group.add(child)
            else:
                children[child] = pid
            continue
        ev = {"pid": pid, "proc": tgid.get(pid, pid), "in_harness": pid in group, "call": call, "ok": ok}
        if err:
            ev["error"] = err
        if call in _FILE_CALLS:
            sm = _STR.search(args)
            if not sm:
                continue
            path = _unescape(sm.group(1))
            dm = _DIRFD.match(args)
            if not path.startswith("/"):
                base = dm.group(1) if dm else "/"
                path = posixpath.join(base, path)
            ev["path"] = posixpath.normpath(path)
            ev["write"] = call == "creat" or any(f in args for f in _WRITE_FLAGS)
        elif call in ("execve", "execveat"):
            strs = _STR.findall(args)
            ev["path"] = _unescape(strs[0]) if strs else ""
            ev["argv"] = [_unescape(s) for s in strs[1:8]]
        elif call in ("connect", "sendto", "sendmsg", "bind"):
            im = _INET.search(args) or _INET6.search(args)
            if im:
                ev["port"], ev["ip"] = int(im.group(1)), im.group(2)
            elif "AF_UNIX" in args:
                um = re.search(r'sun_path="([^"]*)"', args)
                ev["unix"] = um.group(1) if um else ""
            elif call == "connect":
                continue
            if call in ("sendto", "sendmsg"):
                sm = _STR.search(args)
                ev["data"] = _unescape(sm.group(1))[:512] if sm else ""
        elif call in ("ptrace", "process_vm_readv", "process_vm_writev", "kill", "tkill", "tgkill"):
            ev["detail"] = args[:160]
        elif call == "memfd_create":
            sm = _STR.search(args)
            ev["detail"] = _unescape(sm.group(1)) if sm else ""
        elif call in ("unlink", "unlinkat", "rename", "renameat", "renameat2"):
            ev["paths"] = [_unescape(s) for s in _STR.findall(args)[:2]]
        events.append(ev)
    started = _first_marker(events, "plugin-start")
    done = _first_marker(events, "plugin-done")
    return {"events": events, "harness_pid": harness_pid, "children": sorted(children),
            "start_index": started, "done_index": done}


def _first_marker(events, name) -> int | None:
    for i, e in enumerate(events):
        if e.get("in_harness") and e.get("path") == PHASE_PREFIX + name:
            return i
    return None


# --------------------------------------------------------------------------
# fake internet log
# --------------------------------------------------------------------------
def parse_sink(path: Path) -> dict:
    entries = []
    try:
        if path.is_symlink():
            raise OSError("link")
        with open(path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= MAX_SINK_LINES:
                    break
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict):
                    entries.append(e)
    except OSError:
        return {"error": "no log from the fake internet", "dns": [], "tcp": []}
    ready = next((e for e in entries if e.get("kind") == "ready"), None)
    names = {e.get("answer"): e.get("name") for e in entries if e.get("kind") == "dns" and e.get("answer")}
    tcp = []
    for e in entries:
        if e.get("kind") != "tcp":
            continue
        host = e.get("http_host") or e.get("tls_server_name") or names.get(e.get("dst")) or e.get("dst")
        tcp.append({**e, "host": str(host)[:255]})
    return {
        "ready": bool(ready),
        "catch_all": bool(ready and ready.get("catch_all")),
        "dns": [{"name": str(e.get("name"))[:255], "qtype": e.get("qtype")} for e in entries if e.get("kind") == "dns"],
        "tcp": tcp,
        "full": any(e.get("kind") == "log_full" for e in entries),
    }
