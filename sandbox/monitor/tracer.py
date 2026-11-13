"""Detonator's outside tracer. Runs in its own container, never in the plugin's.

The plugin's container joins this container's process namespace
(``--pid container:``), so this script can see the sandbox harness start. It
attaches strace to the harness before any plugin code runs (the harness waits
until it is being traced), follows every thread and child process, and records
the system calls that matter: files opened, programs started, network
connections and a few calls used to tamper with other processes.

The plugin runs as an ordinary user with no capabilities, so it cannot stop
this tracer, and the trace is written to /trace, which only this container
mounts. A plugin can switch off or fool Detonator's in-process monitor, but the
kernel still has to do the work, and that is what this sees.
"""

import json
import os
import posixpath  # trace paths are Linux paths, whatever machine runs the tests
import re
import subprocess
import sys
import threading
import time
from collections import deque

TRACE_DIR = "/trace"
LOG_PATH = os.path.join(TRACE_DIR, "strace.log")
STATUS_PATH = os.path.join(TRACE_DIR, "status.json")
HARNESS = b"/opt/detonator/harness.py"
FIND_TIMEOUT_S = 60
# Stops tracing after this long, even if Detonator itself was killed. Because this script
# is the first process of the shared process namespace, its exit also ends the plugin's
# container, so nothing from a run can keep running.
MAX_LIFETIME_S = 300
SYSCALLS = ("open,openat,openat2,creat,execve,execveat,connect,sendto,sendmsg,bind,listen,"
            "clone,clone3,fork,vfork,unlink,unlinkat,rename,renameat,renameat2,memfd_create,"
            "ptrace,process_vm_readv,process_vm_writev,kill,tkill,tgkill")
# How much of the trace is kept. Lines that can matter (programs, connections, the result
# file, and files in the home folder outside the plugin's own data folder) are kept up to
# IMPORTANT_MAX. Everything else is noise: only its first and last lines are kept, so a
# plugin cannot push one key read out of the log by flooding it with harmless calls.
IMPORTANT_MAX = 60000
NOISE_HEAD = 20000
NOISE_TAIL = 5000

# The standard library, the plugin's own files and the harness: reading these is
# what every Python program does, so those reads are left out of the log. Writes
# to them are kept, and so is any path with a "." or ".." step in it, which could
# lead somewhere else.
QUIET_READ = re.compile(
    r'^(?:\d+ +)?[\d:.]+ (?:open|openat|openat2)\((?:AT_FDCWD(?:<[^>]*>)?, )?"(?![^"]*/\.\.?(?:/|"))(?:/usr/|/lib|/etc/ld\.so|/plugin/|'
    r'/opt/detonator/|/dev/(?:null|urandom|tty))[^"]*", (?:O_RDONLY|\{flags=O_RDONLY)'
    r'(?!.*O_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND))')

_OPEN = re.compile(r'^\d+ +[\d:.]+ (?:open|openat|openat2|creat)\((?:(?:AT_FDCWD|\d+)<([^>]*)>, )?"((?:[^"\\]|\\.)*)"')
_IMPORTANT_PATH = re.compile(r"^(?:/home/|/root/|/out/|/detonator-phase/|/proc/[^/]+/(?:task/\d+/)?environ$)")


def important(line):
    """Whether a trace line can matter to the rules (anything that is not a plain file open
    outside the home folder or inside the plugin's own data folder)."""
    m = _OPEN.match(line)
    if not m:
        return True  # programs, connections, process calls, unfinished/resumed lines
    base, path = m.group(1) or "/", m.group(2)
    full = posixpath.normpath(path if path.startswith("/") else posixpath.join(base, path))
    return bool(_IMPORTANT_PATH.match(full)) and "/.hermes/plugin-data/" not in full + "/"


def find_harness():
    deadline = time.monotonic() + FIND_TIMEOUT_S
    while time.monotonic() < deadline:
        for name in os.listdir("/proc"):
            if not name.isdigit() or int(name) == os.getpid():
                continue
            try:
                with open(f"/proc/{name}/cmdline", "rb") as f:
                    cmd = f.read()
            except OSError:
                continue
            if HARNESS in cmd:
                return int(name)
        time.sleep(0.02)
    return None


def main():
    status = {"tracer_version": 1}
    pid = find_harness()
    status["harness_pid"] = pid
    if pid is None:
        status["error"] = "the sandbox harness never started"
        _write_status(status)
        return 3
    cmd = ["strace", "-f", "-q", "-tt", "-yy", "-s", "256", "-e", f"trace={SYSCALLS}",
           "-o", "/dev/stderr", "-p", str(pid)]
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)
    deadline = threading.Timer(MAX_LIFETIME_S, proc.kill)
    deadline.daemon = True
    deadline.start()
    keep, noise_tail = [], deque(maxlen=NOISE_TAIL)
    total = quiet = noise = important_seen = 0
    for raw in proc.stderr:
        line = raw.decode("utf-8", "replace").rstrip("\n")
        total += 1
        if QUIET_READ.match(line):
            quiet += 1
            continue
        if important(line):
            important_seen += 1
            if important_seen <= IMPORTANT_MAX:
                keep.append((total, line))
            else:
                noise_tail.append((total, line))
            continue
        noise += 1
        if noise <= NOISE_HEAD:
            keep.append((total, line))
        else:
            noise_tail.append((total, line))
    rc = proc.wait()
    lines = sorted(keep + list(noise_tail))
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(line for _, line in lines) + "\n")
    status.update({"strace_exit": rc, "lines_seen": total, "lines_quiet": quiet, "lines_kept": len(lines),
                   "important_dropped": max(0, important_seen - IMPORTANT_MAX),
                   "truncated": total - quiet > len(lines)})
    _write_status(status)
    return 0


def _write_status(status):
    with open(STATUS_PATH, "w", encoding="utf-8") as f:
        json.dump(status, f)


if __name__ == "__main__":
    sys.exit(main())
