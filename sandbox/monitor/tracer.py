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
import re
import subprocess
import sys
import time
from collections import deque

TRACE_DIR = "/trace"
LOG_PATH = os.path.join(TRACE_DIR, "strace.log")
STATUS_PATH = os.path.join(TRACE_DIR, "status.json")
HARNESS = b"/opt/detonator/harness.py"
FIND_TIMEOUT_S = 60
SYSCALLS = ("open,openat,openat2,creat,execve,execveat,connect,sendto,sendmsg,bind,listen,"
            "clone,clone3,fork,vfork,unlink,unlinkat,rename,renameat,renameat2,memfd_create,"
            "ptrace,process_vm_readv,process_vm_writev,kill,tkill,tgkill")
HEAD_LINES = 40000
TAIL_LINES = 10000

# The standard library, the plugin's own files and the harness: reading these is
# what every Python program does, so those reads are left out of the log. Writes
# to them are kept, and so is any path with a "." or ".." step in it, which could
# lead somewhere else.
QUIET_READ = re.compile(
    r'^(?:\d+ +)?[\d:.]+ (?:open|openat|openat2)\((?:AT_FDCWD(?:<[^>]*>)?, )?"(?![^"]*/\.\.?(?:/|"))(?:/usr/|/lib|/etc/ld\.so|/plugin/|'
    r'/opt/detonator/|/dev/(?:null|urandom|tty))[^"]*", (?:O_RDONLY|\{flags=O_RDONLY)'
    r'(?!.*O_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND))')


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
    head, tail, total, quiet = [], deque(maxlen=TAIL_LINES), 0, 0
    for raw in proc.stderr:
        line = raw.decode("utf-8", "replace").rstrip("\n")
        total += 1
        if QUIET_READ.match(line):
            quiet += 1
            continue
        if len(head) < HEAD_LINES:
            head.append(line)
        else:
            tail.append(line)
    rc = proc.wait()
    kept = len(head) + len(tail)
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(head + list(tail)) + "\n")
    status.update({"strace_exit": rc, "lines_seen": total, "lines_quiet": quiet, "lines_kept": kept,
                   "truncated": total - quiet > kept})
    _write_status(status)
    return 0


def _write_status(status):
    with open(STATUS_PATH, "w", encoding="utf-8") as f:
        json.dump(status, f)


if __name__ == "__main__":
    sys.exit(main())
