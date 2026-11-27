"""Detonator's skill mode: does what a Hermes skill tells the agent to do, inside the disposable container.

Started by harness.py when the host asks for a skill run (/in/run.json has "mode": "skill"), so
the outside tracer follows it exactly as for plugins. The host has already read the skill and
written a plan to /in/skill.json: a list of steps, each one either a script the skill ships
(run with no arguments, with --help, and with the arguments its examples show) or a shell
block from SKILL.md (run on its own, as the agent would through its terminal tool).

This file:
  1. plants the same decoy Hermes home as a plugin run (fake keys, credentials, wallets, memory),
  2. installs the skill where Hermes keeps skills (~/.hermes/skills/<name>, a link to the
     read-only copy) and sets HERMES_SKILL_DIR as Hermes does,
  3. gives the commands a work folder with harmless sample files to work on,
  4. runs every step with no input, its own time limit and a fresh set of decoys,
  5. runs the scripts once more with the clock moved forward (Python and Node),
  6. writes what each step printed and how it ended to /out/result.json.

It makes no decisions. The host-side rules (engine/skill.py) judge what the outside monitor saw.
"""

import json
import os
import re
import signal
import subprocess
import threading
import time

SKILL_PATH = "/in/skill.json"
RUN_BUDGET_S = 170          # the host stops a skill container after 240 s
STEP_TIMEOUT_S = 20
OUTPUT_KEEP = 4000
LATE_MIN_LEFT_S = 25
CLOCK_DAYS = 400

# Small stand-ins for macOS commands, so instructions written for a Mac still run here and
# what they lead to (a download, a decoded command) can be watched. They never do anything real.
SHIMS = {
    "base64": '#!/bin/sh\nargs=""\nfor a in "$@"; do case "$a" in -D) args="$args -d";; *) args="$args $a";; esac; done\n'
              'exec /usr/bin/base64 $args\n',
    "open": "#!/bin/sh\nexit 0\n",
    "xattr": "#!/bin/sh\nexit 0\n",
    "osascript": "#!/bin/sh\nexit 0\n",
    "pbcopy": "#!/bin/sh\ncat >/dev/null\nexit 0\n",
    "pbpaste": "#!/bin/sh\nexit 0\n",
    "say": "#!/bin/sh\nexit 0\n",
    "sw_vers": "#!/bin/sh\necho 'ProductName:\tmacOS'\necho 'ProductVersion:\t15.5'\n",
    "launchctl": "#!/bin/sh\nexit 0\n",
    "brew": "#!/bin/sh\necho \"brew: $*\" >&2\nexit 1\n",
}

SAMPLE_FILES = {
    "notes.txt": "Meeting notes\n- ship the report on Friday\n- check the budget\n",
    "data.csv": "name,amount,date\nalpha,10,2026-01-05\nbeta,20,2026-02-11\n",
    "data.json": '{"items": [{"id": 1, "name": "alpha"}, {"id": 2, "name": "beta"}]}\n',
    "README.md": "# Sample project\n\nA small project for testing.\n",
    "index.html": "<!doctype html><title>Sample</title><p>Hello</p>\n",
    "main.py": "def add(a, b):\n    return a + b\n\nprint(add(1, 2))\n",
    "app.js": "console.log('hello');\n",
}
# A tiny valid PDF and PNG, for skills that convert or read documents and images.
SAMPLE_BINARY = {
    "report.pdf": (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>"
                   b"endobj 3 0 obj<</Type/Page/MediaBox[0 0 200 200]/Parent 2 0 R>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"),
    "image.png": bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010806000000"
                               "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082"),
}


def _tail(b, n=OUTPUT_KEEP):
    t = b.decode("utf-8", "replace") if isinstance(b, bytes) else str(b or "")
    return t[-n:]


def _write_shims(folder):
    os.makedirs(folder, exist_ok=True)
    for name, body in SHIMS.items():
        p = os.path.join(folder, name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)


def _workspace(work):
    os.makedirs(work, exist_ok=True)
    for name, text in SAMPLE_FILES.items():
        with open(os.path.join(work, name), "w") as f:
            f.write(text)
    for name, data in SAMPLE_BINARY.items():
        with open(os.path.join(work, name), "wb") as f:
            f.write(data)


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def _ancestors():
    pids, pid = set(), os.getpid()
    while pid > 1 and pid not in pids:
        pids.add(pid)
        try:
            with open(f"/proc/{pid}/stat") as f:
                pid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return pids


def kill_strays():
    """Kill what a step left running after its own process group was killed (a program that moved to
    its own session, a daemon), so it cannot act during later steps under their names. Only this
    container's processes of this user count (the tracer shares the process list, never the cgroup)."""
    keep = _ancestors()
    try:
        with open("/proc/self/cgroup") as f:
            mine = f.read()
    except OSError:
        return []
    uid = os.getuid()
    found = []
    for d in os.listdir("/proc"):
        if not d.isdigit() or int(d) in keep:
            continue
        pid = int(d)
        try:
            if os.stat(f"/proc/{pid}").st_uid != uid:
                continue
            with open(f"/proc/{pid}/cgroup") as f:
                if f.read() != mine:
                    continue
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()[:200]
        except OSError:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            continue
        found.append(cmd or f"pid {pid}")
    return found


def _drain(stream, keep, box):
    """Read a pipe to the end, keeping only the last `keep` bytes (a flood must not fill memory)."""
    total, tail = 0, b""
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
        tail = (tail + chunk)[-keep:]
    box.extend([tail, total])


def run_step(h, step, env, cwd, phase, timeout):
    h._PHASE = phase
    h.phase_marker("skill-" + phase)
    argv = step["argv"] if step.get("argv") else ["/bin/bash", "--noprofile", "--norc", "-c", step["code"]]
    started = time.monotonic()
    rec = {"id": step.get("id"), "phase": phase, "kind": step.get("kind"), "label": step.get("label")}
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
    except OSError as exc:
        rec.update(exit=None, error=f"{type(exc).__name__}: {exc}"[:300], seconds=0.0)
        return rec
    rec["pid"] = proc.pid
    boxes = ([], [])
    readers = [threading.Thread(target=_drain, args=(stream, OUTPUT_KEEP, box), daemon=True)
               for stream, box in zip((proc.stdout, proc.stderr), boxes)]
    for t in readers:
        t.start()
    try:
        proc.wait(timeout=timeout)
        rec["exit"] = proc.returncode
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        proc.wait()
        rec["exit"] = None
        rec["timed_out"] = True
    _kill_group(proc)     # whatever it left running in the background
    for t in readers:
        t.join(2)
    strays = kill_strays()
    if strays:
        rec["left_running"] = strays[:10]
    for t in readers:
        t.join(2)
    out, err = (box[0] if box else b"" for box in boxes)
    sizes = [box[1] if len(box) > 1 else 0 for box in boxes]
    if max(sizes) > 1_000_000:
        rec["output_bytes"] = sum(sizes)
    rec["seconds"] = round(time.monotonic() - started, 2)
    rec["stdout"] = _tail(out)
    rec["stderr"] = _tail(err)
    text = (rec["stderr"] + rec["stdout"]).lower()
    rec["not_found"] = rec["exit"] == 127 or "command not found" in text or "no such file or directory" in text \
        or "modulenotfounderror" in text or "cannot find module" in text
    return rec


def run(h):
    """Called by harness.py with itself as `h`, after the tracer is attached."""
    with open(SKILL_PATH) as f:
        plan = json.load(f)
    name = str(plan.get("name") or "skill")
    declared = {str(k): h_fake(h.CANARY, i, k) for i, k in enumerate(sorted(plan.get("declared_env") or []))}
    home = h.HOME
    skill_dir = os.path.join(h.HERMES_HOME, "skills", name)
    work = os.path.join(home, "work")
    result = {
        "harness_version": 2, "mode": "skill", "errors": [], "name": name,
        "home": home, "plugin_dir": h.PLUGIN_DIR, "skill_dir": skill_dir, "work_dir": work,
        "allowed_write_dirs": [work, os.path.join(home, ".cache"), os.path.join(home, ".local", "share", name)],
        "decoy_paths": sorted(h.ALL_DECOY_PATHS), "decoy_categories": h.DECOY_CATEGORIES,
        "decoy_dirs": h.DECOY_DIRS, "memory_paths": sorted(set(h.MEMORY_FILES) | set(h.HISTORY_FILES)),
        "canary": h.CANARY, "secret_markers": h.SECRET_MARKERS + sorted(v for v in declared.values() if h.CANARY in v),
        "declared_env": sorted(declared),
    }
    h.plant_decoys()
    os.makedirs(os.path.dirname(skill_dir), exist_ok=True)
    try:
        os.symlink(h.PLUGIN_DIR, skill_dir)
    except OSError as exc:
        result["errors"].append(f"install link: {exc}")
    for other in (os.path.join(home, ".claude", "skills", name), os.path.join(home, ".agents", "skills", name)):
        try:
            os.makedirs(os.path.dirname(other), exist_ok=True)
            os.symlink(h.PLUGIN_DIR, other)
        except OSError:
            pass
    _workspace(work)
    shims = os.path.join(home, ".local", "bin")
    _write_shims(shims)
    session = os.urandom(8).hex()
    env = {"PATH": f"{shims}:/usr/local/bin:/usr/bin:/bin", "HOME": home, "USER": os.environ.get("USER", ""),
           "LOGNAME": os.environ.get("USER", ""), "LANG": "C.UTF-8", "TERM": "xterm-256color", "SHELL": "/bin/bash",
           "HERMES_HOME": h.HERMES_HOME, "HERMES_SKILL_DIR": skill_dir, "HERMES_SESSION_ID": session,
           "PYTHONDONTWRITEBYTECODE": "1", **declared,
           **{k: os.environ[k] for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
                                         "CURL_CA_BUNDLE") if os.environ.get(k)}}
    if h.TRACED:
        result["traced"] = h.wait_for_tracer()
    h.reserve_fd()
    h.phase_marker("plugin-start")
    started = time.monotonic()
    steps = plan.get("steps") or []
    runs, skipped = [], []
    for i, step in enumerate(steps):
        left = RUN_BUDGET_S - (time.monotonic() - started)
        if left < 5:
            skipped.append({"id": step.get("id"), "label": step.get("label"), "why": "run time used up"})
            continue
        h.plant_decoys()     # a step that deletes files must not hide what the next one reads
        runs.append(run_step(h, step, env, work, f"step-{i}", min(float(step.get("timeout") or STEP_TIMEOUT_S), left)))
    result["steps"] = runs
    result["skipped_steps"] = skipped

    # The later pass: the scripts again with their clock moved forward (Python and Node only).
    late_steps = [s for s in steps if s.get("kind") == "script"][:6]
    left = RUN_BUDGET_S - (time.monotonic() - started)
    if late_steps and left >= LATE_MIN_LEFT_S:
        import mcp_harness
        clock_dir = f"/tmp/clock-{os.urandom(6).hex()}"
        late_env = mcp_harness.clock_env(env, clock_dir, CLOCK_DAYS)
        late = []
        for i, step in enumerate(late_steps):
            left = RUN_BUDGET_S - (time.monotonic() - started)
            if left < 5:
                break
            h.plant_decoys()
            late.append(run_step(h, step, late_env, work, f"late-step-{i}", min(10.0, left)))
        result["late"] = {"clock_days": CLOCK_DAYS, "clock_dir": clock_dir, "steps": late}
    elif late_steps:
        result["late"] = {"skipped": "not enough time left in the run"}
    result["own_pids"] = [r["pid"] for r in runs + (result.get("late") or {}).get("steps", []) if r.get("pid")]
    h._PHASE = "done"
    h.release_fd()
    h.phase_marker("plugin-done")
    h.write_result(result, indent=1, default=str)
    os._exit(0)


# A declared variable whose name says it holds an address (SIYUAN_URL, ES_HOST, API_BASE) gets a
# fake address, not a fake key. Same list as engine/mcp.py (ADDRESS_NAME_RE, fake_address).
_ADDRESS_NAME_RE = re.compile(r"(?:^|_)(?:URL|URI|ENDPOINT|BASE|BASEURL|ORIGIN|HOST|HOSTNAME|SERVER|DOMAIN|ADDR|ADDRESS)$",
                              re.IGNORECASE)
_HOST_ONLY_RE = re.compile(r"(?:HOST|HOSTNAME|SERVER|DOMAIN|ADDR|ADDRESS)$", re.IGNORECASE)


def fake_address(name):
    host = (re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")[:40].strip("-") or "service") + ".example.com"
    return host if _HOST_ONLY_RE.search(str(name)) else "https://" + host


def h_fake(canary, i, name=""):
    """The fake value for the skill's i-th declared key (sorted by name); the host computes the same."""
    if name and _ADDRESS_NAME_RE.search(str(name)):
        return fake_address(name)
    return f"sk-det-{canary}-env{i}"
