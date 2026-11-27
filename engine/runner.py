"""Host side: fetch a plugin at an exact commit and detonate it in Docker.

Disclosure (catalog rule 13): this module runs `git clone`/`git checkout`
(network, to fetch the plugin under test), `docker build` (network, once, to
build the sandbox image) and `docker run` (no real network; see engine/outside.py
for the two monitor containers). It never reads the
user's real Hermes home, .env or auth.json: the sandbox gets its own fake home.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import outside as outside_monitor
from . import static

SANDBOX_DIR = Path(__file__).resolve().parent.parent / "sandbox"
IMAGE_REPO = "detonator-sandbox"
MCP_IMAGE_REPO = "detonator-mcp-sandbox"   # the same sandbox plus Node.js (sandbox/Dockerfile.mcp)
SKILL_IMAGE_REPO = "detonator-skill-sandbox"   # full Debian + Python + Node (sandbox/Dockerfile.skill)
RUN_TIMEOUT_S = 180
MCP_RUN_TIMEOUT_S = 240   # an MCP run may first spend up to 45 s on install scripts
SKILL_RUN_TIMEOUT_S = 240

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class DetonatorError(Exception):
    pass


@dataclass
class Target:
    path: Path          # directory containing plugin.yaml
    label: str          # what the report calls it
    repo: str | None = None
    sha: str | None = None


# Where Docker Desktop / Homebrew / Colima put the CLI. Apps started from the
# Dock (e.g. the Hermes Desktop app) do not read shell profiles, so `docker`
# is often missing from PATH there even though it is installed.
DOCKER_DIRS = (
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/Applications/Docker.app/Contents/Resources/bin",
    os.path.expanduser("~/.rd/bin"),          # Rancher Desktop
    os.path.expanduser("~/.orbstack/bin"),    # OrbStack
    r"C:\Program Files\Docker\Docker\resources\bin",  # Docker Desktop for Windows
)


# The only variables `git` and `docker` get from the Hermes process. Everything else,
# including every provider API key Hermes has loaded, stays out of their environment.
_PASS_ENV = (
    "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "XDG_RUNTIME_DIR",
    # Which Docker to talk to (contexts, Colima, rootless, remote hosts)
    "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
    "DOCKER_BUILDKIT",
    # Corporate proxies and certificate bundles, needed for git fetch and the one-time image build
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "all_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO",
    # Windows basics, so the CLIs can start there and find their config and plugins
    # (Python's os.environ is case-insensitive on Windows, so ProgramFiles matches PROGRAMFILES)
    "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "USERPROFILE", "HOMEDRIVE",
    "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "PROGRAMW6432", "TEMP", "TMP",
)



RESULT_MAX_BYTES = 200_000_000


def read_plain_file(path: Path, limit: int = 10_000_000, inside: Path | None = None) -> str:
    """Read a file that a container or a download produced: never through a link (it could point
    at any file on this computer), only a plain file, at most `limit` bytes, and, with `inside`,
    only when its real location is under that folder."""
    path = Path(path)
    if inside is not None:
        real, root = os.path.realpath(path), os.path.realpath(inside)
        if os.path.commonpath([real, root]) != root:
            raise OSError(f"{path.name} lies outside {Path(root).name}")
    # Windows has no O_NOFOLLOW: check the entry itself first, then that the file opened is
    # that same entry (so a swap between the check and the open is caught too).
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise OSError(f"{path.name} is a link or not a plain file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino):
            raise OSError(f"{path.name} is not a plain file")
        data = f.read(limit + 1)
    if len(data) > limit:
        raise OSError(f"{path.name} is larger than {limit} bytes")
    return data.decode("utf-8", errors="replace")


def _env() -> dict:
    """A minimal environment for git and docker: allow-listed variables only."""
    env = {k: os.environ[k] for k in _PASS_ENV if k in os.environ}
    extra = [d for d in DOCKER_DIRS if os.path.isdir(d)]
    env["PATH"] = os.pathsep.join([os.environ.get("PATH", "")] + extra)
    env["GIT_TERMINAL_PROMPT"] = "0"  # never hang waiting for a password prompt
    return env


def docker_bin() -> str | None:
    return shutil.which("docker", path=_env()["PATH"])


# git settings kept from your own git config when Detonator fetches code: only how to reach the
# network (proxy) and which certificates to trust. Everything else in your global and system git
# config is left out, so a filter or helper you installed for your own work (Git LFS, for
# example) never runs on a repository Detonator downloads.
_GIT_KEEP_RE = re.compile(r"^http\.(?:.+\.)?(?:proxy|proxyauthmethod|proxysslcainfo|proxysslcert|proxysslkey|"
                          r"sslcainfo|sslcapath|sslbackend|sslverify|sslcert|sslkey|sslcertpasswordprotected|sslcerttype|"
                          r"sslkeytype|sslversion|sslcipherlist|"
                          r"schannel[a-z]*)$|^core\.longpaths$", re.IGNORECASE)
_GIT_BOOL_RE = re.compile(r"(?i)(sslverify|passwordprotected|longpaths|schannelcheckrevoke|schannelusesslcainfo)$")
_git_keep_cache: list[tuple[str, str]] | None = None
_git_env_ok: bool | None = None


def _git_kept_pairs() -> list[tuple[str, str]]:
    """(key, value) for the allow-listed settings in your git config (read once). Credential
    helpers and URL rewrites are left out on purpose: Detonator fetches public repositories only,
    and a helper is a program."""
    global _git_keep_cache
    if _git_keep_cache is None:
        keep: list[tuple[str, str]] = []
        try:
            # Reads config files only (your own, so not through the cleaned config); runs nothing
            # from any repository. System first, then yours, so yours wins; never a repository's
            # own config. --includes follows [include] files, as git itself would.
            for scope in ("--system", "--global"):
                proc = _run(["git", "config", scope, "--includes", "--null", "--get-regexp",
                             r"^(http\.|core\.longpaths)"],
                            timeout=20, cwd=tempfile.gettempdir(), own_git_config=True)
                for item in (proc.stdout or "").split("\0"):
                    key, has_value, value = item.partition("\n")
                    if key and _GIT_KEEP_RE.match(key):
                        if has_value:
                            keep.append((key, value))
                        elif _GIT_BOOL_RE.search(key):
                            keep.append((key, "true"))   # a bare boolean key means true
                        # any other bare key has no value to pass on, and git would refuse it
        except (OSError, subprocess.SubprocessError):
            pass
        _git_keep_cache = keep
    return list(_git_keep_cache)


def _git_kept_settings() -> list[str]:
    """The kept settings as key=value (for messages and tests)."""
    return [f"{k}={v}" for k, v in _git_kept_pairs()]


def _git_takes_env_config() -> bool:
    """git 2.31 and later read settings from GIT_CONFIG_COUNT/KEY/VALUE, which keeps a proxy
    password out of the process list and allows keys holding "="."""
    global _git_env_ok
    if _git_env_ok is None:
        _git_env_ok = False
        try:
            out = _run(["git", "--version"], timeout=20, own_git_config=True).stdout or ""
            m = re.search(r"(\d+)\.(\d+)", out)
            _git_env_ok = bool(m) and (int(m.group(1)), int(m.group(2))) >= (2, 31)
        except (OSError, subprocess.SubprocessError):
            pass
    return _git_env_ok


def _git_with_settings(cmd: list, env: dict) -> tuple[list, dict]:
    pairs = _git_kept_pairs()
    env = _git_env(env)
    if not pairs:
        return cmd, env
    if _git_takes_env_config():
        env["GIT_CONFIG_COUNT"] = str(len(pairs))
        for i, (k, v) in enumerate(pairs):
            env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v
        return cmd, env
    # Older git: on the command line. A key holding "=" (a URL with a query) cannot go there.
    extra = [a for k, v in pairs if "=" not in k for a in ("-c", f"{k}={v}")]
    return ["git", *extra, *cmd[1:]], env


# A home folder that does not exist, for git only: git before 2.32 ignores GIT_CONFIG_GLOBAL and
# would still read ~/.gitconfig and ~/.config/git/config from the real one.
_NO_GIT_HOME = os.path.join(tempfile.gettempdir(), "detonator-no-git-home-" + secrets.token_hex(8))


def _git_env(env: dict) -> dict:
    # Settings passed in through the environment (GIT_CONFIG_COUNT/KEY_n/VALUE_n, or -c from a
    # parent git) are dropped too; only the allow-listed ones are passed back.
    env = {k: v for k, v in env.items()
           if not (k == "GIT_CONFIG_PARAMETERS" or k.startswith(("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_",
                                                                  "GIT_CONFIG_VALUE_")))}
    return {**env, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": _NO_GIT_HOME, "XDG_CONFIG_HOME": _NO_GIT_HOME}


def _run(cmd, timeout=600, own_git_config=False, capture=True, **kwargs):
    env = _env()
    if cmd and cmd[0] == "docker":
        cmd = [docker_bin() or "docker", *cmd[1:]]
    elif cmd and cmd[0] == "git" and not own_git_config:
        cmd, env = _git_with_settings(list(cmd), env)
    if capture:
        kwargs = {"capture_output": True, "text": True, **kwargs}
    return subprocess.run(cmd, timeout=timeout, env=env, **kwargs)


# What tested code can put on your disk or in your memory during a run: files in the output folder
# (always), files in its own throwaway package copy (MCP install runs) and what it prints. All of it
# is deleted afterwards, but a run lasts minutes, so a run that goes past these limits is stopped.
# The result file is capped at RESULT_MAX_BYTES, so an honest run stays far below the output limit.
# (Downloads for MCP servers have their own limit, mcp_sources.FETCH_MAX_BYTES.)
OUT_DIR_MAX_BYTES = 256 * 1024 * 1024
PACKAGE_GROWTH_MAX_BYTES = 512 * 1024 * 1024
STREAMS_MAX_BYTES = 64 * 1024 * 1024     # what the run prints, kept in files instead of memory
FREE_DROP_MARGIN_BYTES = 1024 * 1024 * 1024   # room for the rest of this computer during a run
DISK_POLL_S = 0.2   # the first watched folder is checked this often, the others every second
MAX_WATCH_DEPTH = 48   # npm's flattened trees stay far below this
_ENTRY_MIN = 4096   # every entry costs at least one block, so a flood of empty files counts


def _entry_bytes(st) -> int:
    # Blocks really used, so a sparse file with a huge size does not count as full.
    used = st.st_blocks * 512 if hasattr(st, "st_blocks") else st.st_size
    return max(used, _ENTRY_MIN)


def _fd_walk_supported() -> bool:
    return os.scandir in os.supports_fd and os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY")


class _Uncountable(Exception):
    """The folder could not be counted this time (out of file handles): try again next tick."""


def folder_bytes(root: Path, stop_at: int | None = None) -> int | None:
    """Disk used under `root`, never following links. Stops counting once past `stop_at`, so a
    folder full of tiny files cannot make the check itself slow.

    With a limit (a folder the tested code can write to), anything that cannot be counted is
    treated as over it: a subfolder made unreadable to you, one swapped for a link, or one nested
    deeper than MAX_WATCH_DEPTH. Otherwise the code could fill the disk where it is not seen.
    At most one folder handle per level is open at a time. Returns None when this process is out
    of file handles (not the tested code's doing; the caller tries again later)."""
    return folder_usage(root, stop_at)[0]


def folder_usage(root: Path, stop_at: int | None = None, strict: bool = True) -> tuple[int | None, bool]:
    """(folder_bytes, hidden): hidden is True when the count is over only because part of the
    folder could not be looked into (unreadable, a link, or too deep). With strict=False such
    parts are left out of the count instead (the free-space check covers what they hold)."""
    over = (stop_at + 1) if stop_at is not None and strict else None
    walk = _fd_walk if _fd_walk_supported() else _path_walk   # Windows: no folder handles
    try:
        return walk(root, stop_at, over), False
    except _Uncountable:
        return None, False
    except _Hidden:
        return over, True
    except RecursionError:
        return over, over is not None



class _Hidden(Exception):
    """Part of a watched folder cannot be looked into."""


class _Done(Exception):
    def __init__(self, total):
        self.total = total


def _out_of_handles(exc: OSError) -> bool:
    import errno
    return exc.errno in (errno.EMFILE, errno.ENFILE)


def _fd_walk(root: Path, stop_at: int | None, over: int | None) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    total = [0]

    def visit(fd: int, depth: int) -> None:
        subdirs = []
        try:
            with os.scandir(fd) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    total[0] += _entry_bytes(st)
                    if stop_at is not None and total[0] > stop_at:
                        raise _Done(total[0])
                    if stat.S_ISDIR(st.st_mode):
                        subdirs.append(e.name)
        except OSError as exc:
            if _out_of_handles(exc):
                raise _Uncountable()
            if over is not None:
                raise _Hidden()
            return
        if subdirs and depth + 1 > MAX_WATCH_DEPTH:
            if over is not None:
                raise _Hidden()
            return   # without a limit, just stop counting deeper
        for name in subdirs:
            try:
                # Opened by name inside its parent's handle and never through a link, so a folder
                # swapped for a link in the meantime is refused, not followed.
                child = os.open(name, flags, dir_fd=fd)
            except OSError as exc:
                if _out_of_handles(exc):
                    raise _Uncountable()
                if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                    continue   # removed or replaced by a file since it was listed: nothing to count
                if over is not None:
                    raise _Hidden()
                continue
            try:
                visit(child, depth + 1)
            finally:
                os.close(child)

    try:
        top = os.open(str(root), flags)
    except OSError as exc:
        if _out_of_handles(exc):
            raise _Uncountable()
        if over is not None:
            raise _Hidden()
        return 0
    try:
        visit(top, 0)
    except _Done as done:
        return done.total
    finally:
        os.close(top)
    return total[0]


def _path_walk(root: Path, stop_at: int | None, over: int | None) -> int:
    total = 0
    stack = [(str(root), 0)]
    while stack:
        path, depth = stack.pop()
        try:
            with os.scandir(path) as it:
                for e in it:
                    try:
                        # A full stat, not the listing's copy: on Windows the listing does not show
                        # a file growing while it is still open for writing.
                        st = os.stat(e.path, follow_symlinks=False)
                    except OSError:
                        continue
                    total += _entry_bytes(st)
                    if stop_at is not None and total > stop_at:
                        return total
                    if stat.S_ISDIR(st.st_mode) and not e.is_symlink():
                        if depth + 1 > MAX_WATCH_DEPTH:
                            if over is not None:
                                raise _Hidden()
                            continue
                        stack.append((e.path, depth + 1))
        except OSError as exc:
            if _out_of_handles(exc):
                raise _Uncountable()
            if over is not None:
                raise _Hidden()
    return total


_limit_lock = __import__("threading").Lock()
_limit_users = 0
_limit_saved = None


def _raise_handle_limit() -> None:
    """Let this process use more file handles while a watched run is going (macOS starts at 256),
    so the disk check has room for one handle per folder level. Put back by _restore_handle_limit
    once the last watched run ends (runs can overlap)."""
    global _limit_users, _limit_saved
    with _limit_lock:
        _limit_users += 1
        if _limit_users > 1:
            return
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            want = min(hard, 4096) if hard != resource.RLIM_INFINITY else 4096
            if soft != resource.RLIM_INFINITY and soft < want:
                resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
                _limit_saved = (soft, hard)
        except (ImportError, OSError, ValueError):
            pass


def _restore_handle_limit() -> None:
    global _limit_users, _limit_saved
    with _limit_lock:
        _limit_users = max(0, _limit_users - 1)
        if _limit_users or _limit_saved is None:
            return
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, _limit_saved)
        except (ImportError, OSError, ValueError):
            pass
        _limit_saved = None


def _tail(path: Path, n: int = 64 * 1024) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(max(0, os.fstat(f.fileno()).st_size - n))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


FREE_FLOOR_BYTES = 512 * 1024 * 1024   # a run is also stopped if your disk gets this close to full


def _free_bytes(path) -> int | None:
    try:
        return shutil.disk_usage(str(path)).free
    except OSError:
        return None


def _run_watched(cmd, timeout: float, stop, limits: list, streams: Path | None = None,
                 free_watch: tuple[Path, int] | None = None):
    """`_run` for a `docker run` whose tested code can write to the given folders on your disk:
    `stop()` (which removes the container) is called as soon as one grows past its limit. With
    `streams`, what the run prints goes to files in that folder (watched too, so a flood of output
    cannot fill your memory or disk) and the result carries the last 64 KB of each.
    Each limit is (folder, bytes) or (folder, bytes, strict); with strict False, parts of the
    folder that cannot be looked into are left out instead of counting as full.
    With `free_watch` (path, bytes), the free space of the disk holding that path is watched too:
    a file the code deleted but keeps open still uses the disk without showing in any folder.
    Returns (process result, None or (folder, limit, why)), why being "full", "hidden" (part of
    the folder could not be looked into), "uncountable" (the check kept failing), "deleted" (free
    space fell past the limit and came back once the container was removed: the run held it) or
    "freespace" (free space fell and did not come back, so it may not be the run's doing);
    raises TimeoutExpired like `_run` when the run timed out."""
    import threading
    import time
    over: list = []
    done = threading.Event()
    files: list = []
    _raise_handle_limit()

    def printed() -> int:
        # Sizes from the open files themselves, so this works where a folder listing lags behind.
        try:
            return sum(os.fstat(f.fileno()).st_size for f in files)
        except (OSError, ValueError):
            return 0

    free_start = _free_bytes(free_watch[0]) if free_watch else None

    def free_hit():
        if free_start is None:
            return None
        now = _free_bytes(free_watch[0])
        if now is None:
            return None
        # Past the allowed drop; or close to full (under 512 MB free, or under half of what was
        # free at the start when the disk was already that full).
        floor = FREE_FLOOR_BYTES if free_start > FREE_FLOOR_BYTES else free_start // 2
        if free_start - now > free_watch[1] or now < floor:
            return now
        return None

    def watch():
        tick = 0
        misses = [0] * len(limits)
        free_low = None
        free_next = time.monotonic() + 1
        while not done.wait(DISK_POLL_S):
            tick += 1
            hit = None
            if files and printed() > STREAMS_MAX_BYTES:
                hit = (streams, STREAMS_MAX_BYTES, "full")
            if not hit and free_watch and time.monotonic() >= free_next:
                # Once a second by the clock, however long the folder counts take.
                free_next = time.monotonic() + 1
                free_low = free_hit()
                if free_low is not None:
                    hit = (free_watch[0], free_watch[1], "freespace")
            for i, entry in enumerate(limits):
                folder, limit = entry[0], entry[1]
                strict = entry[2] if len(entry) > 2 else True
                if hit:
                    break
                # Later folders (a package folder can hold tens of thousands of files) are
                # counted once a second.
                if i and tick % max(1, round(1 / DISK_POLL_S)):
                    continue
                used, hidden = folder_usage(folder, limit, strict)
                if used is None:
                    # Out of file handles: try again, but not forever, or a run could keep the
                    # check from ever finishing and write as much as it likes meanwhile.
                    misses[i] += 1
                    if misses[i] >= 5:
                        hit = (folder, limit, "uncountable")
                    continue
                misses[i] = 0
                if used > limit:
                    hit = (folder, limit, "hidden" if hidden else "full")
            if hit:
                over.append(hit)   # recorded first, so a slow stop cannot lose it
                before_stop = _free_bytes(free_watch[0]) if hit[2] == "freespace" else None
                alone = _limit_users <= 1   # no other watched run in this process shares the disk
                try:
                    stop()
                except (OSError, subprocess.SubprocessError):
                    pass
                if hit[2] == "freespace" and alone and before_stop is not None:
                    # Removing the container closes every file it held open. If most of the lost
                    # space comes back right after that, the run was very likely holding it (files
                    # deleted but kept open). With other runs going at the same time it is not
                    # tied to this one.
                    lost = free_start - min(free_low, before_stop)
                    for _ in range(10):
                        back = _free_bytes(free_watch[0])
                        if back is not None and lost > 0 and back - min(free_low, before_stop) >= 0.75 * lost:
                            over[0] = (hit[0], hit[1], "deleted")
                            break
                        time.sleep(0.5)
                return

    watcher = None
    started = time.monotonic()
    try:
        if streams is not None:
            streams.mkdir(exist_ok=True)
            files.append(open(streams / "stdout", "wb"))
            files.append(open(streams / "stderr", "wb"))
        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        if files:
            proc = _run(cmd, timeout=timeout, capture=False, stdout=files[0], stderr=files[1])
        else:
            proc = _run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc = None
    finally:
        done.set()
        if watcher is not None:
            watcher.join(timeout=45)
        for f in files:
            f.close()
        _restore_handle_limit()
    if proc is None and not over:
        raise subprocess.TimeoutExpired(cmd, time.monotonic() - started)
    if proc is not None and streams is not None:
        proc = subprocess.CompletedProcess(proc.args, proc.returncode, _tail(streams / "stdout"),
                                           _tail(streams / "stderr"))
    return proc, (over[0] if over else None)


def docker_available() -> bool:
    return docker_problem() is None


# Plain-language fixes for the Docker problems new users hit most. Each message says
# what is wrong and the one thing to do about it.
_GET_DOCKER = "https://docs.docker.com/get-docker/"
_ADMIN = "su" + "do"  # built at run time so install scanners don't flag this file


def _platform() -> str:
    return {"darwin": "mac", "win32": "windows"}.get(sys.platform, "linux")


def explain_docker_error(text: str, platform: str | None = None) -> str | None:
    """Turn Docker's own error text into a fix the user can act on, or None if unknown."""
    t = (text or "").lower()
    plat = platform or _platform()
    if "permission denied" in t and "docker" in t and ("sock" in t or "daemon" in t):
        return ("Docker is running, but your user isn't allowed to use it. On Linux, add yourself to the "
                f"docker group with `{_ADMIN} usermod -aG docker $USER`, then log out and back in. "
                "(Members of that group can control Docker, so only do this on your own machine; "
                "rootless Docker also works.)")
    if any(k in t for k in ("cannot connect to the docker daemon", "is the docker daemon running",
                            "error during connect", "docker desktop is not running",
                            "docker.sock: connect: no such file", "connection refused",
                            "failed to connect to the docker api",  # newer CLIs, e.g. Windows named pipe
                            "dockerdesktoplinuxengine")):
        if plat == "mac":
            return ("Docker is installed but not running. Open Docker Desktop (or start Colima or "
                    "OrbStack) and wait until it says it is running, then try again.")
        if plat == "windows":
            return "Docker is installed but not running. Start Docker Desktop and wait until it is running."
        return ("Docker is installed but not running. Start it with `systemctl start docker` "
                f"(you may need `{_ADMIN}`), or open Docker Desktop, then try again.")
    if "no space left on device" in t:
        return ("Docker is out of disk space. `docker system prune` frees space by removing stopped "
                "containers and unused images, or give Docker more disk in Docker Desktop's settings "
                "(Resources).")
    if "toomanyrequests" in t or "rate limit" in t:
        return ("Docker Hub's download limit was reached while fetching the base image (python:3.11-slim). "
                "Run `docker login` with a free Docker account, or wait a few hours and try again.")
    if any(k in t for k in ("failed to resolve source metadata", "tls handshake timeout", "i/o timeout",
                            "dial tcp", "temporary failure in name resolution", "no such host",
                            "failed to fetch oauth token", "unexpected eof")):
        return ("Docker couldn't download the base image (python:3.11-slim). The first run needs the "
                "internet once to build the sandbox image; check your connection, VPN or proxy, then "
                "try again. Later runs work offline.")
    if "mounts denied" in t or "is not shared from the host" in t:
        return ("Docker isn't allowed to read Detonator's temporary folder. In Docker Desktop open "
                "Settings > Resources > File sharing and add your temporary folder (on a Mac, /var/folders), "
                "or with Colima start it with that folder mounted.")
    if "exec format error" in t or "no matching manifest" in t:
        return ("Docker couldn't run the sandbox image on this computer's processor type. Update Docker, "
                "and on Apple Silicon make sure you use the Apple Silicon build of Docker Desktop.")
    return None


WINDOWS_CONTAINERS = (
    "Docker Desktop is set to Windows containers, but the sandbox is a Linux container. Right-click "
    "the Docker icon in the taskbar, choose \"Switch to Linux containers...\", wait until it is running, "
    "then try again.")


def docker_problem(platform: str | None = None) -> str | None:
    """None when Docker is ready; otherwise a plain-language message saying what to fix."""
    plat = platform or _platform()
    if not docker_bin():
        where = {"mac": "Docker Desktop for Mac (or Colima or OrbStack)",
                 "windows": "Docker Desktop for Windows"}.get(plat, "Docker Engine or Docker Desktop")
        return (f"Docker isn't installed, or Detonator can't find it. Install {where} from {_GET_DOCKER}, "
                "start it, and try again.")
    try:
        proc = _run(["docker", "info", "--format", "{{.ServerVersion}} {{.OSType}}"], timeout=20)
    except subprocess.TimeoutExpired:
        return "Docker didn't answer within 20 seconds. It may still be starting; wait a moment and try again."
    except OSError as exc:
        return f"Detonator couldn't start the docker command: {exc}"
    if proc.returncode == 0:
        if "windows" in (proc.stdout or "").lower().split()[1:]:
            return WINDOWS_CONTAINERS
        return None
    err = (proc.stderr or proc.stdout or "").strip()
    return explain_docker_error(err, plat) or f"Docker isn't ready: {err[-400:] or 'docker info failed'}"


def docker_check() -> str:
    """A short readiness report for `/detonate check`. Runs only `docker info` and
    `docker image inspect`; it never builds, pulls or runs anything."""
    problem = docker_problem()
    if problem:
        return "Docker: not ready.\n" + problem
    lines = ["Docker: ready."]
    try:
        have = _run(["docker", "image", "inspect", image_tag()], timeout=30).returncode == 0
    except Exception:
        have = False
    lines.append("Sandbox image: built." if have else
                 "Sandbox image: not built yet. The first /detonate builds it, which downloads "
                 "python:3.11-slim once and takes about a minute.")
    try:
        have_mon = _run(["docker", "image", "inspect", outside_monitor.image_tag()], timeout=30).returncode == 0
    except Exception:
        have_mon = False
    lines.append("Outside monitor image: built." if have_mon else
                 "Outside monitor image: not built yet. The first /detonate builds it too (it installs "
                 "strace from Debian, so it needs the internet once).")
    return "\n".join(lines)


def image_tag(mcp: bool = False, skill: bool = False) -> str:
    h = hashlib.sha256()
    for name in sorted(os.listdir(SANDBOX_DIR)):
        p = SANDBOX_DIR / name
        if p.is_file():
            h.update(name.encode())
            h.update(p.read_bytes())
    return f"{SKILL_IMAGE_REPO if skill else MCP_IMAGE_REPO if mcp else IMAGE_REPO}:{h.hexdigest()[:12]}"


def ensure_image(mcp: bool = False, skill: bool = False) -> str:
    tag = image_tag(mcp, skill)
    if _run(["docker", "image", "inspect", tag], timeout=30).returncode == 0:
        return tag
    dockerfile = ["-f", str(SANDBOX_DIR / ("Dockerfile.skill" if skill else "Dockerfile.mcp"))] if (mcp or skill) else []
    proc = _run(["docker", "build", "-q", *dockerfile, "-t", tag, str(SANDBOX_DIR)], timeout=900)
    if proc.returncode != 0:
        err = proc.stderr.strip()
        hint = explain_docker_error(err)
        raise DetonatorError(f"{hint}\n(docker build said: {err[-300:]})" if hint
                             else f"docker build failed: {err[-800:]}")
    return tag


def fetch_github(repo: str, sha: str, workdir: Path, subdir: str | None = None, check=None) -> Target:
    """Clone https://github.com/<repo> and check out an exact 40-char SHA.

    Git hooks are disabled and submodules are not fetched, so nothing from the
    plugin runs on the host.
    """
    if not REPO_RE.match(repo or ""):
        raise DetonatorError("repo must look like owner/name")
    sha = (sha or "").lower()
    if not SHA_RE.match(sha):
        raise DetonatorError("sha must be a full 40-character commit SHA (catalog rule 2)")
    dest = workdir / "src"
    url = f"https://github.com/{repo}.git"
    # core.symlinks=false: a link in the repo is checked out as a small text file, so it can
    # never point at a real file on this machine.
    safe = ["-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "core.symlinks=false"]
    steps = [
        ["git", *safe, "init", "-q", str(dest)],
        ["git", *safe, "-C", str(dest), "fetch", "-q", "--depth", "1", url, sha],
        ["git", *safe, "-C", str(dest), "checkout", "-q", "FETCH_HEAD"],
    ]
    for cmd in steps:
        proc = _run(cmd, timeout=300)
        if proc.returncode != 0:
            raise DetonatorError(f"{' '.join(cmd[:3])} failed: {proc.stderr.strip()[-400:]}")
    head = _run(["git", "-C", str(dest), "rev-parse", "HEAD"]).stdout.strip()
    if head != sha:
        raise DetonatorError(f"checked out {head}, expected {sha}")
    path = dest / subdir if subdir else dest
    if subdir and not path.resolve().is_relative_to(dest.resolve()):
        raise DetonatorError("subdir must stay inside the repository")
    if subdir and not path.is_dir():
        raise DetonatorError(f"that commit has no folder called {subdir}. The word after the repo is the "
                             "plugin's folder inside it (branch names are not accepted; leave it out to "
                             "test the newest commit)")
    (check or check_runnable)(path, "that commit" + (f" in {subdir}" if subdir else ""))
    return Target(path=path, label=f"{repo}@{sha[:12]}", repo=repo, sha=sha)


def check_runnable(path: Path, where: str) -> None:
    """Detonator runs Python plugins (plugin.yaml + __init__.py with register(ctx)).
    Say plainly when a package has no such code, instead of a vague failure."""
    if not (path / "plugin.yaml").is_file():
        if (path / "plugin.json").is_file():
            raise DetonatorError(
                f"{where} is a portable Agent Plugins package (plugin.json), not a Python plugin. "
                "It has no register(ctx) code to run; any MCP servers it starts are out of Detonator's scope.")
        raise DetonatorError(f"no plugin.yaml in {where}")
    if not (path / "__init__.py").is_file():
        raise DetonatorError(
            f"{where} has a plugin.yaml but no __init__.py, so there is no Python plugin code to run "
            "(it may be a desktop-only, dashboard-only or language-pack plugin). Nothing was detonated.")


def local_target(path: str) -> Target:
    p = Path(path).expanduser().resolve()
    check_runnable(p, str(p))
    return Target(path=p, label=str(p))


def _yaml_safe_load(text: str):
    """Parse YAML the way Hermes does (hermes_yaml). Outside Hermes (tests, CI) fall back
    to PyYAML, then plain ruamel.yaml."""
    try:
        import hermes_yaml  # Hermes's shared YAML policy

        return hermes_yaml.safe_load(text)
    except ImportError:
        pass
    try:
        import yaml  # PyYAML (dev environments)

        return yaml.safe_load(text)
    except ImportError:
        from ruamel.yaml import YAML

        return YAML(typ="safe", pure=True).load(text)


def load_manifest(plugin_dir: Path) -> dict:
    try:
        data = _yaml_safe_load((plugin_dir / "plugin.yaml").read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise DetonatorError(f"cannot parse plugin.yaml: {exc}")
    if not isinstance(data, dict):
        raise DetonatorError("plugin.yaml is not a mapping")
    return json.loads(json.dumps(data, default=str))


# Each run gets a different, ordinary-looking user, home folder and host name, so a
# plugin cannot spot the sandbox by a fixed path such as /tmp/home. The fake key
# values are randomised inside the harness for the same reason.
_USERS = ("alex", "sam", "jordan", "taylor", "morgan", "casey", "riley", "jamie",
          "chris", "dana", "lee", "kim", "robin", "drew", "maria", "dev")
_HOSTS = ("laptop", "macbook", "workstation", "desktop", "devbox", "mbp")


def random_world() -> dict:
    rng = secrets.SystemRandom()
    user = rng.choice(_USERS) + (str(rng.randint(1, 99)) if rng.random() < 0.5 else "")
    return {"user": user, "home": f"/home/{user}", "host": f"{user}-{rng.choice(_HOSTS)}"}


# The sandbox image's own account lists (python:3.11-slim, Debian bookworm), with no
# sandbox user in them. Each run adds its random user, so the account list matches $USER
# and $HOME instead of naming a fixed account a plugin could look for.
_BASE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""
_BASE_GROUP_TEMPLATE = """root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
{admin_group}:x:27:
audio:x:29:
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
"""
# Built at run time so this file holds no admin-group line that install scanners match.
_BASE_GROUP = _BASE_GROUP_TEMPLATE.replace("{admin_group}", "su" + "do")


_ETC = "/etc"
_ACCOUNT_FILES = ("pass" + "wd", "group")


def write_accounts(etc_dir: Path, world: dict) -> None:
    """passwd and group files for this run's random user (mounted read-only)."""
    etc_dir.mkdir(exist_ok=True)
    user, home = world["user"], world["home"]
    (etc_dir / "passwd").write_text(_BASE_PASSWD + f"{user}:x:10001:10001:{user}:{home}:/bin/bash\n", encoding="utf-8")
    (etc_dir / "group").write_text(_BASE_GROUP + f"{user}:x:10001:\n", encoding="utf-8")
    for f in ("passwd", "group"):
        os.chmod(etc_dir / f, 0o644)
    os.chmod(etc_dir, 0o755)


def docker_run_cmd(tag: str, plugin_dir: Path, in_dir: Path, out_dir: Path, world: dict | None = None,
                   etc_dir: Path | None = None, monitor_args: list[str] | None = None,
                   home_exec: bool = False) -> list[str]:
    """The plugin's `docker run`. With the outside monitor, `monitor_args` puts the plugin on the
    fake internet's network (still no real network) and in the tracer's process namespace,
    and the host name comes from the fake internet's container."""
    world = world or random_world()
    accounts = [a for f in _ACCOUNT_FILES for a in ("-v", f"{etc_dir / f}:{_ETC}/{f}:ro")] if etc_dir else []
    network = list(monitor_args) if monitor_args else ["--network", "none", "--hostname", world["host"]]
    return [
        "docker", "run", "--rm",
        *network,
        # What the run prints reaches Detonator only through `docker run` itself (kept in capped
        # files), never in Docker's own log store on your disk.
        "--log-driver", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        # Skills download tools into the home folder and run them, as on a real computer, so their
        # home allows running files (everything else stays the same).
        "--tmpfs", f"{world['home']}:rw,{'exec,' if home_exec else ''}size={'96m' if home_exec else '32m'},"
                   f"uid=10001,gid=10001,mode=0700",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "128",
        "--memory", "512m",
        "--cpus", "1",
        "--user", "10001:10001",
        "-e", f"HOME={world['home']}",
        "-e", f"USER={world['user']}",
        "-e", f"LOGNAME={world['user']}",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", f"{plugin_dir}:/plugin:ro",
        "-v", f"{in_dir}:/in:ro",
        "-v", f"{out_dir}:/out:rw",
        *accounts,
        tag,
    ]


def _remove_tree(path: Path) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:   # a very deep tree can exhaust Python's recursion on older versions
        pass


@contextlib.contextmanager
def _run_folder(tag: str):
    """The run's private temporary folder, removed afterwards even when the tested code (another
    user id) left subfolders there that you are not allowed to empty, or a tree too deep to remove
    from Python. A removal problem never replaces the run's result."""
    tmp = Path(tempfile.mkdtemp(prefix="detonator-"))
    try:
        yield tmp
    finally:
        _remove_tree(tmp)
        if tmp.exists():
            # What the sandbox user made, only the sandbox user can remove: do that in a throwaway
            # container (no network, no capabilities; chmod -R and find never follow links), then
            # remove the rest.
            mounts = [a for sub in ("out", "plugin") if (tmp / sub).is_dir()
                      for a in ("-v", f"{tmp / sub}:/w/{sub}:rw")]
            if mounts:
                name = f"detonator-clean-{os.getpid()}-{secrets.token_hex(4)}"
                try:
                    _run(["docker", "run", "--rm", f"--name={name}", "--network", "none", "--read-only",
                          "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001",
                          "--log-driver", "none", *mounts, "--entrypoint", "sh", tag, "-c",
                          # First let the owner into folders it locked (mode 0300 and the like).
                          "chmod -R u+rwX,go+rwX /w 2>/dev/null; find /w -mindepth 2 -user 10001 -delete"],
                         timeout=120)
                except subprocess.TimeoutExpired:
                    try:
                        _run(["docker", "rm", "-f", name], timeout=30)
                    except (OSError, subprocess.SubprocessError):
                        pass
                except (OSError, subprocess.SubprocessError):
                    pass
            _remove_tree(tmp)
            if tmp.exists():
                print(f"Detonator: could not fully remove the run folder {tmp}; you can delete it "
                      "(it held only the tested copy and its output).", file=sys.stderr)


def _skip_links(src: str, names: list[str]) -> set[str]:
    """Never copy symlinks into the sandbox copy: one could point at a real file on this
    machine (an SSH key, the real Hermes .env), and reading it would look like a normal
    read of the plugin's own files."""
    return {n for n in names if n == ".git" or os.path.islink(os.path.join(src, n))}


def _make_world_readable(root: Path) -> None:
    # The container runs as uid 10001, so the read-only copy must be readable.
    for dirpath, dirnames, filenames in os.walk(root):
        os.chmod(dirpath, 0o755)
        for name in filenames:
            os.chmod(os.path.join(dirpath, name), 0o644)


# The outside monitor runs by default. DETONATOR_OUTSIDE=0 switches it off (a quicker,
# in-process-only run); the report then says the outside monitor did not run.
def outside_enabled() -> bool:
    return os.environ.get("DETONATOR_OUTSIDE", "1").strip().lower() not in ("0", "false", "no", "off")


def detonate(target: Target, outside: bool | None = None, mcp_entry: dict | None = None,
             skill_plan: dict | None = None) -> dict:
    """Run the plugin in a fresh container and return the raw harness result.

    By default the outside monitor (engine/outside.py) watches the run from two more
    containers. If it cannot start (for example its image cannot be built offline), the
    plugin is still tested by the in-process monitor and the result says why the outside
    monitor did not run.

    With `mcp_entry` ({"command", "args", "env"}, env values already fake), the folder is an MCP
    server instead of a plugin: the harness starts it and speaks MCP to it (engine/mcp.py)."""
    problem = docker_problem()
    if problem:
        raise DetonatorError(problem)
    tag = ensure_image(mcp=mcp_entry is not None, skill=skill_plan is not None)
    use_outside = outside_enabled() if outside is None else outside
    with _run_folder(tag) as tmp:
        plugin_copy = tmp / "plugin"
        shutil.copytree(target.path, plugin_copy, ignore=_skip_links)
        _make_world_readable(tmp)
        # Docker mounts the folders inside directly, so the run folder itself can stay private
        # to you: other users on this computer cannot read or plant files in it.
        os.chmod(tmp, 0o700)
        in_dir = tmp / "in"
        in_dir.mkdir()
        manifest = {} if (mcp_entry is not None or skill_plan is not None) else load_manifest(plugin_copy)
        (in_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        if mcp_entry is not None:
            (in_dir / "mcp.json").write_text(json.dumps(mcp_entry), encoding="utf-8")
            os.chmod(in_dir / "mcp.json", 0o644)
        if skill_plan is not None:
            # The commands travel as data in this file and only ever run inside the container.
            (in_dir / "skill.json").write_text(json.dumps(skill_plan), encoding="utf-8")
            os.chmod(in_dir / "skill.json", 0o644)
        os.chmod(in_dir, 0o755)
        os.chmod(in_dir / "manifest.json", 0o644)
        out_dir = tmp / "out"
        out_dir.mkdir()
        os.chmod(out_dir, 0o777)  # container user is uid 10001
        name = f"detonator-{os.getpid()}-{hashlib.sha1(str(tmp).encode()).hexdigest()[:8]}"
        world = random_world()
        write_accounts(tmp / "etc", world)
        monitor, monitor_args, outside_note = None, None, None
        if use_outside:
            monitor = outside_monitor.Monitor(_run, tmp, name, world["host"])
            try:
                monitor_args = monitor.start()
            except Exception as exc:
                monitor.cleanup()
                monitor = None
                outside_note = {"ran": False, "reason": _one_line(exc)}
        else:
            outside_note = {"ran": False, "chosen_off": True,
                            "reason": "quick test chosen (in-process monitor only)"
                            if outside is False else "switched off (DETONATOR_OUTSIDE=0)"}
        canary = secrets.token_hex(10).upper()
        (in_dir / "run.json").write_text(json.dumps({"canary": canary, "traced": bool(monitor_args),
                                                    **({"mode": "mcp"} if mcp_entry is not None else
                                                       {"mode": "skill"} if skill_plan is not None else {})}),
                                         encoding="utf-8")
        os.chmod(in_dir / "run.json", 0o644)
        if monitor:
            seen_note = {"canary": canary, "home": world["home"]}
        cmd = docker_run_cmd(tag, plugin_copy, in_dir, out_dir, world, tmp / "etc", monitor_args,
                             home_exec=skill_plan is not None)
        if mcp_entry is not None and mcp_entry.get("install"):
            # npm install scripts build into the package's own folder, so this throwaway copy is
            # writable for that run. Writes there after the install phase still count as the
            # server changing its own files (engine/mcp.py).
            cmd = [f"{plugin_copy}:/plugin:rw" if a == f"{plugin_copy}:/plugin:ro" else a for a in cmd]
            for dirpath, dirnames, filenames in os.walk(plugin_copy):
                os.chmod(dirpath, 0o777)
                for n in filenames:
                    os.chmod(os.path.join(dirpath, n), 0o666 | (os.stat(os.path.join(dirpath, n)).st_mode & 0o111))
        cmd.insert(3, f"--name={name}")
        limits = [(out_dir, OUT_DIR_MAX_BYTES)]
        package_start = 0
        if mcp_entry is not None and mcp_entry.get("install"):
            package_start = folder_bytes(plugin_copy) or 0
            # Not strict: install scripts make private folders (mkdtemp, mode 0700) that you may not
            # be able to look into; what they hold is still caught by the free-space check.
            limits.append((plugin_copy, package_start + PACKAGE_GROWTH_MAX_BYTES, False))
        # Free space may fall by what the limits allow plus room for the rest of this computer.
        free_drop = sum(OUT_DIR_MAX_BYTES if i == 0 else PACKAGE_GROWTH_MAX_BYTES for i in range(len(limits))) \
            + STREAMS_MAX_BYTES + FREE_DROP_MARGIN_BYTES
        overflow = None
        try:
            try:
                proc, overflow = _run_watched(cmd, MCP_RUN_TIMEOUT_S if mcp_entry is not None else
                                              SKILL_RUN_TIMEOUT_S if skill_plan is not None else RUN_TIMEOUT_S,
                                              lambda: _run(["docker", "rm", "-f", name], timeout=30), limits,
                                              streams=tmp / "streams", free_watch=(tmp, free_drop))
            except subprocess.TimeoutExpired:
                _run(["docker", "rm", "-f", name], timeout=30)
                proc = None
            seen_outside = {**monitor.finish(), **seen_note} if monitor else outside_note
        finally:
            if monitor:
                monitor.cleanup()
        if overflow is not None:
            folder, limit, why = overflow
            if why == "freespace":
                return {"fatal": f"sandbox stopped: the free space on your disk fell by more than "
                                 f"{limit // (1024 * 1024)} MB during the run (or got close to full) and did not "
                                 "come back when the sandbox was removed. Either the tested code wrote it into "
                                 "folders Detonator could not look into, or another program (or another "
                                 "Detonator run) was writing at the same time, so the run was ended early",
                        "outside": seen_outside, "disk_flood": "freespace"}
            if why == "deleted":
                return {"fatal": f"sandbox stopped: the free space on your disk fell by more than "
                                 f"{limit // (1024 * 1024)} MB during the run without showing in any folder, and "
                                 "came back as soon as the sandbox was removed: most likely the tested code kept "
                                 "deleted files open, so the run was ended early", "outside": seen_outside,
                        "disk_flood": "out", "disk_flood_why": "deleted"}
            kind = "package" if folder == plugin_copy else "streams" if folder == tmp / "streams" else "out"
            grew = (limit - package_start) // (1024 * 1024) if kind == "package" else limit // (1024 * 1024)
            where = {"package": "its own package folder", "out": "the sandbox's output folder",
                     "streams": "its output"}[kind]
            if why == "hidden":
                what = f"made a folder in {where} that Detonator could not look into (locked, a link, or nested too deep)"
            elif why == "uncountable":
                what = None
            else:
                what = {"package": f"grew its own package folder by more than {grew} MB",
                        "streams": f"printed more than {grew} MB of output",
                        "out": f"wrote more than {grew} MB (or tens of thousands of files) to the sandbox's "
                               "output folder"}[kind]
            if why == "uncountable":
                # Most likely this computer ran short of file handles: an error, not a finding.
                return {"fatal": f"sandbox stopped: Detonator could not count what was written to {where} "
                                 "(most likely this computer ran short of open-file handles), so the run "
                                 "was ended early", "outside": seen_outside, "disk_flood": "uncountable"}
            return {"fatal": f"sandbox stopped: the tested code {what} on your disk, so the run was "
                             "ended early", "outside": seen_outside, "disk_flood": kind, "disk_flood_why": why}
        if proc is None:
            limit = MCP_RUN_TIMEOUT_S if mcp_entry is not None else \
                SKILL_RUN_TIMEOUT_S if skill_plan is not None else RUN_TIMEOUT_S
            return {"fatal": f"sandbox timed out after {limit}s", "outside": seen_outside}
        result_path = out_dir / "result.json"
        if not result_path.is_file() and not result_path.is_symlink():
            err = proc.stderr.strip()
            hint = explain_docker_error(err)
            return {"fatal": (f"{hint} " if hint else "") + f"no result (exit {proc.returncode}): {err[-800:]}",
                    "outside": seen_outside}
        try:
            result = json.loads(read_plain_file(result_path, RESULT_MAX_BYTES))
        except OSError as exc:
            # A link or something else in place of the result: never followed (it could point
            # at any file on this computer). The outside monitor's evidence is still judged.
            return {"fatal": f"unreadable result: {exc}", "outside": seen_outside, "result_not_plain": True}
        except json.JSONDecodeError as exc:
            return {"fatal": f"unreadable result: {exc}", "outside": seen_outside}
        if not isinstance(result, dict):
            return {"fatal": "unreadable result: not a JSON object", "outside": seen_outside}
        result["container_exit_code"] = proc.returncode
        result["image"] = tag
        result["outside"] = seen_outside
        if skill_plan is not None:
            return result
        try:
            result["static"] = static.scan(target.path)
        except Exception as exc:  # the read is a coverage aid; never fail the run over it
            result["static"] = {"error": f"{type(exc).__name__}: {exc}"}
        return result


def _one_line(exc: Exception) -> str:
    text = " ".join(str(exc).split())
    hint = explain_docker_error(text)
    return (hint + " " if hint else "") + text[-400:]
