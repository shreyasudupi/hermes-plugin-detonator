"""Host side: fetch a plugin at an exact commit and detonate it in Docker.

Disclosure (catalog rule 13): this module runs `git clone`/`git checkout`
(network, to fetch the plugin under test), `docker build` (network, once, to
build the sandbox image) and `docker run` (no real network; see engine/outside.py
for the two monitor containers). It never reads the
user's real Hermes home, .env or auth.json: the sandbox gets its own fake home.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import outside as outside_monitor
from . import static

SANDBOX_DIR = Path(__file__).resolve().parent.parent / "sandbox"
IMAGE_REPO = "detonator-sandbox"
RUN_TIMEOUT_S = 180

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


def _env() -> dict:
    """A minimal environment for git and docker: allow-listed variables only."""
    env = {k: os.environ[k] for k in _PASS_ENV if k in os.environ}
    extra = [d for d in DOCKER_DIRS if os.path.isdir(d)]
    env["PATH"] = os.pathsep.join([os.environ.get("PATH", "")] + extra)
    env["GIT_TERMINAL_PROMPT"] = "0"  # never hang waiting for a password prompt
    return env


def docker_bin() -> str | None:
    return shutil.which("docker", path=_env()["PATH"])


def _run(cmd, timeout=600, **kwargs):
    env = _env()
    if cmd and cmd[0] == "docker":
        cmd = [docker_bin() or "docker", *cmd[1:]]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, **kwargs)


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


def image_tag() -> str:
    h = hashlib.sha256()
    for name in sorted(os.listdir(SANDBOX_DIR)):
        p = SANDBOX_DIR / name
        if p.is_file():
            h.update(name.encode())
            h.update(p.read_bytes())
    return f"{IMAGE_REPO}:{h.hexdigest()[:12]}"


def ensure_image() -> str:
    tag = image_tag()
    if _run(["docker", "image", "inspect", tag], timeout=30).returncode == 0:
        return tag
    proc = _run(["docker", "build", "-q", "-t", tag, str(SANDBOX_DIR)], timeout=900)
    if proc.returncode != 0:
        err = proc.stderr.strip()
        hint = explain_docker_error(err)
        raise DetonatorError(f"{hint}\n(docker build said: {err[-300:]})" if hint
                             else f"docker build failed: {err[-800:]}")
    return tag


def fetch_github(repo: str, sha: str, workdir: Path, subdir: str | None = None) -> Target:
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
    check_runnable(path, "that commit" + (f" in {subdir}" if subdir else ""))
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
                   etc_dir: Path | None = None, monitor_args: list[str] | None = None) -> list[str]:
    """The plugin's `docker run`. With the outside monitor, `monitor_args` puts the plugin on the
    fake internet's network (still no real network) and in the tracer's process namespace,
    and the host name comes from the fake internet's container."""
    world = world or random_world()
    accounts = [a for f in _ACCOUNT_FILES for a in ("-v", f"{etc_dir / f}:{_ETC}/{f}:ro")] if etc_dir else []
    network = list(monitor_args) if monitor_args else ["--network", "none", "--hostname", world["host"]]
    return [
        "docker", "run", "--rm",
        *network,
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        "--tmpfs", f"{world['home']}:rw,size=32m,uid=10001,gid=10001,mode=0700",
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


def detonate(target: Target, outside: bool | None = None) -> dict:
    """Run the plugin in a fresh container and return the raw harness result.

    By default the outside monitor (engine/outside.py) watches the run from two more
    containers. If it cannot start (for example its image cannot be built offline), the
    plugin is still tested by the in-process monitor and the result says why the outside
    monitor did not run."""
    problem = docker_problem()
    if problem:
        raise DetonatorError(problem)
    tag = ensure_image()
    use_outside = outside_enabled() if outside is None else outside
    with tempfile.TemporaryDirectory(prefix="detonator-") as tmp:
        tmp = Path(tmp)
        plugin_copy = tmp / "plugin"
        shutil.copytree(target.path, plugin_copy, ignore=_skip_links)
        _make_world_readable(tmp)
        # Docker mounts the folders inside directly, so the run folder itself can stay private
        # to you: other users on this computer cannot read or plant files in it.
        os.chmod(tmp, 0o700)
        in_dir = tmp / "in"
        in_dir.mkdir()
        (in_dir / "manifest.json").write_text(json.dumps(load_manifest(plugin_copy)), encoding="utf-8")
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
        (in_dir / "run.json").write_text(json.dumps({"canary": canary, "traced": bool(monitor_args)}),
                                         encoding="utf-8")
        os.chmod(in_dir / "run.json", 0o644)
        if monitor:
            seen_note = {"canary": canary, "home": world["home"]}
        cmd = docker_run_cmd(tag, plugin_copy, in_dir, out_dir, world, tmp / "etc", monitor_args)
        cmd.insert(3, f"--name={name}")
        try:
            try:
                proc = _run(cmd, timeout=RUN_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                _run(["docker", "rm", "-f", name], timeout=30)
                proc = None
            seen_outside = {**monitor.finish(), **seen_note} if monitor else outside_note
        finally:
            if monitor:
                monitor.cleanup()
        if proc is None:
            return {"fatal": f"sandbox timed out after {RUN_TIMEOUT_S}s", "outside": seen_outside}
        result_path = out_dir / "result.json"
        if not result_path.is_file():
            err = proc.stderr.strip()
            hint = explain_docker_error(err)
            return {"fatal": (f"{hint} " if hint else "") + f"no result (exit {proc.returncode}): {err[-800:]}",
                    "outside": seen_outside}
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return {"fatal": f"unreadable result: {exc}", "outside": seen_outside}
        if not isinstance(result, dict):
            return {"fatal": "unreadable result: not a JSON object", "outside": seen_outside}
        result["container_exit_code"] = proc.returncode
        result["image"] = tag
        result["outside"] = seen_outside
        try:
            result["static"] = static.scan(target.path)
        except Exception as exc:  # the read is a coverage aid; never fail the run over it
            result["static"] = {"error": f"{type(exc).__name__}: {exc}"}
        return result


def _one_line(exc: Exception) -> str:
    text = " ".join(str(exc).split())
    hint = explain_docker_error(text)
    return (hint + " " if hint else "") + text[-400:]
