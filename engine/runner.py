"""Host side: fetch a plugin at an exact commit and detonate it in Docker.

Disclosure (catalog rule 13): this module runs `git clone`/`git checkout`
(network, to fetch the plugin under test), `docker build` (network, once, to
build the sandbox image) and `docker run` (no network). It never reads the
user's real Hermes home, .env or auth.json: the sandbox gets its own fake home.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

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
)


def _env() -> dict:
    env = dict(os.environ)
    extra = [d for d in DOCKER_DIRS if os.path.isdir(d)]
    env["PATH"] = os.pathsep.join([env.get("PATH", "")] + extra)
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
    if not docker_bin():
        return False
    try:
        return _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20).returncode == 0
    except Exception:
        return False


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
        raise DetonatorError(f"docker build failed: {proc.stderr.strip()[-800:]}")
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
    """Parse YAML with PyYAML if present, else ruamel.yaml (which Hermes ships)."""
    try:
        import yaml  # PyYAML (dev environments)

        return yaml.safe_load(text)
    except ImportError:
        from ruamel.yaml import YAML  # Hermes's own YAML dependency

        return YAML(typ="safe", pure=True).load(text)


def load_manifest(plugin_dir: Path) -> dict:
    try:
        data = _yaml_safe_load((plugin_dir / "plugin.yaml").read_text()) or {}
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


def docker_run_cmd(tag: str, plugin_dir: Path, in_dir: Path, out_dir: Path, world: dict | None = None) -> list[str]:
    world = world or random_world()
    return [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        "--tmpfs", f"{world['home']}:rw,size=32m,uid=10001,gid=10001,mode=0700",
        "--hostname", world["host"],
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


def detonate(target: Target) -> dict:
    """Run the plugin in a fresh container and return the raw harness result."""
    if not docker_available():
        raise DetonatorError("Docker is not available. Install Docker and make sure the daemon is running.")
    tag = ensure_image()
    with tempfile.TemporaryDirectory(prefix="detonator-") as tmp:
        tmp = Path(tmp)
        plugin_copy = tmp / "plugin"
        shutil.copytree(target.path, plugin_copy, ignore=_skip_links)
        _make_world_readable(tmp)
        in_dir = tmp / "in"
        in_dir.mkdir()
        (in_dir / "manifest.json").write_text(json.dumps(load_manifest(plugin_copy)))
        os.chmod(in_dir, 0o755)
        os.chmod(in_dir / "manifest.json", 0o644)
        out_dir = tmp / "out"
        out_dir.mkdir()
        os.chmod(out_dir, 0o777)  # container user is uid 10001
        name = f"detonator-{os.getpid()}-{hashlib.sha1(str(tmp).encode()).hexdigest()[:8]}"
        cmd = docker_run_cmd(tag, plugin_copy, in_dir, out_dir)
        cmd.insert(3, f"--name={name}")
        try:
            proc = _run(cmd, timeout=RUN_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            _run(["docker", "rm", "-f", name], timeout=30)
            return {"fatal": f"sandbox timed out after {RUN_TIMEOUT_S}s"}
        result_path = out_dir / "result.json"
        if not result_path.is_file():
            return {"fatal": f"no result (exit {proc.returncode}): {proc.stderr.strip()[-800:]}"}
        try:
            result = json.loads(result_path.read_text())
        except json.JSONDecodeError as exc:
            return {"fatal": f"unreadable result: {exc}"}
        result["container_exit_code"] = proc.returncode
        result["image"] = tag
        try:
            result["static"] = static.scan(target.path)
        except Exception as exc:  # the read is a coverage aid; never fail the run over it
            result["static"] = {"error": f"{type(exc).__name__}: {exc}"}
        return result
