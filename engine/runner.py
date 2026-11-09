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
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

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


def _run(cmd, timeout=600, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)


def docker_available() -> bool:
    if not shutil.which("docker"):
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
    safe = ["-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never"]
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
    if not (path / "plugin.yaml").is_file():
        raise DetonatorError("no plugin.yaml at that commit" + (f" in {subdir}" if subdir else ""))
    return Target(path=path, label=f"{repo}@{sha[:12]}", repo=repo, sha=sha)


def local_target(path: str) -> Target:
    p = Path(path).expanduser().resolve()
    if not (p / "plugin.yaml").is_file():
        raise DetonatorError(f"no plugin.yaml in {p}")
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


def docker_run_cmd(tag: str, plugin_dir: Path, in_dir: Path, out_dir: Path) -> list[str]:
    return [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "128",
        "--memory", "512m",
        "--cpus", "1",
        "--user", "10001:10001",
        "-e", "HOME=/tmp/home",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", f"{plugin_dir}:/plugin:ro",
        "-v", f"{in_dir}:/in:ro",
        "-v", f"{out_dir}:/out:rw",
        tag,
    ]


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
        shutil.copytree(target.path, plugin_copy, ignore=shutil.ignore_patterns(".git"))
        _make_world_readable(tmp)
        in_dir = tmp / "in"
        in_dir.mkdir()
        (in_dir / "manifest.json").write_text(json.dumps(load_manifest(target.path)))
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
        return result
