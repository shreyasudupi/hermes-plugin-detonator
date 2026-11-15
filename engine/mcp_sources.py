"""Where an MCP server comes from: a Hermes config entry, a local folder, or an exact package.

Turns one `mcp_servers.<name>` entry from ~/.hermes/config.yaml into something the sandbox can
run, without ever running it on this computer:

  * npx / uvx packages are downloaded in a separate, short-lived fetch container (network on,
    no decoys, install scripts OFF). Their install scripts run later inside the locked sandbox.
  * a local script (python /path/server.py, node /path/index.js) is copied from its folder.
  * remote (HTTP) servers run on someone else's computer: only their entry is checked.

It also checks the entry itself (unpinned packages, keys written into config.yaml, full trust).
Values are never copied anywhere: the sandbox gets fake keys under the same names, and evidence
shows only the first characters of a value.

Disclosure (catalog rule 13): `docker run` of a pinned node or python image with network access to
download the package (npm install --ignore-scripts / pip install --only-binary). Nothing from the
package runs in that container.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import runner

DOCKERFILE_MCP = runner.SANDBOX_DIR / "Dockerfile.mcp"
FETCH_TIMEOUT_S = 300
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")

NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]{0,100}/)?[a-z0-9][a-z0-9._~-]{0,213}$")
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,100}[A-Za-z0-9])?$")
EXACT_NPM = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
EXACT_PYPI = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev)\d+)*$")
PY_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
# Well-known key shapes, and long random-looking strings.
TOKEN_SHAPES = re.compile(r"^(?:sk-|sk_|pk_|rk_|ghp_|gho_|ghs_|github_pat_|glpat-|xox[abprs]-|AKIA|AIza|"
                          r"ya29\.|eyJ|hf_|npm_|pypi-|shpat_|SG\.|dop_v1_|lin_api_|ntn_|secret_)", re.I)
LOOPBACK = ("127.", "localhost", "[::1]", "::1")


class SourceError(Exception):
    pass


@dataclass
class Plan:
    """How to get and start one server. kind: npm, pypi, local, remote."""
    kind: str
    name: str = ""                 # server name in the config (or the folder)
    package: str = ""
    version: str | None = None     # None = not pinned (latest is tested)
    pinned: bool = True
    script: str = ""               # local: the script path on this computer
    command: str = ""              # local: python or node
    args: list = field(default_factory=list)   # the server's own arguments
    env_names: list = field(default_factory=list)
    url: str = ""


# ---------------------------------------------------------------------------
# Reading Hermes's config
# ---------------------------------------------------------------------------
def hermes_config_path() -> Path:
    home = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
    return Path(home) / "config.yaml"


def read_servers(path: Path | None = None) -> dict:
    """The `mcp_servers` mapping from Hermes's config.yaml (read-only)."""
    path = path or hermes_config_path()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        raise SourceError(f"could not read {path}")
    try:
        data = runner._yaml_safe_load(text) or {}
    except Exception as exc:
        raise SourceError(f"could not parse {path}: {exc}")
    servers = data.get("mcp_servers") if isinstance(data, dict) else None
    return servers if isinstance(servers, dict) else {}


def _env_names(entry: dict) -> list:
    env = entry.get("env") or {}
    if not isinstance(env, dict):
        raise SourceError("env must be a mapping")
    names = [str(k) for k in env]
    if not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", n) for n in names):
        raise SourceError("env has a name that is not a plain variable name")
    return names[:32]


def _split_npm(spec: str):
    if spec.startswith("@"):
        name, _, ver = spec[1:].partition("@")
        name = "@" + name
    else:
        name, _, ver = spec.partition("@")
    return name.lower(), (ver or None)


def plan_entry(name: str, entry, base: Path | None = None) -> Plan:
    """Work out what an entry starts. Never runs anything."""
    if not isinstance(entry, dict):
        raise SourceError(f"{name}: the server entry is not a mapping")
    if entry.get("url"):
        return Plan(kind="remote", name=name, url=str(entry.get("url"))[:300])
    command = entry.get("command")
    if not isinstance(command, str) or not command.strip():
        raise SourceError(f"{name}: no command to start the server")
    args = entry.get("args") or []
    if not isinstance(args, list) or not all(isinstance(a, (str, int, float)) for a in args):
        raise SourceError(f"{name}: args must be a list of words")
    args = [str(a) for a in args][:64]
    env_names = _env_names(entry)
    prog = posixpath.basename(command.strip().replace("\\", "/")).lower()
    for suffix in (".exe", ".cmd"):
        prog = prog[: -len(suffix)] if prog.endswith(suffix) else prog

    if prog in ("npx", "bunx", "pnpx"):
        spec, rest, i = None, [], 0
        while i < len(args):
            a = args[i]
            if spec is None and a in ("-p", "--package") and i + 1 < len(args):
                spec, i = args[i + 1], i + 2
                continue
            if spec is None and a.startswith("-"):
                i += 1
                continue
            if spec is None:
                spec = a
            else:
                rest.append(a)
            i += 1
        if not spec:
            raise SourceError(f"{name}: npx is given no package")
        pkg, ver = _split_npm(spec)
        if not NPM_NAME.match(pkg):
            raise SourceError(f"{name}: '{spec[:80]}' is not a plain npm package name "
                              "(git, file and URL packages are not supported yet)")
        pinned = bool(ver and EXACT_NPM.match(ver))
        return Plan(kind="npm", name=name, package=pkg, version=ver if pinned else None, pinned=pinned,
                    args=rest, env_names=env_names)

    if prog in ("uvx", "pipx") or (prog == "uv" and args[:1] == ["tool"]):
        a = args[2:] if prog == "uv" else (args[1:] if prog == "pipx" and args[:1] == ["run"] else args)
        spec, script, rest, i = None, None, [], 0
        while i < len(a):
            if a[i] in ("--from", "--spec") and i + 1 < len(a):
                spec, i = a[i + 1], i + 2
                continue
            if a[i].startswith("-") and script is None:
                i += 2 if a[i] in ("--with", "--python", "-p", "--index-url") else 1
                continue
            if script is None:
                script = a[i]
            else:
                rest.append(a[i])
            i += 1
        spec = spec or script
        if not spec:
            raise SourceError(f"{name}: uvx is given no package")
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(?:==(.+)|@(.+))?$", spec)
        if not m or not PYPI_NAME.match(m.group(1)):
            raise SourceError(f"{name}: '{spec[:80]}' is not a plain PyPI package name "
                              "(git and URL packages are not supported yet)")
        ver = m.group(2) or m.group(3)
        pinned = bool(ver and EXACT_PYPI.match(ver))
        return Plan(kind="pypi", name=name, package=m.group(1), version=ver if pinned else None, pinned=pinned,
                    script=script if script and script != spec else "", args=rest, env_names=env_names)

    if re.fullmatch(r"python(?:3(?:\.\d+)?)?|node|bun|deno|sh|bash", prog):
        run_as = "node" if prog in ("node", "bun", "deno") else "python" if prog.startswith("python") else prog
        for i, a in enumerate(args):
            if a.startswith("-"):
                continue
            p = Path(os.path.expanduser(a))
            if not p.is_absolute() and base is not None:
                p = base / p
            if p.is_file():
                return Plan(kind="local", name=name, command=run_as, script=str(p.resolve()),
                            args=args[:i] + ["\0SCRIPT\0"] + args[i + 1:], env_names=env_names)
            break
        if run_as == "python" and len(args) >= 2 and args[0] == "-m":
            raise SourceError(f"{name}: runs an installed Python module ({args[1][:60]}); give the package "
                              "with uvx in the config, or test its folder with /detonate-mcp <folder>")
        raise SourceError(f"{name}: could not find the script it starts on this computer")
    if prog == "docker":
        raise SourceError(f"{name}: starts a Docker container. Running Docker inside the sandbox would break "
                          "its isolation, so this server cannot be tested yet.")
    raise SourceError(f"{name}: starts '{prog[:40]}', a program Detonator cannot move into the sandbox. "
                      "Only npx, uvx and python/node scripts can be tested.")


# ---------------------------------------------------------------------------
# Checks on the entry itself
# ---------------------------------------------------------------------------
def _redact(value: str) -> str:
    return value[:4] + "…" + f" ({len(value)} characters)"


def _looks_secret(value: str) -> bool:
    v = value.strip()
    if not v or v.startswith(("${", "$")) or len(v) < 12:
        return False
    if TOKEN_SHAPES.match(v):
        return True
    return len(v) >= 24 and bool(re.fullmatch(r"[A-Za-z0-9_\-.+/=]+", v)) and \
        bool(re.search(r"[A-Za-z]", v)) and bool(re.search(r"\d", v)) and not re.fullmatch(r"[\d.]+", v)


def config_checks(name: str, entry: dict, plan: Plan | None) -> list:
    """Findings about the entry, as plain dicts: (rule, severity, title, evidence)."""
    out = []
    if not isinstance(entry, dict):
        return out
    if plan and plan.kind in ("npm", "pypi") and not plan.pinned:
        out.append(("mcp_unpinned_launch", "medium",
                    f"Starts the newest version of {plan.package} each time (no exact version)",
                    [f"{plan.package}: the version tested here may not be the one Hermes runs tomorrow"]))
    found = []
    for key in ("env", "headers"):
        values = entry.get(key) or {}
        if isinstance(values, dict):
            for k, v in values.items():
                if isinstance(v, str) and (_looks_secret(v) or (key == "headers" and v.lower().startswith("bearer ")
                                                                and _looks_secret(v[7:]))):
                    found.append(f"{key}.{str(k)[:40]}: {_redact(v)}")
    for a in entry.get("args") or []:
        if isinstance(a, str):
            val = a.split("=", 1)[1] if a.startswith("--") and "=" in a else a
            if TOKEN_SHAPES.match(val) and len(val) >= 16:
                found.append(f"args: {_redact(val)}")
    if found:
        out.append(("mcp_inline_secret", "medium", "Has a key written into config.yaml", found[:6]))
    third_party = plan is not None and plan.kind in ("npm", "pypi", "remote")
    trust = str(entry.get("trust") or "full").lower()
    if third_party and trust == "full":
        out.append(("mcp_full_trust_third_party", "low",
                    "Runs a third-party server with full trust (the default)",
                    [f"{name}: trust is {'not set' if 'trust' not in entry else 'full'}; with trust: untrusted, "
                     "Hermes asks before every tool that is not marked read-only"]))
    if plan and plan.kind == "remote" and plan.url.lower().startswith("http://") \
            and not plan.url.lower()[7:].startswith(LOOPBACK):
        out.append(("mcp_inline_secret", "medium", "Talks to a remote server without encryption (http://)",
                    [plan.url[:120]]))
    return out


# ---------------------------------------------------------------------------
# Getting the code (never runs it here)
# ---------------------------------------------------------------------------
def node_image() -> str:
    for line in DOCKERFILE_MCP.read_text(encoding="utf-8").splitlines():
        if line.startswith("FROM node:"):
            return line.split()[1]
    raise SourceError("Dockerfile.mcp names no node image")


def python_image() -> str:
    for line in DOCKERFILE_MCP.read_text(encoding="utf-8").splitlines():
        if line.startswith("FROM python:"):
            return line.split()[1]
    raise SourceError("Dockerfile.mcp names no python image")


def _proxy_args() -> list:
    """Corporate proxies and certificate bundles from this computer, so the download works
    where the person's own npm and pip work."""
    args = []
    proxy = ""
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
        if os.environ.get(k):
            args += ["-e", f"{k}={os.environ[k]}"]
            proxy = proxy or (os.environ[k] if "proxy" in k.lower() and "no" not in k.lower() else "")
    if proxy and re.match(r"^\w+://(?:[^@/]*@)?(?:127\.|localhost|\[::1\])", proxy):
        args += ["--network", "host"]     # a proxy on this computer's own loopback
    ca = next((os.environ[k] for k in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE")
               if os.environ.get(k) and Path(os.environ[k]).is_file()), None)
    if ca:
        args += ["-v", f"{ca}:/etc/detonator-ca.pem:ro", "-e", "NODE_EXTRA_CA_CERTS=/etc/detonator-ca.pem",
                 "-e", "PIP_CERT=/etc/detonator-ca.pem", "-e", "SSL_CERT_FILE=/etc/detonator-ca.pem"]
    return args


def _fetch_cmd(image: str, work: Path, argv: list) -> list:
    return ["docker", "run", "--rm", "--read-only", "--tmpfs", "/tmp:rw,size=512m,mode=1777",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256",
            "--memory", "1g", "--cpus", "2", "--user", "10001:10001", "-e", "HOME=/tmp",
            "-e", "npm_config_cache=/tmp/.npm", "-e", "npm_config_update_notifier=false",
            *_proxy_args(), "-v", f"{work}:/work:rw", "-w", "/work", "--entrypoint", argv[0], image, *argv[1:]]


def _run_fetch(cmd: list, what: str) -> None:
    try:
        proc = runner._run(cmd, timeout=FETCH_TIMEOUT_S)
    except Exception as exc:
        raise SourceError(f"could not download {what}: {type(exc).__name__}")
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        hint = runner.explain_docker_error(err)
        raise SourceError(f"could not download {what}" + (f": {hint}" if hint else f": {err[-400:]}"))


def fetch_npm(plan: Plan, work: Path) -> Path:
    work.mkdir(parents=True, exist_ok=True)
    os.chmod(work, 0o777)
    spec = f"{plan.package}@{plan.version or 'latest'}"
    _run_fetch(_fetch_cmd(node_image(), work, [
        "npm", "install", "--ignore-scripts", "--omit=dev", "--no-audit", "--no-fund", "--no-package-lock",
        "--prefix", "/work", "--", spec]), spec)
    return work


def fetch_pypi(plan: Plan, work: Path) -> Path:
    work.mkdir(parents=True, exist_ok=True)
    os.chmod(work, 0o777)
    spec = f"{plan.package}=={plan.version}" if plan.version else plan.package
    # Wheels only: building from a source package runs its code, which must not happen outside the sandbox.
    _run_fetch(_fetch_cmd(python_image(), work, [
        "python", "-m", "pip", "install", "--only-binary=:all:", "--no-compile", "--no-cache-dir",
        "--disable-pip-version-check", "--target", "/work/site", "--", spec]),
        spec + " (only packages published as wheels can be tested)")
    return work


def _inside(base: Path, rel: str) -> bool:
    norm = posixpath.normpath(rel)
    return not (norm.startswith("../") or norm == ".." or norm.startswith("/"))


def npm_entry(plan: Plan, work: Path) -> dict:
    pkg_dir = work / "node_modules" / plan.package
    try:
        meta = json.loads((pkg_dir / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SourceError(f"{plan.package} did not install")
    plan.version = plan.version or str(meta.get("version") or "")[:40]
    bins = meta.get("bin")
    short = plan.package.split("/")[-1]
    if isinstance(bins, str):
        rel = bins
    elif isinstance(bins, dict) and bins:
        rel = bins.get(short) or (next(iter(bins.values())) if len(bins) == 1 else bins[sorted(bins)[0]])
    else:
        rel = meta.get("main") or "index.js"
    rel = str(rel)
    if not _inside(pkg_dir, rel):
        raise SourceError(f"{plan.package}: its start file points outside the package")
    return {"command": "node", "args": [f"node_modules/{plan.package}/{posixpath.normpath(rel)}", *plan.args],
            "env": {n: "" for n in plan.env_names}}


def pypi_entry(plan: Plan, work: Path) -> dict:
    site = work / "site"
    norm = re.sub(r"[-_.]+", "_", plan.package).lower()
    infos = [d for d in site.glob("*.dist-info") if re.sub(r"[-_.]+", "_", d.name[: -len(".dist-info")].rsplit("-", 1)[0]).lower() == norm]
    if not infos:
        raise SourceError(f"{plan.package} did not install")
    info = infos[0]
    plan.version = plan.version or info.name[: -len(".dist-info")].rsplit("-", 1)[-1][:40]
    scripts = {}
    try:
        section = None
        for line in (info / "entry_points.txt").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("["):
                section = line.strip("[]")
            elif section == "console_scripts" and "=" in line:
                k, v = (x.strip() for x in line.split("=", 1))
                scripts[k] = v.split("[", 1)[0].strip()
    except OSError:
        pass
    want = plan.script or plan.package
    target = scripts.get(want) or (next(iter(scripts.values())) if len(scripts) == 1 else None)
    if not target or ":" not in target:
        raise SourceError(f"{plan.package}: no command named {want} in the package "
                          f"({', '.join(sorted(scripts))[:200] or 'it has none'})")
    module, func = target.split(":", 1)
    if not (PY_IDENT.match(module) and PY_IDENT.match(func)):
        raise SourceError(f"{plan.package}: its command entry is not a plain module:function")
    code = f"import sys; from {module} import {func.split('.')[0]} as _m; sys.argv[0] = {want!r}; " \
           f"sys.exit(_m{''.join('.' + p for p in func.split('.')[1:])}())"
    return {"command": "python", "args": ["-c", code, *plan.args], "env": {n: "" for n in plan.env_names},
            "extra_env": {"PYTHONPATH": "/plugin/site"}}


def npm_install_scripts(folder: Path, limit: int = 2000) -> list:
    """Packages under node_modules that have install scripts (they run when a person installs it)."""
    found = []
    root = folder / "node_modules"
    if not root.is_dir():
        return found
    for i, pj in enumerate(root.rglob("package.json")):
        if i > limit:
            break
        up = pj.parent.parent
        if pj.is_symlink() or not (up.name == "node_modules" or
                                   (up.name.startswith("@") and up.parent.name == "node_modules")):
            continue    # a package's own package.json sits right under node_modules (or a @scope)
        try:
            meta = json.loads(pj.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        scripts = meta.get("scripts") if isinstance(meta, dict) else None
        has = [s for s in INSTALL_SCRIPTS if isinstance(scripts, dict) and scripts.get(s)]
        if not has and (pj.parent / "binding.gyp").is_file():
            has = ["install (node-gyp build)"]
        if has:
            found.append({"package": str(meta.get("name") or pj.parent.name)[:100],
                          "scripts": {s: str((scripts or {}).get(s, "node-gyp rebuild"))[:200] for s in has}})
    return found[:50]


def local_folder(plan: Plan, work: Path) -> tuple[Path, dict]:
    """Copy the script's project folder (no symlinks) and point the entry at the copy."""
    script = Path(plan.script)
    folder = script.parent
    marker = "package.json" if plan.command == "node" else "pyproject.toml"
    for up in [script.parent, *list(script.parent.parents)[:3]]:
        if (up / marker).is_file():
            folder = up
            break
    home = Path(os.path.expanduser("~")).resolve()
    if folder in (home, Path("/")) or folder == home.parent:
        raise SourceError(f"{plan.name}: the script sits directly in your home folder; move it into its own folder")
    dest = work / "server"
    shutil.copytree(folder, dest, ignore=runner._skip_links)
    rel = script.relative_to(folder).as_posix()
    args = [rel if a == "\0SCRIPT\0" else a for a in plan.args]
    return dest, {"command": plan.command, "args": args, "env": {n: "" for n in plan.env_names}}
