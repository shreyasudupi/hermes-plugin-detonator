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
package runs in that container. It never gets host networking: a proxy on this computer's loopback
is reached through host.docker.internal (Docker Desktop) or a one-port relay (Linux, `_Relay`).
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import secrets
import shutil
import sys
import tempfile
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


def _hermes_raw_config():
    """Inside Hermes: its own public config reader (hermes_cli.config, listed in Hermes's plugin
    public API). It follows the active profile and returns the file as written, so `${VAR}`
    references stay unexpanded and no value from your .env is ever read. None outside Hermes."""
    try:
        from hermes_cli.config import read_raw_config  # public Hermes surface
    except Exception:
        return None
    try:
        data = read_raw_config()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def read_servers(path: Path | None = None) -> dict:
    """The `mcp_servers` mapping from Hermes's config.yaml (read-only). Only this mapping is
    used; env and header values are checked for written-in keys and then dropped."""
    data = _hermes_raw_config() if path is None else None
    if data is not None:
        servers = data.get("mcp_servers")
        return servers if isinstance(servers, dict) else {}
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


def _readable_file(path: str) -> bool:
    try:
        return Path(path).is_file() and os.access(path, os.R_OK)
    except OSError:
        return False


_PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
_NO_PROXY_VARS = ("NO_PROXY", "no_proxy")
_LOOPBACK_URL = re.compile(r"^(?P<scheme>\w+)://(?P<auth>[^@/]*@)?"
                           r"(?P<host>127(?:\.\d{1,3}){3}|localhost|\[::1\])(?::(?P<port>\d{1,5}))?(?P<rest>/.*)?$", re.I)
_DEFAULT_PORTS = {"http": 80, "https": 443, "socks5": 1080, "socks5h": 1080, "socks4": 1080}
DESKTOP_HOST = "host.docker.internal"
RELAY_MAX_CONNS = 32
RELAY_IDLE_S = 300


class _Relay:
    """Forwards TCP from containers on Docker's bridge to one proxy port on this computer's loopback.

    Used instead of host networking: the download container then sees only this one port of
    this computer, never its other local services. It listens on the bridge's gateway address
    (not reachable from other computers), accepts only peers inside the bridge subnet, and
    lives only for one download."""

    def __init__(self, bind_ip: str, subnet: str, target: tuple):
        import ipaddress
        import socket
        import threading
        self._net = ipaddress.ip_network(subnet, strict=False)
        self._target = target
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((bind_ip, 0))
        self._sock.listen(16)
        self._sock.settimeout(0.5)    # so close() is noticed on every platform
        self.host, self.port = self._sock.getsockname()[:2]
        self._slots = threading.BoundedSemaphore(RELAY_MAX_CONNS)
        self._closed = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        import ipaddress
        import socket
        import threading
        while not self._closed:
            try:
                conn, peer = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(None)
            try:
                ok = ipaddress.ip_address(peer[0]) in self._net
            except ValueError:
                ok = False
            if not ok or not self._slots.acquire(blocking=False):
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        import socket
        import threading
        try:
            up = socket.create_connection(self._target, timeout=10)
        except OSError:
            conn.close()
            self._slots.release()
            return
        for s in (conn, up):
            s.settimeout(RELAY_IDLE_S)

        def pump(a, b):
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            finally:
                for s in (a, b):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t = threading.Thread(target=pump, args=(up, conn), daemon=True)
        t.start()
        pump(conn, up)
        t.join(RELAY_IDLE_S)
        conn.close()
        up.close()
        self._slots.release()

    def close(self):
        import socket
        self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


def _docker_desktop() -> bool:
    """Docker Desktop (Mac, Windows, and its Linux app) forwards host.docker.internal to this
    computer, its loopback included."""
    if os.name == "nt" or sys.platform == "darwin":
        return True
    try:
        out = runner._run(["docker", "info", "--format", "{{.OperatingSystem}}"], timeout=20).stdout or ""
    except Exception:
        return False
    return "docker desktop" in out.lower()


def _bridge() -> tuple:
    """(gateway ip, subnet) of Docker's default bridge network."""
    try:
        out = runner._run(["docker", "network", "inspect", "bridge", "--format",
                           "{{range .IPAM.Config}}{{.Gateway}} {{.Subnet}}\n{{end}}"], timeout=20).stdout or ""
    except Exception:
        out = ""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and ":" not in parts[0]:
            return parts[0], parts[1]
    raise SourceError("your proxy runs on this computer (localhost) and Docker's bridge network was not "
                      "found, so the download container cannot reach it; set HTTPS_PROXY to an address "
                      "that is not localhost, or unset it")


def _proxy_var_names(names: tuple) -> tuple:
    """Windows environment names ignore case, so HTTPS_PROXY and https_proxy are one variable there."""
    return tuple(n for n in names if n.isupper()) if os.name == "nt" else names


class _ProxySetup:
    """Docker arguments that give the download container this computer's proxy settings and
    certificate bundle, so the download works where the person's own npm and pip work.

    It never uses host networking. A proxy on this computer's loopback is reached through
    host.docker.internal on Docker Desktop, or through a one-port relay (`_Relay`) on Linux.
    Proxy values go through a private env file, so a proxy password never shows in ps."""

    def __init__(self):
        self.args, self._relays, self._env_file = [], {}, None

    def __enter__(self):
        try:
            self._build()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self.args

    def _build(self):
        rewritten, by_name = {}, []
        for k in _proxy_var_names(_PROXY_VARS):
            val = os.environ.get(k)
            if not val:
                continue
            m = _LOOPBACK_URL.match(val.strip())
            if not m:
                by_name.append(k)
                continue
            rewritten[k] = self._reach(m)
        for k in _proxy_var_names(_NO_PROXY_VARS):
            if os.environ.get(k):
                by_name.append(k)
        for k in by_name:
            self.args += ["-e", k]    # by name: docker reads the value, so it never shows in ps
        if rewritten:
            import tempfile
            fd, path = tempfile.mkstemp(prefix="detonator-proxy-", suffix=".env")
            self._env_file = path
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                for k, v in rewritten.items():
                    fh.write(f"{k}={v}\n")
            self.args += ["--env-file", path]
            if not self._relays:
                self.args += ["--add-host", f"{DESKTOP_HOST}:host-gateway"]
        ca = next((os.environ[k] for k in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE")
                   if os.environ.get(k) and _readable_file(os.environ[k])), None)
        if ca:
            self.args += ["-v", f"{ca}:/etc/detonator-ca.pem:ro", "-e", "NODE_EXTRA_CA_CERTS=/etc/detonator-ca.pem",
                          "-e", "PIP_CERT=/etc/detonator-ca.pem", "-e", "SSL_CERT_FILE=/etc/detonator-ca.pem"]

    def _reach(self, m) -> str:
        """The same proxy URL, pointed at an address the download container can reach."""
        scheme = m.group("scheme").lower()
        port = int(m.group("port") or _DEFAULT_PORTS.get(scheme, 80))
        if not 0 < port < 65536:
            raise SourceError("your proxy address has an invalid port")
        if _docker_desktop():
            return f"{m.group('scheme')}://{m.group('auth') or ''}{DESKTOP_HOST}:{port}{m.group('rest') or ''}"
        target_host = "::1" if m.group("host") == "[::1]" else (
            "127.0.0.1" if m.group("host").lower() == "localhost" else m.group("host"))
        relay = self._relays.get((target_host, port))
        if relay is None:
            if len(self._relays) >= 4:
                raise SourceError("your proxy settings name too many different local proxies")
            gw, subnet = _bridge()
            try:
                relay = self._relays[(target_host, port)] = _Relay(gw, subnet, (target_host, port))
            except OSError as exc:
                raise SourceError("your proxy runs on this computer (localhost) and Detonator could not "
                                  f"open a relay to it ({type(exc).__name__}); set HTTPS_PROXY to an "
                                  "address that is not localhost, or unset it")
        return f"{m.group('scheme')}://{m.group('auth') or ''}{relay.host}:{relay.port}{m.group('rest') or ''}"

    def __exit__(self, *exc):
        for relay in self._relays.values():
            relay.close()
        self._relays = {}
        if self._env_file:
            try:
                os.unlink(self._env_file)
            except OSError:
                pass
            self._env_file = None
        return False


def _fetch_name() -> str:
    return f"detonator-fetch-{os.getpid()}-{secrets.token_hex(4)}"


def _fetch_user() -> str:
    """Download as you (never root), so the downloaded files are yours and the temporary
    folder can be deleted afterwards. Where there is no such user id, the sandbox user."""
    uid, gid = getattr(os, "getuid", lambda: -1)(), getattr(os, "getgid", lambda: -1)()
    return f"{uid}:{gid}" if uid > 0 and gid >= 0 else "10001:10001"


FETCH_MAX_BYTES = 1024 * 1024 * 1024   # a download bigger than this is stopped


def _fetch_cmd(image: str, work: Path, argv: list, proxy_args: list = (), name: str = "") -> list:
    return ["docker", "run", "--rm", *([f"--name={name}"] if name else []), "--log-driver", "none", "--read-only", "--tmpfs", "/tmp:rw,size=512m,mode=1777",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256",
            "--memory", "1g", "--cpus", "2", "--user", _fetch_user(), "-e", "HOME=/tmp",
            "-e", "npm_config_cache=/tmp/.npm", "-e", "npm_config_update_notifier=false",
            *proxy_args, "-v", f"{work}:/work:rw", "-w", "/work", "--entrypoint", argv[0], image, *argv[1:]]


def _run_fetch(cmd: list, what: str, work: Path | None = None) -> None:
    name = next((a.split("=", 1)[1] for a in cmd if a.startswith("--name=")), "")
    try:
        if work is not None and name:
            # The download writes into a folder on your disk; stop it if it grows too big.
            with tempfile.TemporaryDirectory(prefix="detonator-fetch-") as streams:
                proc, over = runner._run_watched(cmd, FETCH_TIMEOUT_S,
                                                 lambda: runner._run(["docker", "rm", "-f", name], timeout=30),
                                                 [(work, FETCH_MAX_BYTES)], streams=Path(streams))
            if over:
                raise SourceError(f"could not download {what}: it is bigger than "
                                  f"{FETCH_MAX_BYTES // (1024 * 1024)} MB, so the download was stopped")
        else:
            proc = runner._run(cmd, timeout=FETCH_TIMEOUT_S)
    except SourceError:
        raise
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
    with _ProxySetup() as proxy:
        _run_fetch(_fetch_cmd(node_image(), work, [
            # No dependency from a git repo or a web address: npm has to run git (and, for git, a
            # package's prepare step) to get those, outside the sandbox. Registry packages only.
            "npm", "install", "--ignore-scripts", "--allow-git=none", "--allow-remote=none", "--omit=dev",
            "--no-audit", "--no-fund", "--no-package-lock", "--prefix", "/work", "--", spec], proxy,
            _fetch_name()), spec, work)
    return work


def fetch_pypi(plan: Plan, work: Path) -> Path:
    work.mkdir(parents=True, exist_ok=True)
    os.chmod(work, 0o777)
    spec = f"{plan.package}=={plan.version}" if plan.version else plan.package
    # Wheels only: building from a source package runs its code, which must not happen outside the sandbox.
    with _ProxySetup() as proxy:
        _run_fetch(_fetch_cmd(python_image(), work, [
            "python", "-m", "pip", "install", "--only-binary=:all:", "--no-compile", "--no-cache-dir",
            "--disable-pip-version-check", "--target", "/work/site", "--", spec], proxy, _fetch_name()),
            spec + " (only packages published as wheels can be tested)", work)
    return work


def _inside(base: Path, rel: str) -> bool:
    norm = posixpath.normpath(rel)
    return not (norm.startswith("../") or norm == ".." or norm.startswith("/"))


def npm_entry(plan: Plan, work: Path) -> dict:
    pkg_dir = work / "node_modules" / plan.package
    try:
        meta = json.loads(runner.read_plain_file(pkg_dir / "package.json", 2_000_000, inside=work))
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
        for line in runner.read_plain_file(info / "entry_points.txt", 2_000_000, inside=work).splitlines():
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
            meta = json.loads(runner.read_plain_file(pj, 2_000_000, inside=folder))
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


# ---------------------------------------------------------------------------
# Code that is hidden on purpose. Dynamic tests only see code that runs; real npm malware
# often ships a payload that waits for a download, a typo'd script name or a library call
# that never comes in the sandbox. These signs are read from the files, nothing is run.
# ---------------------------------------------------------------------------
OBFUSCATOR_RE = re.compile(r"\b_0x[0-9a-z]{4,8}\b")   # hand-made copies use letters past f too
NUMBER_RUN_RE = re.compile(r"\d{1,3}(?:\s*,\s*\d{1,3})*")   # one pass, no backtracking blow-up


def _long_number_list(text: str, count: int = 2000) -> bool:
    """True when the text holds a comma-separated list of at least `count` small numbers."""
    return any(m.group().count(",") >= count for m in NUMBER_RUN_RE.finditer(text) if len(m.group()) > count)
DECODE_RE = re.compile(r"String\.fromCharCode|\batob\(|Buffer\.from\(")
CODE_SUFFIXES = (".js", ".mjs", ".cjs")
MAX_CODE_BYTES = 16_000_000


def _code_roots(folder: Path, start: str = "") -> list:
    """The server's own code and every package with install scripts, never their dependencies."""
    roots = [folder]
    nm = folder / "node_modules"
    if nm.is_dir():
        for pj in list(nm.glob("*/package.json")) + list(nm.glob("@*/*/package.json")):
            pkg = pj.parent
            rel = pkg.relative_to(folder).as_posix()
            try:
                meta = json.loads(runner.read_plain_file(pj, 2_000_000, inside=folder))
            except (OSError, ValueError):
                continue
            scripts = meta.get("scripts") if isinstance(meta, dict) else None
            if (start and start.startswith(rel + "/")) or (
                    isinstance(scripts, dict) and any(scripts.get(k) for k in INSTALL_SCRIPTS)):
                roots.append(pkg)
    return roots


def hidden_code(folder: Path, start: str = "", limit: int = 4000) -> list:
    """Files that look obfuscated on purpose: javascript-obfuscator names (_0x1a2b), or code
    decoded from a long list of numbers and run. Minified bundles alone do not count."""
    found, seen = [], 0
    for root in _code_roots(Path(folder), start):
        for path in root.rglob("*"):
            rel_parts = path.relative_to(root).parts
            if "node_modules" in rel_parts[:-1] or path.suffix not in CODE_SUFFIXES or path.is_symlink():
                continue
            seen += 1
            if seen > limit:
                return found
            try:
                if path.stat().st_size > MAX_CODE_BYTES:
                    continue
                text = runner.read_plain_file(path, MAX_CODE_BYTES, inside=folder)
            except OSError:
                continue
            names = len(OBFUSCATOR_RE.findall(text, 0, 2_000_000))
            why = ""
            if names >= 200 or (names >= 40 and names * 1024 >= 2 * len(text)):
                why = f"{names} obfuscator names like _0x1a2b"
            elif "eval(" in text and DECODE_RE.search(text) and _long_number_list(text):
                why = "runs code it decodes from a long list of numbers"
            if why:
                found.append(f"{path.relative_to(folder).as_posix()} ({path.stat().st_size // 1024} KB): {why}")
            if len(found) >= 8:
                return found
    return found
