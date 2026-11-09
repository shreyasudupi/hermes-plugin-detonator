"""A quick read of the plugin's source, used only to check the dynamic run's coverage.

This is not a second scanner: Hermes's own install scan already reviews source.
It answers one question the sandbox cannot answer by itself: does the code
contain risky abilities (shell, dynamic code, secret paths, start-up locations,
network) that never ran during the detonation? Code that exists but stayed
quiet may be waiting for a date, a keyword or a real API key.

The source is parsed with `ast` on the host and never executed or imported.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 400
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "site-packages", "tests", "test"}
ENTRY = "__init__.py"

SHELL_CALLS = {
    "subprocess": {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"},
    "os": {"system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp",
           "execlpe", "spawnv", "spawnve", "spawnvp", "spawnl", "spawnlp", "posix_spawn", "posix_spawnp"},
    "pty": {"spawn"},
    "asyncio": {"create_subprocess_exec", "create_subprocess_shell"},
}
NETWORK_CALLS = {
    "socket": {"socket", "create_connection", "getaddrinfo"},
    "urllib.request": {"urlopen", "Request", "build_opener"},
    "http.client": {"HTTPConnection", "HTTPSConnection"},
    "requests": {"get", "post", "put", "patch", "delete", "head", "request", "Session"},
    "httpx": {"get", "post", "put", "patch", "delete", "head", "request", "Client", "AsyncClient", "stream"},
    "aiohttp": {"ClientSession", "request"},
    "websockets": {"connect"},
    "websocket": {"create_connection", "WebSocketApp"},
}
DYNAMIC_BUILTINS = {"exec", "eval", "compile"}
DYNAMIC_CALLS = {"marshal": {"loads"}, "pickle": {"loads", "load"}, "importlib": {"import_module"}}
TIME_CALLS = {"datetime": {"now", "today", "utcnow"}, "date": {"today"}, "time": {"time", "localtime", "gmtime"}}

# Credential stores and start-up locations, matched in the plugin's own path-like
# string literals (prose such as docstrings is skipped, see _path_like).
SECRET_RE = re.compile(
    r"\.ssh[/\\]|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws[/\\]credentials|\.netrc\b|\.git-credentials\b|"
    r"\.docker[/\\]config\.json|\.kube[/\\]config|\bgh[/\\]hosts\.yml|\bLogin Data\b|\blogins\.json\b|"
    r"\bkey[34]\.db\b|\.ethereum[/\\]keystore|\.solana[/\\]id\.json|\bwallet\.dat\b|\.hermes[/\\]auth\.json",
    re.IGNORECASE)
PERSIST_RE = re.compile(
    r"Library[/\\]Launch(?:Agents|Daemons)|\.config[/\\](?:autostart|systemd)|\bcrontab\b|"
    r"(?:^|[/\\~])\.(?:bashrc|bash_profile|zshrc|zprofile)\b|\bsitecustomize\.py\b",
    re.IGNORECASE)


def _path_like(text: str) -> bool:
    """A file path or command, not prose: short, one line, at most a couple of spaces."""
    return len(text) < 300 and "\n" not in text and text.count(" ") <= 3


CATEGORIES = ("shell", "dynamic_code", "secret_paths", "persistence", "network")


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str):
        self.rel = rel
        self.aliases: dict[str, str] = {}   # local name -> module path ("sp" -> "subprocess")
        self.hits: dict[str, list[str]] = {c: [] for c in CATEGORIES}
        self.time_checks: list[str] = []
        self.modules: dict[str, set[str]] = {c: set() for c in CATEGORIES}

    def _where(self, node, what):
        return f"{self.rel}:{getattr(node, 'lineno', '?')} {what}"

    def visit_Import(self, node):
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
        self.generic_visit(node)

    def _dotted(self, func) -> str | None:
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if not isinstance(func, ast.Name):
            return None
        head = self.aliases.get(func.id, func.id)
        return ".".join([head] + list(reversed(parts)))

    @staticmethod
    def _match(dotted: str, table: dict) -> str | None:
        mod, _, name = dotted.rpartition(".")
        for module, names in table.items():
            if name in names and (mod == module or mod.endswith("." + module) or
                                  (module == "urllib.request" and mod == "urllib.request")):
                return module
        return None

    def visit_Call(self, node):
        dotted = self._dotted(node.func)
        if dotted:
            if dotted in DYNAMIC_BUILTINS:
                if not (node.args and isinstance(node.args[0], ast.Constant)):
                    self.hits["dynamic_code"].append(self._where(node, f"{dotted}(...)"))
            elif dotted == "__import__" and node.args and not isinstance(node.args[0], ast.Constant):
                self.hits["dynamic_code"].append(self._where(node, "__import__(<computed name>)"))
            for cat, table in (("shell", SHELL_CALLS), ("network", NETWORK_CALLS), ("dynamic_code", DYNAMIC_CALLS)):
                module = self._match(dotted, table)
                if module:
                    if cat == "dynamic_code" and module == "importlib" and node.args and \
                            isinstance(node.args[0], ast.Constant):
                        continue
                    self.hits[cat].append(self._where(node, dotted))
                    self.modules[cat].add(module.split(".")[0])
            if self._match(dotted, TIME_CALLS):
                self.time_checks.append(self._where(node, dotted))
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and _path_like(node.value):
            if SECRET_RE.search(node.value):
                self.hits["secret_paths"].append(self._where(node, _quote(node.value)))
            if PERSIST_RE.search(node.value):
                self.hits["persistence"].append(self._where(node, _quote(node.value)))


def _quote(text: str) -> str:
    text = " ".join(text.split())
    return repr(text if len(text) <= 60 else text[:57] + "...")


def _module_index(files: dict) -> dict:
    """dotted-name suffix -> rel path, so `client`, `pkg.client` and `src.pkg.client` all resolve."""
    index = {}
    for rel in files:
        parts = rel[:-3].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        for k in range(len(parts)):
            index.setdefault(".".join(parts[k:]), rel)
    return index


def _local_imports(rel: str, tree, index: dict) -> set:
    pkg = rel.split("/")[:-1]
    found = set()
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
                mod = ".".join(base + ([node.module] if node.module else []))
                names = [mod] + [f"{mod}.{a.name}" if mod else a.name for a in node.names]
            elif node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
        for name in names:
            name = name.strip(".")
            while name:
                if name in index:
                    found.add(index[name])
                    break
                name = name.rpartition(".")[0]
    return found


def scan(plugin_dir) -> dict:
    """Risky abilities in the code the plugin loads, starting from its __init__.py.

    Files nothing imports (setup scripts, demos, eval harnesses) are left out:
    Hermes never runs them as part of the plugin.
    """
    root = Path(plugin_dir)
    files = {}
    for path in sorted(root.rglob("*.py")):
        rel_parts = path.relative_to(root).parts
        if any(p in SKIP_DIRS for p in rel_parts[:-1]) or path.stat().st_size > MAX_FILE_BYTES:
            continue
        files["/".join(rel_parts)] = path
        if len(files) >= MAX_FILES:
            break
    trees, unparsed = {}, []
    for rel, path in files.items():
        try:
            trees[rel] = ast.parse(path.read_text(errors="replace"), filename=rel)
        except (SyntaxError, ValueError):
            unparsed.append(rel)
    index = _module_index(trees)
    if ENTRY in trees:
        reachable, todo = set(), [ENTRY]
        while todo:
            rel = todo.pop()
            if rel in reachable:
                continue
            reachable.add(rel)
            todo.extend(_local_imports(rel, trees[rel], index) - reachable)
    else:
        reachable = set(trees)

    hits = {c: [] for c in CATEGORIES}
    modules = {c: set() for c in CATEGORIES}
    time_checks = []
    for rel in sorted(reachable):
        v = _Visitor(rel)
        v.visit(trees[rel])
        for c in CATEGORIES:
            hits[c].extend(v.hits[c])
            modules[c] |= v.modules[c]
        time_checks.extend(v.time_checks)
    return {
        "files": len(reachable),
        "skipped_files": len(trees) - len(reachable),
        "unparsed": unparsed,
        "hits": {c: hits[c][:20] for c in CATEGORIES if hits[c]},
        "modules": {c: sorted(modules[c]) for c in CATEGORIES if modules[c]},
        "time_checks": time_checks[:10],
    }
