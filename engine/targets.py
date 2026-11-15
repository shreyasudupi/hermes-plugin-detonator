"""Turn what a person types into an exact plugin commit to test.

People know a plugin's catalog name or its GitHub page, not commit SHAs. So /detonate also takes:

- a catalog name (`/detonate weather`): the repo, commit and folder the Hermes catalog pins, which
  is exactly what `hermes plugins install <name>` would install. Read from Hermes's own catalog.
- a repo with no commit (`/detonate owner/repo` or a github.com link): its newest commit on the
  default branch, looked up with `git ls-remote` only after the person approves the run.
- `update <name>`: the installed copy of a plugin against what an update would install.

Every run is still on one exact 40-character commit; the report always names it in full.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
GITHUB_URL_RE = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
LATEST = None  # a commit we look up after approval

USAGE = (
    "Usage: /detonate <catalog-name>              (test what `hermes plugins install` would install)\n"
    "   or: /detonate <owner/repo or GitHub link> [subdir]   (its newest commit)\n"
    "   or: /detonate update <installed-name>     (your installed copy vs. what an update would install)\n"
    "   or: /detonate <owner/repo> <40-char-sha> [<newer-sha>] [subdir]   (exact commits)\n"
    "   or: /detonate check                       (is Docker ready? runs nothing)"
)

Sha = Union[str, None, tuple]


@dataclass
class Plan:
    repo: str
    sha: Sha                      # 40-hex, LATEST, or (old, new) where new may be LATEST
    subdir: Optional[str] = None
    source: str = ""              # plain words for the approval question
    notes: list = field(default_factory=list)


def _clean_subdir(subdir: Optional[str]) -> Optional[str]:
    subdir = (subdir or "").strip()
    if subdir.startswith("/"):
        raise ValueError("subdir must be a relative path inside the repo.")
    subdir = subdir.rstrip("/") or None
    if subdir and ( ".." in Path(subdir).parts or "\\" in subdir):
        raise ValueError("subdir must be a relative path inside the repo.")
    return subdir


def github_repo(text: str) -> Optional[str]:
    """owner/name from `owner/name` or a github.com link; None for anything else."""
    text = (text or "").strip()
    m = GITHUB_URL_RE.match(text)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    if REPO_RE.match(text) and not text.startswith(("http:", "https:")):
        return text[:-4] if text.endswith(".git") else text
    return None


def catalog_entry(name: str):
    """The Hermes catalog entry for `name`, the same lookup `hermes plugins install <name>` uses.
    Returns None when Hermes or the entry is not available."""
    try:
        from hermes_cli import plugin_catalog  # Hermes's own catalog reader
    except Exception:
        return None
    for getter in ("get_live_catalog_entry", "get_catalog_entry"):
        fn = getattr(plugin_catalog, getter, None)
        if fn is None:
            continue
        try:
            entry = fn(name)
        except Exception:
            entry = None
        if entry is not None:
            return entry
    return None


def _entry_target(entry) -> tuple[str, str, Optional[str]]:
    repo = github_repo(getattr(entry, "repo", ""))
    sha = str(getattr(entry, "sha", "")).lower()
    if not repo or not SHA_RE.match(sha):
        raise ValueError(f"The catalog entry for {entry.name} is not a GitHub repo at an exact commit, "
                         "so Detonator cannot fetch it.")
    return repo, sha, _clean_subdir(getattr(entry, "subdir", "") or None)


def hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home  # public Hermes helper
        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes"))


def _read_small(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def installed_commit(plugin_dir: Path) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """(sha, repo, catalog_name) of an installed plugin, read from files only (no git command).
    The checked-out commit in .git wins; Hermes's install record fills in the rest."""
    record = {}
    try:
        record = json.loads(_read_small(plugin_dir / ".hermes-catalog.json") or "{}")
    except ValueError:
        record = {}
    sha = None
    head = _read_small(plugin_dir / ".git" / "HEAD").strip()
    if SHA_RE.match(head.lower()):
        sha = head.lower()
    elif head.startswith("ref: "):
        ref = head[5:].strip()
        if re.match(r"^refs/[A-Za-z0-9_./-]+$", ref) and ".." not in ref:
            sha = _read_small(plugin_dir / ".git" / ref).strip().lower() or None
            if not sha:
                for line in _read_small(plugin_dir / ".git" / "packed-refs").splitlines():
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == ref:
                        sha = parts[0].lower()
    if not (sha and SHA_RE.match(sha)):
        rec_sha = str(record.get("sha") or "").lower()
        sha = rec_sha if SHA_RE.match(rec_sha) else None
    repo = github_repo(str(record.get("repo") or "")) if record else None
    if not repo:
        for line in _read_small(plugin_dir / ".git" / "config").splitlines():
            line = line.strip()
            if line.startswith("url = "):
                repo = github_repo(line[6:].strip())
                if repo:
                    break
    name = str(record.get("catalog_name") or "") or None
    return sha, repo, name


def plan_update(name: str) -> Plan:
    if not NAME_RE.match(name or ""):
        raise ValueError("Give the installed plugin's name, as `hermes plugins list` shows it.")
    plugin_dir = hermes_home() / "plugins" / name
    if not plugin_dir.is_dir() or plugin_dir.is_symlink():
        raise ValueError(f"No installed plugin called {name} (looked in {plugin_dir}). "
                         "`hermes plugins list` shows the names.")
    old, repo, cat_name = installed_commit(plugin_dir)
    if not old or not repo:
        raise ValueError(f"Could not tell which GitHub commit of {name} is installed. "
                         "Use /detonate <owner/repo> <old-sha> <new-sha> instead.")
    entry = catalog_entry(cat_name or name)
    if entry is not None and github_repo(entry.repo) == repo:
        _, new, subdir = _entry_target(entry)
        where = "the version the Hermes catalog now pins (what `hermes plugins update` installs)"
    else:
        new, subdir = LATEST, None
        where = "the newest commit on its default branch"
    if new == old:
        raise ValueError(f"{name} is already at {old[:12]}, the version an update would install, so there "
                         f"is nothing newer to compare. To test the installed version: /detonate {name}")
    return Plan(repo, (old, new), subdir, source=f"your installed {name} (@{old[:12]}) against {where}")


def parse(raw: str) -> Plan:
    parts = shlex.split(raw or "")
    if not parts:
        raise ValueError(USAGE)
    if parts[0].lower() == "update":
        if len(parts) != 2:
            raise ValueError("Usage: /detonate update <installed-name>")
        return plan_update(parts[1].lower())

    repo = github_repo(parts[0])
    if repo is None:
        name = parts[0].lower()
        if len(parts) > 1 or not NAME_RE.match(name):
            raise ValueError(USAGE)
        entry = catalog_entry(name)
        if entry is None:
            raise ValueError(f"Your Hermes catalog has no plugin called {name}. If it was added recently, "
                             "run `hermes update` (Hermes from before Nov 9, 2026 cannot read the online "
                             "catalog, so it misses newer plugins). `hermes plugins search <word>` finds "
                             "catalog names. Or test it by its GitHub page: /detonate <owner/repo>.")
        repo, sha, subdir = _entry_target(entry)
        return Plan(repo, sha, subdir, source=f"{name} from the Hermes catalog, the exact commit "
                                                f"`hermes plugins install {name}` installs")

    rest = parts[1:]
    shas = []
    while rest and SHA_RE.match(rest[0].lower()):
        shas.append(rest.pop(0).lower())
    if len(shas) > 2 or len(rest) > 1:
        raise ValueError(USAGE)
    if rest and re.fullmatch(r"[0-9a-fA-F]{7,39}", rest[0]):
        raise ValueError("Give the full 40-character commit SHA (short SHAs are not accepted), "
                         f"or leave it out to test the newest commit: /detonate {repo}")
    subdir = _clean_subdir(rest[0] if rest else None)
    if len(shas) == 2:
        if shas[0] == shas[1]:
            raise ValueError("The two commits are the same; give an older and a newer SHA to compare.")
        return Plan(repo, (shas[0], shas[1]), subdir)
    if shas:
        return Plan(repo, shas[0], subdir)
    return Plan(repo, LATEST, subdir, source=f"the newest commit of {repo} on its default branch")


def resolve_latest(repo: str, run) -> str:
    """The commit the default branch points at now, via `git ls-remote` (reads refs only, runs no code)."""
    url = f"https://github.com/{repo}.git"
    proc = run(["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
                "ls-remote", url, "HEAD"], timeout=60)
    if proc.returncode == 0:
        for line in (proc.stdout or "").splitlines():
            sha = line.split()[0].lower() if line.split() else ""
            if SHA_RE.match(sha):
                return sha
    raise LookupError(f"Could not find the newest commit of {repo} (is the repo public and spelled right?). "
                      + ((proc.stderr or "").strip()[-200:]))
