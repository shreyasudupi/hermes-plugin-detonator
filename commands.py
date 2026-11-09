"""User-facing entry points: the /detonate slash command and `hermes detonate`.

Every run needs an explicit yes from the person at the keyboard (catalog rule 12):
- /detonate asks with ctx.ask_choice(). When nothing can ask (a cron job, a
  hook, an unattended or non-interactive run) ask_choice returns None and we
  refuse cleanly.
- `hermes detonate` asks on the terminal and refuses when stdin is not a TTY.
There is no flag that skips the question.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
import tempfile
import time
from pathlib import Path

if __package__:
    from .engine import report, rules, runner

USAGE = "Usage: /detonate <owner/repo> <40-char-sha> [subdir]"
APPROVE, CANCEL = "run", "cancel"


def parse_target(raw: str):
    parts = shlex.split(raw or "")
    if len(parts) not in (2, 3):
        raise ValueError(USAGE)
    repo, sha = parts[0], parts[1].lower()
    subdir = parts[2] if len(parts) == 3 else None
    if not runner.REPO_RE.match(repo):
        raise ValueError("The repo must look like owner/name.")
    if not runner.SHA_RE.match(sha):
        raise ValueError("Give the full 40-character commit SHA (branches and short SHAs are not accepted).")
    if subdir and (subdir.startswith("/") or ".." in Path(subdir).parts):
        raise ValueError("subdir must be a relative path inside the repo.")
    return repo, sha, subdir


def approval_question(repo: str, sha: str, subdir: str | None) -> str:
    where = f"{repo}@{sha[:12]}" + (f" ({subdir})" if subdir else "")
    return (
        f"Detonate {where}? Detonator will git-fetch that exact commit and run the plugin's code "
        "inside a disposable Docker container with no network and fake secrets. "
        "Your real Hermes home and keys are never mounted."
    )


def reports_dir() -> Path:
    try:
        from plugins.plugin_storage import plugin_data_dir  # public Hermes surface

        base = Path(plugin_data_dir("detonator"))
    except Exception:
        home = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
        base = Path(home) / "plugin-data" / "detonator"
    path = base / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_detonation(repo: str, sha: str, subdir: str | None):
    """Fetch, detonate, judge. Returns (evaluation, markdown, report_path)."""
    with tempfile.TemporaryDirectory(prefix="detonator-src-") as work:
        target = runner.fetch_github(repo, sha, Path(work), subdir)
        raw = runner.detonate(target)
    evaluation = rules.evaluate(raw)
    markdown = report.render(target.label, evaluation, raw)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{repo}@{sha[:12]}" + (f"-{subdir}" if subdir else ""))
    path = reports_dir() / f"{time.strftime('%Y%m%d-%H%M%S')}-{safe}.md"
    path.write_text(markdown)
    return evaluation, markdown, path


def summary(evaluation: dict, path: Path) -> str:
    verdict = evaluation.get("verdict", "ERROR")
    lines = [report.VERDICT_TEXT.get(verdict, verdict)]
    for f in (evaluation.get("findings") or [])[:6]:
        ids = ", ".join((f.get("attack") or []) + (f.get("atlas") or []))
        lines.append(f"- [{f['severity']}] {f['title']}" + (f" ({ids})" if ids else ""))
        if f["severity"] in ("critical", "high", "medium") and f.get("why"):
            lines.append(f"  Why: {f['why']}")
    lines.append(f"Full report: {path}")
    lines.append("Advisory only: a clean run is evidence, not proof.")
    return "\n".join(lines)


def make_slash_handler(ctx):
    def handle(raw_args: str = "", **_kwargs) -> str:
        try:
            repo, sha, subdir = parse_target(raw_args)
        except ValueError as exc:
            return str(exc)
        choice = ctx.ask_choice(
            approval_question(repo, sha, subdir),
            [
                {"value": APPROVE, "label": "Run in sandbox", "description": "uses Docker"},
                {"value": CANCEL, "label": "Cancel"},
            ],
        )
        if choice != APPROVE:
            return ("Not run: Detonator needs your explicit approval, and none was given "
                    "(cancelled, timed out, or no one could be asked).")
        try:
            evaluation, _md, path = run_detonation(repo, sha, subdir)
        except runner.DetonatorError as exc:
            return f"Detonator could not run: {exc}"
        except Exception as exc:  # never crash the session
            return f"Detonator failed unexpectedly: {type(exc).__name__}: {exc}"
        return summary(evaluation, path)

    return handle


def setup_cli(subparser):
    subparser.add_argument("repo", help="GitHub owner/name of the plugin to test")
    subparser.add_argument("sha", help="full 40-character commit SHA")
    subparser.add_argument("--subdir", help="plugin folder inside the repo")


def cli_handler(args) -> int:
    raw = " ".join(shlex.quote(x) for x in [args.repo, args.sha] + ([args.subdir] if args.subdir else []))
    try:
        repo, sha, subdir = parse_target(raw)
    except ValueError as exc:
        print(str(exc).replace("/detonate", "hermes detonate"), file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("Refusing to run: Detonator needs an interactive yes from you, and stdin is not a terminal.",
              file=sys.stderr)
        return 2
    print(approval_question(repo, sha, subdir))
    try:
        answer = input("Type 'yes' to run: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer != "yes":
        print("Cancelled.")
        return 1
    try:
        evaluation, markdown, path = run_detonation(repo, sha, subdir)
    except runner.DetonatorError as exc:
        print(f"Detonator could not run: {exc}", file=sys.stderr)
        return 2
    print(markdown)
    print(f"\nSaved to {path}")
    return {"DANGEROUS": 3, "SUSPICIOUS": 3, "ERROR": 2}.get(evaluation["verdict"], 0)
