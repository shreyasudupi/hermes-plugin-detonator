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
    from .engine import diff, report, rules, runner, targets

USAGE = targets.USAGE if __package__ else ""
APPROVE, QUICK, CANCEL = "run", "run-quick", "cancel"
# One line each, so people can choose for themselves (no option is pushed as "recommended").
FULL_HELP = ("inside and outside monitors: also catches plugins that hide what they do or fake "
             "a clean result; takes a second or two longer")
QUICK_HELP = ("inside monitor only: a little faster, but a plugin that hides what it does or "
              "fakes its own report can fool it")


def parse_target(raw: str):
    """(repo, sha, subdir) for one run, or (repo, (old_sha, new_sha), subdir) to compare.
    A sha of None means "the newest commit", looked up only after approval."""
    plan = targets.parse(raw)
    return plan.repo, plan.sha, plan.subdir


def _short(sha) -> str:
    return sha[:12] if sha else "newest commit"


def approval_question(repo: str, sha, subdir: str | None, source: str = "") -> str:
    folder = f" ({subdir})" if subdir else ""
    if isinstance(sha, tuple):
        what = source or f"{repo}@{_short(sha[0])} and @{_short(sha[1])}"
        return (
            f"Detonate and compare {what}{folder}? Detonator will git-fetch both exact commits"
            + (" (looking up the newest one first)" if None in sha else "")
            + " and run each plugin version inside its own disposable Docker container with fake "
            "secrets and no real network. Your real Hermes home and keys are never mounted."
        )
    where = repo + (f"@{sha[:12]}" if sha else "") + folder
    if sha is None:
        what = f"the newest commit of {repo}{folder} (on its default branch)"
    else:
        what = f"{where}: {source}" if source else where
    return (
        f"Detonate {what}? Detonator will "
        + ("look up that commit, then " if sha is None else "")
        + "git-fetch that exact commit and run the plugin's code "
        "inside a disposable Docker container with fake secrets and no real network. "
        "Your real Hermes home and keys are never mounted."
    )


def resolve(repo: str, sha):
    """Fill in "newest commit" (None) with a real 40-character SHA. Runs after approval only."""
    if isinstance(sha, tuple):
        return tuple(targets.resolve_latest(repo, runner._run) if s is None else s for s in sha)
    return targets.resolve_latest(repo, runner._run) if sha is None else sha


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


def _report_path(repo: str, tag: str, subdir: str | None) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{repo}@{tag}" + (f"-{subdir}" if subdir else ""))
    return reports_dir() / f"{time.strftime('%Y%m%d-%H%M%S')}-{safe}.md"


def run_detonation(repo: str, sha: str, subdir: str | None, with_raw: bool = False, outside: bool | None = None):
    """Fetch, detonate, judge. Returns (evaluation, markdown, report_path[, raw]).
    outside=False runs the quick test (in-process monitor only)."""
    with tempfile.TemporaryDirectory(prefix="detonator-src-") as work:
        target = runner.fetch_github(repo, sha, Path(work), subdir)
        raw = runner.detonate(target, outside=outside)
    evaluation = rules.evaluate(raw)
    markdown = report.render(target.label, evaluation, raw)
    path = _report_path(repo, sha[:12], subdir)
    path.write_text(markdown, encoding="utf-8")
    _write_summary_json(path, repo, sha, subdir, evaluation)
    return (evaluation, markdown, path, raw) if with_raw else (evaluation, markdown, path)


def _write_summary_json(path: Path, repo: str, sha: str, subdir: str | None, evaluation: dict) -> None:
    """Machine-readable copy of the verdict and findings, read by the detonator_report tool."""
    try:
        import json

        path.with_suffix(".json").write_text(json.dumps({
            "repo": repo, "sha": sha, "subdir": subdir or None,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "verdict": evaluation.get("verdict", "ERROR"),
            "test_mode": report.test_mode(evaluation.get("outside")),
            "not_checked": None if (evaluation.get("outside") or {}).get("ran") else report.NOT_CHECKED,
            "findings": evaluation.get("findings") or [],
            "report_path": str(path),
        }, default=str), encoding="utf-8")
    except Exception:
        pass  # the Markdown report is the record; the JSON copy is a convenience


def run_comparison(repo: str, old_sha: str, new_sha: str, subdir: str | None, outside: bool | None = None) -> str:
    """Detonate both commits, then report what the newer one does that the older did not."""
    old_eval, _, old_path, old_raw = run_detonation(repo, old_sha, subdir, with_raw=True, outside=outside)
    new_eval, _, new_path, new_raw = run_detonation(repo, new_sha, subdir, with_raw=True, outside=outside)
    changes = diff.compare(old_eval, new_eval, old_raw, new_raw)
    label = repo + (f" ({subdir})" if subdir else "")
    path = _report_path(repo, f"{old_sha[:8]}-vs-{new_sha[:8]}", subdir)
    path.write_text(diff.render(label, old_sha, new_sha, changes), encoding="utf-8")
    mode = report.test_mode(new_eval.get("outside"))
    if not (new_eval.get("outside") or {}).get("ran"):
        mode += "\n" + report.NOT_CHECKED
    out = diff.summary(changes, old_sha, new_sha, paths=[path, old_path, new_path])
    return out.replace("\n", f"\n{mode}\n", 1)


def summary(evaluation: dict, path: Path, commit: str | None = None) -> str:
    verdict = evaluation.get("verdict", "ERROR")
    lines = [report.VERDICT_TEXT.get(verdict, verdict), report.test_mode(evaluation.get("outside"))]
    if commit:
        lines.append(f"Tested commit: {commit}")
    if not (evaluation.get("outside") or {}).get("ran"):
        lines.append(report.NOT_CHECKED)
    for f in (evaluation.get("findings") or [])[:6]:
        ids = ", ".join((f.get("attack") or []) + (f.get("atlas") or []))
        lines.append(f"- [{f['severity']}] {f['title']}" + (f" ({ids})" if ids else ""))
        if f["severity"] in ("critical", "high", "medium") and f.get("why"):
            lines.append(f"  Why: {f['why']}")
    lines.append(f"Full report: {path}")
    # Hermes does not pass slash-command output to the model, so the model cannot know a report
    # exists; naming the tool is the wording that works even with small free models.
    lines.append('For a plain-words explanation, ask: "Use the detonator_report tool to explain my latest report"')
    if verdict == "NO_FINDINGS":
        lines.append("Advisory only: a clean run is evidence, not proof.")
    else:
        lines.append("Advisory only: this shows what the plugin did in the sandbox; you decide whether to install it.")
    return "\n".join(lines)


def _docker_problem() -> str | None:
    try:
        return runner.docker_problem()
    except Exception:
        return None  # the run itself reports Docker trouble in detail


def make_slash_handler(ctx):
    def handle(raw_args: str = "", **_kwargs) -> str:
        if (raw_args or "").strip().lower() in ("check", "doctor"):
            # Read-only: `docker info` and `docker image inspect`. Runs no plugin code.
            try:
                return runner.docker_check()
            except Exception as exc:  # never crash the session
                return f"Detonator could not check Docker: {type(exc).__name__}: {exc}"
        try:
            plan = targets.parse(raw_args)
        except ValueError as exc:
            return str(exc)
        repo, sha, subdir = plan.repo, plan.sha, plan.subdir
        # Check Docker before asking, so nobody approves a run that cannot start.
        # Read-only (`docker info`); runs no plugin code.
        problem = _docker_problem()
        if problem:
            return f"Detonator could not run: {problem}"
        choice = ctx.ask_choice(
            approval_question(repo, sha, subdir, plan.source),
            [
                {"value": APPROVE, "label": "Run full test", "description": FULL_HELP},
                {"value": QUICK, "label": "Run quick test", "description": QUICK_HELP},
                {"value": CANCEL, "label": "Cancel"},
            ],
        )
        if choice not in (APPROVE, QUICK):
            return ("Not run: Detonator needs your explicit approval, and none was given "
                    "(cancelled, timed out, or no one could be asked).")
        outside = False if choice == QUICK else None
        try:
            sha = resolve(repo, sha)
            if isinstance(sha, tuple):
                if sha[0] == sha[1]:
                    return f"Nothing to compare: the newest commit of {repo} is the one you have ({sha[0][:12]})."
                return run_comparison(repo, sha[0], sha[1], subdir, outside=outside)
            evaluation, _md, path = run_detonation(repo, sha, subdir, outside=outside)
        except (runner.DetonatorError, LookupError) as exc:
            return f"Detonator could not run: {exc}"
        except Exception as exc:  # never crash the session
            return f"Detonator failed unexpectedly: {type(exc).__name__}: {exc}"
        return summary(evaluation, path, sha)

    return handle


def setup_cli(subparser):
    subparser.add_argument("repo", metavar="target",
                           help="a catalog name, GitHub owner/name or link, or `update <installed-name>`")
    subparser.add_argument("sha", nargs="?", default=None,
                           help="optional full 40-character commit SHA (default: what the catalog pins, "
                                "or the newest commit); after `update`, the installed plugin's name")
    subparser.add_argument("--subdir", help="plugin folder inside the repo")
    subparser.add_argument("--compare-to", dest="compare_to", metavar="NEW_SHA",
                           help="also run this newer commit and report what changed")
    subparser.add_argument("--quick", action="store_true",
                           help="quick test: " + QUICK_HELP + " (default is the full test: " + FULL_HELP + ")")


def cli_handler(args) -> int:
    parts = [args.repo] + ([args.sha] if getattr(args, "sha", None) else []) + ([args.compare_to] if getattr(args, "compare_to", None) else [])
    raw = " ".join(shlex.quote(x) for x in parts + ([args.subdir] if args.subdir else []))
    try:
        plan = targets.parse(raw)
    except ValueError as exc:
        print(str(exc).replace("/detonate", "hermes detonate"), file=sys.stderr)
        return 2
    repo, sha, subdir = plan.repo, plan.sha, plan.subdir
    if not sys.stdin.isatty():
        print("Refusing to run: Detonator needs an interactive yes from you, and stdin is not a terminal.",
              file=sys.stderr)
        return 2
    problem = _docker_problem()
    if problem:
        print(f"Detonator could not run: {problem}", file=sys.stderr)
        return 2
    print(approval_question(repo, sha, subdir, plan.source))
    if getattr(args, "quick", False):
        print("Quick test: " + QUICK_HELP + ". Leave out --quick for the full test.")
    else:
        print("Full test: " + FULL_HELP + ". Add --quick for the quick test.")
    try:
        answer = input("Type 'yes' to run: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer not in ("yes", "y"):
        print("Cancelled.")
        return 1
    outside = False if getattr(args, "quick", False) else None
    try:
        sha = resolve(repo, sha)
        if isinstance(sha, tuple):
            if sha[0] == sha[1]:
                print(f"Nothing to compare: the newest commit of {repo} is the one you have ({sha[0][:12]}).")
                return 0
            print(run_comparison(repo, sha[0], sha[1], subdir, outside=outside))
            return 0
        evaluation, markdown, path = run_detonation(repo, sha, subdir, outside=outside)
    except (runner.DetonatorError, LookupError) as exc:
        print(f"Detonator could not run: {exc}", file=sys.stderr)
        return 2
    print(markdown)
    print(f"\nTested commit: {sha}\nSaved to {path}")
    return {"DANGEROUS": 3, "SUSPICIOUS": 3, "ERROR": 2}.get(evaluation["verdict"], 0)
