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
    from .engine import diff, mcp, report, rules, runner, skill, targets

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
    lines = [report.verdict_text(evaluation), report.test_mode(evaluation.get("outside"))]
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


# --------------------------------------------------------------------------------------
# MCP servers: /detonate-mcp
# --------------------------------------------------------------------------------------
MCP_HELP = ("inside the sandbox, watched by the outside monitor (a tracer and a fake internet); "
            "takes one to two minutes for most servers (two passes, the second with the clock moved forward)")


def mcp_approval_question(spec: str) -> str:
    return (
        f"Detonate the MCP server '{spec}'? Detonator will read the entry (from a local folder's "
        "mcp-server.yaml, or by that name from your ~/.hermes/config.yaml), download its package in a "
        "locked-down container with install scripts off, then start the server inside a disposable Docker "
        "container with fake secrets and no real network, acting as Hermes: it lists the tools, calls each "
        "one with test input, and watches what the server does. Your real keys are never given to it."
    )


def _mcp_target(spec: str):
    """Resolve the MCP target (reads config / downloads the package). Runs after approval only.
    A config server name and a local folder are both accepted; a folder wins if it exists."""
    p = Path(os.path.expanduser(spec))
    if p.is_dir():
        return mcp.load_folder_entry(str(p)), None
    work = tempfile.mkdtemp(prefix="detonator-mcp-")
    return mcp.load_config_target(spec, Path(work)), work


def run_mcp_detonation(spec: str, outside: bool | None = None) -> str:
    target, work = _mcp_target(spec)
    try:
        raw = mcp.detonate(target, outside=outside)
        evaluation = mcp.evaluate(raw)
        markdown = mcp.render(target.label, evaluation, raw)
        tag = re.sub(r"[^A-Za-z0-9_.-]", "_", target.label)[:60]
        path = reports_dir() / f"{time.strftime('%Y%m%d-%H%M%S')}-mcp-{tag}.md"
        path.write_text(markdown, encoding="utf-8")
        # The detonator_report tool reads the newest summary, so MCP runs write one too.
        _write_summary_json(path, f"MCP server {target.label}"[:300], None, None, evaluation)
    finally:
        if work:
            import shutil
            shutil.rmtree(work, ignore_errors=True)
    text = summary(evaluation, path)
    # The shared summary speaks of plugins; here the thing under test is a server.
    for old, new in (("the plugin's", "the server's"), ("the plugin", "the server"), ("a plugin", "a server")):
        text = text.replace(old, new)
    return text


def make_mcp_slash_handler(ctx):
    def handle(raw_args: str = "", **_kwargs) -> str:
        spec = (raw_args or "").strip()
        if spec.lower().split(" ", 1)[0] in ("", "help"):
            return ("Usage: /detonate-mcp <folder> | <server-name>\n"
                    "  <folder>: a directory with the server's code and an mcp-server.yaml entry\n"
                    "  <server-name>: a server listed under mcp_servers in your ~/.hermes/config.yaml")
        if spec.lower().startswith("config "):
            spec = spec[len("config "):].strip()
        choice = ctx.ask_choice(
            mcp_approval_question(spec),
            [
                # No quick test here: the server is its own process, so only the outside monitor
                # sees what it does; without it a key stealer would come out clean.
                {"value": APPROVE, "label": "Run test", "description": MCP_HELP},
                {"value": CANCEL, "label": "Cancel"},
            ],
        )
        if choice != APPROVE:
            return ("Not run: Detonator needs your explicit approval, and none was given "
                    "(cancelled, timed out, or no one could be asked).")
        try:
            return run_mcp_detonation(spec)
        except mcp.McpError as exc:
            return f"Detonator could not run: {exc}"
        except (runner.DetonatorError, LookupError) as exc:
            return f"Detonator could not run: {exc}"
        except Exception as exc:  # never crash the session
            return f"Detonator failed unexpectedly: {type(exc).__name__}: {exc}"

    return handle


def setup_mcp_cli(subparser):
    subparser.add_argument("server", metavar="folder-or-name",
                           help="a folder with mcp-server.yaml, or a server name from ~/.hermes/config.yaml")


def mcp_cli_handler(args) -> int:
    spec = args.server
    if not sys.stdin.isatty():
        print("Refusing to run: Detonator needs an interactive yes from you, and stdin is not a terminal.",
              file=sys.stderr)
        return 2
    print(mcp_approval_question(spec))
    print("Test: " + MCP_HELP)
    try:
        answer = input("Type 'yes' to run: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer not in ("yes", "y"):
        print("Cancelled.")
        return 1
    try:
        print(run_mcp_detonation(spec))
    except mcp.McpError as exc:
        print(f"Detonator could not run: {exc}", file=sys.stderr)
        return 2
    except (runner.DetonatorError, LookupError) as exc:
        print(f"Detonator could not run: {exc}", file=sys.stderr)
        return 2
    return 0


# --------------------------------------------------------------------------------------
# Skills: /detonate-skill
# --------------------------------------------------------------------------------------
TEXT_ONLY = "text-only"
SKILL_FULL_HELP = ("reads the skill, then runs its scripts and the commands its instructions show inside the "
                   "sandbox, watched by the outside monitor; usually under a minute")
SKILL_TEXT_HELP = ("reads the skill's files only and runs nothing: catches planted instructions, hidden text and "
                   "download-and-run commands, but not what the scripts do")
SKILL_USAGE = ("Usage: /detonate-skill <folder> | <installed-skill-name> | <owner/repo/folder@commit-sha>\n"
               "  <folder>: a skill folder with a SKILL.md\n"
               "  <installed-skill-name>: a skill in your Hermes skills folder (copied, never changed)\n"
               "  <owner/repo/folder@sha>: a skill on GitHub at an exact 40-character commit")


def skill_approval_question(spec: str) -> str:
    return (
        f"Detonate the skill '{spec}'? Detonator will read its files (nothing runs on your computer), then copy "
        "it into a disposable Docker container with fake secrets and no real network, install it there as "
        "Hermes would, and run its scripts and the shell commands its instructions tell the agent to run, "
        "each on its own, while a tracer and a fake internet watch from outside. Your real keys and files are "
        "never given to it."
    )


def run_skill_detonation(spec: str, text_only: bool = False):
    work = tempfile.mkdtemp(prefix="detonator-skill-")
    try:
        target = skill.resolve(spec, Path(work))
        raw = skill.detonate(target, text_only=text_only)
        evaluation = skill.evaluate(raw)
        markdown = skill.render(target.label, evaluation, raw)
        tag = re.sub(r"[^A-Za-z0-9_.-]", "_", target.label)[-60:]
        path = reports_dir() / f"{time.strftime('%Y%m%d-%H%M%S')}-skill-{tag}.md"
        path.write_text(markdown, encoding="utf-8")
        _write_summary_json(path, f"skill {target.label}"[:300], target.sha, None, evaluation)
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    return evaluation, markdown, path


def skill_summary(evaluation: dict, path: Path) -> str:
    text = summary(evaluation, path).replace(report.test_mode(evaluation.get("outside")), skill.test_mode(evaluation), 1)
    if (evaluation.get("outside") or {}).get("chosen_off"):
        text = text.replace(report.NOT_CHECKED, "Text-only check: the skill's scripts and commands were not run.")
    layers = evaluation.get("layers") or []
    if layers:
        text = text.replace("Full report:", "Checked:\n" + "\n".join(f"- {x.split(':')[0]}: "
                            f"{x.split(':', 1)[1].strip()[:140]}" for x in layers) + "\nFull report:", 1)
    for a, b in (("the plugin's", "the skill's"), ("the plugin", "the skill"), ("a plugin", "a skill")):
        text = text.replace(a, b)
    return text


def make_skill_slash_handler(ctx):
    def handle(raw_args: str = "", **_kwargs) -> str:
        spec = (raw_args or "").strip()
        if spec.lower() in ("", "help"):
            return SKILL_USAGE
        choice = ctx.ask_choice(
            skill_approval_question(spec),
            [
                {"value": APPROVE, "label": "Run full test", "description": SKILL_FULL_HELP},
                {"value": TEXT_ONLY, "label": "Read the text only", "description": SKILL_TEXT_HELP},
                {"value": CANCEL, "label": "Cancel"},
            ],
        )
        if choice not in (APPROVE, TEXT_ONLY):
            return ("Not run: Detonator needs your explicit approval, and none was given "
                    "(cancelled, timed out, or no one could be asked).")
        try:
            evaluation, _md, path = run_skill_detonation(spec, text_only=choice == TEXT_ONLY)
            return skill_summary(evaluation, path)
        except skill.SkillError as exc:
            return f"Detonator could not run: {exc}"
        except (runner.DetonatorError, LookupError) as exc:
            return f"Detonator could not run: {exc}"
        except Exception as exc:  # never crash the session
            return f"Detonator failed unexpectedly: {type(exc).__name__}: {exc}"

    return handle


def setup_skill_cli(subparser):
    subparser.add_argument("skill", metavar="folder-or-name",
                           help="a skill folder, an installed skill's name, or owner/repo/folder@<commit-sha>")
    subparser.add_argument("--text-only", dest="text_only", action="store_true",
                           help="text-only: " + SKILL_TEXT_HELP)


def skill_cli_handler(args) -> int:
    spec = args.skill
    if not sys.stdin.isatty():
        print("Refusing to run: Detonator needs an interactive yes from you, and stdin is not a terminal.",
              file=sys.stderr)
        return 2
    print(skill_approval_question(spec))
    text_only = bool(getattr(args, "text_only", False))
    print(("Text-only check: " + SKILL_TEXT_HELP) if text_only else ("Full test: " + SKILL_FULL_HELP +
                                                                      ". Add --text-only to read it without running it."))
    try:
        answer = input("Type 'yes' to run: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer not in ("yes", "y"):
        print("Cancelled.")
        return 1
    try:
        evaluation, markdown, path = run_skill_detonation(spec, text_only=text_only)
    except (skill.SkillError, runner.DetonatorError, LookupError) as exc:
        print(f"Detonator could not run: {exc}", file=sys.stderr)
        return 2
    print(markdown)
    print(f"\nSaved to {path}")
    return {"DANGEROUS": 3, "SUSPICIOUS": 3, "ERROR": 2}.get(evaluation["verdict"], 0)


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
