"""Skills: check a Hermes skill before you install or trust it (/detonate-skill).

A skill is a folder with a SKILL.md (instructions for the agent) and optional scripts. The agent
reads SKILL.md and follows it, usually by running the commands it shows through its terminal tool,
and runs the skill's scripts the same way. Hermes's own skill scanner reads the files; this checks
them in three layers:

  1. text: the instructions themselves (engine/skill_text.py), read on the host, never run,
  2. scripts: every script the skill ships runs in the sandbox, watched by the outside monitor,
  3. commands: every shell block in SKILL.md runs on its own in the sandbox, as the agent would.

Layers 2 and 3 use the same disposable container, tracer and fake internet as /detonate-mcp
(engine/runner.py, engine/outside.py), in an image with everyday command-line tools
(sandbox/Dockerfile.skill). No AI model is involved: plain-English instructions are only judged by
layer 1, and the report says what each layer covered.

Disclosure (catalog rule 13): same Docker commands as engine/runner.py; nothing from the skill runs
on the host. GitHub downloads use the same hook-free `git` fetch as /detonate.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import mcp, report, rules, runner, targets
from . import skill_text as text
from .rules import CRITICAL, HIGH, INFO, LOW, MEDIUM, Finding

MAX_BLOCKS = 24
MAX_SCRIPTS = 10
MAX_BLOCK_CHARS = 4000
INTERPRETERS = {".py": ["python3"], ".js": ["node"], ".mjs": ["node"], ".cjs": ["node"], ".ts": ["node"],
                ".sh": ["bash"], ".bash": ["bash"], ".zsh": ["bash"], ".command": ["bash"]}
VERDICT_LOW_COVERAGE = "LOW_COVERAGE"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
GITHUB_RE = re.compile(r"^(?:https?://github\.com/)?([A-Za-z0-9][\w.-]*/[\w.-]+?)(?:\.git)?"
                       r"(?:/(?:tree/[0-9a-f]{40}/)?([\w./ -]+?))?/?@([0-9a-f]{40})$")


class SkillError(Exception):
    pass


@dataclass
class SkillTarget:
    path: Path
    label: str
    source: str = "folder"
    sha: str | None = None
    notes: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Finding the skill
# ---------------------------------------------------------------------------
def skill_roots() -> list[Path]:
    """Where Hermes keeps skills, newest docs first: the skills folder, its hub quarantine, and
    the project folders it may trust (current directory)."""
    home = targets.hermes_home()
    roots = [home / "skills", home / "skills" / ".hub" / "quarantine"]
    cwd = Path.cwd()
    roots += [cwd / ".hermes" / "skills", cwd / ".agents" / "skills"]
    return [r for r in roots if r.is_dir()]


def find_installed(name: str) -> list[Path]:
    """Skill folders whose folder name or front-matter name is `name`. Only reads SKILL.md files."""
    if not _NAME_RE.match(name):
        return []
    found = []
    for root in skill_roots():
        for md in sorted(root.rglob(text.SKILL_FILE))[:5000]:
            if md.is_symlink() or not md.is_file():
                continue
            folder = md.parent
            if folder.name == name:
                found.append(folder)
                continue
            try:
                head = md.read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                continue
            m = re.search(r"^name:\s*['\"]?([^'\"\n]+?)['\"]?\s*$", head, re.M)
            if m and m.group(1).strip() == name:
                found.append(folder)
    return list(dict.fromkeys(found))


def check_skill_folder(path: Path, where: str) -> None:
    if text.find_skill_file(path) is None:
        inner = sorted(p.parent for p in path.glob("*/" + text.SKILL_FILE))[:5]
        hint = (" It has skills inside: " + ", ".join(p.name for p in inner) + ". Name one of those folders.") \
            if inner else ""
        raise SkillError(f"no SKILL.md in {where}, so it is not a skill.{hint}")


def resolve(spec: str, work: Path) -> SkillTarget:
    """A local folder, an installed skill's name, or owner/repo[/folder]@<40-char sha> on GitHub."""
    spec = (spec or "").strip()
    p = Path(os.path.expanduser(spec))
    if spec and p.is_dir():
        p = p.resolve()
        check_skill_folder(p, str(p))
        return SkillTarget(path=p, label=str(p))
    m = GITHUB_RE.match(spec)
    if m:
        repo, sub, sha = m.group(1), (m.group(2) or "").strip("/") or None, m.group(3)
        t = runner.fetch_github(repo, sha, work, sub, check=lambda path, where: check_skill_folder(path, where))
        return SkillTarget(path=t.path, label=f"{repo}{'/' + sub if sub else ''}@{sha[:12]}", source="github", sha=sha)
    if "/" in spec or "@" in spec:
        raise SkillError("for a skill on GitHub, use owner/repo/folder@<full 40-character commit SHA> "
                         "(the SHA pins exactly what is tested)")
    found = find_installed(spec)
    if not found:
        raise SkillError(f"no installed skill called '{spec}' in your Hermes skills folder, and no folder by that "
                         "name here. Give a folder, an installed skill's name, or owner/repo/folder@<sha>.")
    if len(found) > 1:
        raise SkillError(f"more than one skill is called '{spec}': " + ", ".join(str(f) for f in found[:5])
                         + ". Give the folder instead.")
    return SkillTarget(path=found[0], label=f"installed skill {spec}", source="installed")


# ---------------------------------------------------------------------------
# Planning what to run (layers 2 and 3)
# ---------------------------------------------------------------------------
_DIR_VARS = re.compile(r"\$\{?(?:SKILL_DIR|CLAUDE_SKILL_DIR|SKILL_ROOT|SKILL_PATH|BASE_DIR)\}?|\{baseDir\}|\{skill_dir\}|"
                       r"\{SKILL_DIR\}|<skill[-_ ]?dir(?:ectory)?>|~/\.(?:claude|codex|openclaw|hermes|agents)/skills/"
                       r"(?:[\w.-]+/)*?(?=[\w.-]+/(?:scripts|references|templates|assets|bin)/)", re.I)
_ANGLE = re.compile(r"<([A-Za-z][\w ./:-]{0,40})>")
_YOUR = re.compile(r"\b(?:YOUR|MY)_[A-Z0-9_]{2,40}\b|\b(?:your|my)-[a-z0-9-]{2,30}\b|\bxxx+\b|\bsk-\.\.\.")
_PATH_TO = re.compile(r"(?:/?path/to/|/your/)[\w./-]*")


def _sample_for(word: str) -> str:
    w = word.lower()
    for keys, value in ((("pdf",), "report.pdf"), (("csv", "spreadsheet", "sheet"), "data.csv"),
                        (("png", "jpg", "image", "img", "photo", "picture", "screenshot"), "image.png"),
                        (("json",), "data.json"), (("html", "page"), "index.html"), (("py", "python"), "main.py"),
                        (("js", "javascript"), "app.js"), (("md", "markdown", "readme"), "README.md")):
        if any(k in w for k in keys):
            return value
    if any(k in w for k in ("dir", "folder", "repo", "project", "workspace", "path")):
        return "."
    if any(k in w for k in ("file", "doc", "input", "txt", "text", "note")):
        return "notes.txt"
    if any(k in w for k in ("url", "link", "site", "website", "endpoint", "host")):
        return "https://example.com/"
    if any(k in w for k in ("email", "address", "recipient")):
        return "test@example.com"
    if any(k in w for k in ("key", "token", "secret", "password")):
        return "det-test-value"
    if any(k in w for k in ("num", "count", "id", "port", "size", "limit")):
        return "1"
    return "test"


def fill_placeholders(code: str) -> tuple[str, list]:
    """Swap the usual doc placeholders (<file>, YOUR_API_KEY, path/to/x.pdf) for sample values the
    work folder holds, and the skill-folder variables of other agents for Hermes's own."""
    filled = []

    def angle(m):
        filled.append(m.group(0))
        return _sample_for(m.group(1))

    code = _DIR_VARS.sub(lambda m: "${HERMES_SKILL_DIR}" + ("/" if m.group(0).endswith("/") else ""), code)
    code = re.sub(r"\$\{HERMES_SKILL_DIR\}/(?:[\w.-]+/)*?(?=(?:scripts|references|templates|assets|bin)/)",
                  "${HERMES_SKILL_DIR}/", code)
    code = _ANGLE.sub(angle, code)
    code = _PATH_TO.sub(lambda m: (filled.append(m.group(0)), _sample_for(m.group(0)))[1], code)
    code = _YOUR.sub(lambda m: (filled.append(m.group(0)), "det-test-value")[1], code)
    return code, filled


def _console_lines(code: str) -> str:
    """A console/session block: keep only the typed commands (lines starting with $ or >)."""
    lines = code.splitlines()
    typed = [ln for ln in lines if re.match(r"^\s*[$%>] ", ln)]
    if typed:
        return "\n".join(re.sub(r"^\s*[$%>] ", "", ln) for ln in typed)
    return code


def plan_steps(sk: text.Skill) -> tuple[list, list]:
    """(steps, skipped). Each step is {"id", "kind", "label", "code"|"argv", "timeout"}."""
    steps, skipped, seen = [], [], set()
    blocks = list(sk.blocks)
    main = text.find_skill_file(sk.root)
    main_rel = main.relative_to(sk.root).as_posix() if main else text.SKILL_FILE
    blocks.sort(key=lambda b: (b["file"] != main_rel, b["file"], b["line"]))
    for b in blocks:
        if b["lang"] in ("powershell", "ps1", "pwsh", "cmd"):
            skipped.append(f"{b['file']} line {b['line']}: Windows command (PowerShell/cmd), not run on Linux")
            continue
        code = _console_lines(b["code"]) if b["lang"] in ("console", "shell-session", "sh-session", "terminal") \
            else b["code"]
        code = re.sub(r"(?m)^\s*\$ ", "", code)
        code = re.sub(r"(?<![\w-])sudo\s+(?:-\w+\s+)*", "", code)    # no root in the sandbox; try it as the user
        code, filled = fill_placeholders(code)
        if not code.strip() or code.strip() in seen:
            continue
        if len(code) > MAX_BLOCK_CHARS:
            skipped.append(f"{b['file']} line {b['line']}: block too long to run ({len(code)} characters)")
            continue
        if len(steps) >= MAX_BLOCKS:
            skipped.append(f"{b['file']} line {b['line']}: more blocks than the run has time for")
            continue
        seen.add(code.strip())
        first = next((ln.strip() for ln in code.splitlines() if ln.strip() and not ln.strip().startswith("#")), "")
        steps.append({"kind": "block", "label": f"{b['file']} line {b['line']}: {text._defang(first, 70)}",
                      "code": code, "filled": filled[:8]})
    for im in sk.inline[:12]:
        code, filled = fill_placeholders(re.sub(r"(?<![\w-])sudo\s+", "", im["code"]))
        if code.strip() in seen or len(steps) >= MAX_BLOCKS:
            continue
        seen.add(code.strip())
        steps.append({"kind": "inline", "label": f"{im['file']}: {text._defang(code, 70)}", "code": code,
                      "filled": filled[:8]})
    mentioned = "\n".join(s.get("code", "") for s in steps)
    for rel in sk.scripts[:MAX_SCRIPTS * 2]:
        ext = posixpath.splitext(rel)[1].lower()
        interp = INTERPRETERS.get(ext)
        head = sk.files.get(rel, "")[:200]
        if not interp and head.startswith("#!"):
            line = head.splitlines()[0]
            interp = ["python3"] if "python" in line else ["node"] if "node" in line else \
                ["bash"] if re.search(r"\b(?:ba|z|da)?sh\b", line) else None
        if not interp:
            skipped.append(f"{rel}: no interpreter in the sandbox for this kind of file")
            continue
        if sum(1 for s in steps if s["kind"] == "script") >= MAX_SCRIPTS * 2:
            skipped.append(f"{rel}: more scripts than the run has time for")
            continue
        path = "${HERMES_SKILL_DIR}/" + rel
        # The examples in SKILL.md already run as blocks; run each script on its own too, so code
        # that SKILL.md never shows still runs.
        for args in ([], ["--help"]):
            argv_text = " ".join(interp + [f'"{path}"'] + args)
            steps.append({"kind": "script", "label": f"{rel}{' ' + ' '.join(args) if args else ''}",
                          "code": argv_text, "script": rel, "in_blocks": posixpath.basename(rel) in mentioned})
    for i, s in enumerate(steps):
        s["id"] = i
    return steps, skipped


def make_plan(sk: text.Skill) -> dict:
    steps, skipped = plan_steps(sk)
    name = re.sub(r"[^A-Za-z0-9._-]", "-", sk.name or sk.root.name)[:80].strip(".-") or "skill"
    return {"name": name, "declared_env": text.declared_env(sk), "steps": steps, "planned_skips": skipped}


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------
def detonate(target: SkillTarget, text_only: bool = False) -> dict:
    """Read the skill (layer 1) and, unless text_only, run its scripts and commands (layers 2 and 3)."""
    sk = text.read_skill(target.path)
    raw = {"mode": "skill", "skill": text.summary(sk), "text_findings": [f.to_dict() for f in text.text_findings(sk)],
           "mentioned_hosts": sorted(text.mentioned_hosts(sk))[:200], "text_only": text_only}
    plan = make_plan(sk)
    raw["plan"] = {"steps": [{**{k: v for k, v in s.items() if k != "code"},
                              **({"code": s["code"][:2000]} if s.get("code") else {})} for s in plan["steps"]],
                   "planned_skips": plan["planned_skips"]}
    if text_only:
        raw["outside"] = {"ran": False, "chosen_off": True, "reason": "text-only check chosen (nothing was run)"}
        return raw
    if not plan["steps"]:
        raw["outside"] = {"ran": False, "reason": "the skill has no scripts or commands to run"}
        raw["nothing_to_run"] = True
        return raw
    run_target = runner.Target(path=target.path, label=target.label)
    result = runner.detonate(run_target, outside=True, skill_plan=plan)
    raw.update({k: v for k, v in result.items() if k not in raw})
    raw["outside"] = result.get("outside")
    return raw


# ---------------------------------------------------------------------------
# Judging
# ---------------------------------------------------------------------------
# A package tool reading its own login file is how it works on every machine (npm sends its
# registry token to its registry, pip and git look in .netrc for the host they contact). Only the
# real program from the image counts: a copy in the home folder or a script named npm does not.
_TOOL_PREFIXES = ("/usr/bin/", "/bin/", "/usr/local/bin/", "/usr/lib/", "/usr/local/lib/")
_PIP = {"pip", "pip3", "pip3.11"}
_OWN_CONFIG = {
    ".npmrc": ({"npm", "npx", "pnpm", "yarn", "corepack", "npm-cli.js", "npx-cli.js"},
               ("registry.npmjs.org", "registry.yarnpkg.com")),
    ".netrc": (_PIP | {"git", "git-remote-https", "git-remote-http"}, ()),
    ".pypirc": (_PIP | {"twine"}, ("pypi.org", "upload.pypi.org", "test.pypi.org")),
    ".git-credentials": ({"git", "git-credential-store", "git-remote-https"}, ()),
    ".config/gh/hosts.yml": ({"gh"}, ()),
    ".docker/config.json": ({"docker"}, ()),
}
_RC_FILES = (".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile", ".zshenv")
_EXPORT_ONLY = text.EXPORT_ONLY
_SETTINGS_RISK = re.compile(r"registry|proxy|https?://|_auth|token|script-shell|ignore-scripts|cafile|strict-ssl", re.I)


def _program(path: str, argv: list) -> str | None:
    if not path.startswith(_TOOL_PREFIXES):
        return None
    base = posixpath.basename(path)
    if re.fullmatch(r"node|python3?(?:\.\d+)?", base):
        if len(argv) > 2 and argv[1] == "-m" and argv[2] == "pip":
            return "pip"
        if len(argv) > 1 and str(argv[1]).startswith(_TOOL_PREFIXES):
            return posixpath.basename(str(argv[1]))
        return None
    return base


def _tool_own_config(raw: dict, out: dict) -> tuple[dict, list]:
    """Take package tools' use of their own settings files out of the trace and the sink before
    judging, and say what was taken. A read of its own login file by the real tool is INFO; the
    tool writing its own settings file is LOW, unless the command changes where it connects or
    what it runs. A key from that file sent anywhere but the tool's own registry stays a leak."""
    trace = out.get("trace") or {}
    events = trace.get("events") or []
    home = str(raw.get("home") or "")
    if not events or not home:
        return out, []
    own = {posixpath.join(home, rel): (rel, progs, hosts) for rel, (progs, hosts) in _OWN_CONFIG.items()}
    rc = {posixpath.join(home, f) for f in _RC_FILES}
    codes = {}
    for st in (raw.get("plan") or {}).get("steps") or []:
        codes[st.get("id")] = st.get("code") or " ".join(st.get("argv") or [])
    phase_code = {str(r.get("phase")): codes.get(r.get("id"), "") for r in raw.get("steps") or []}
    keep_idx, reads, writes, exports = set(), [], [], []
    prog = {}
    start = trace.get("start_index")
    phase = "start"
    for i, e in enumerate(events):
        p = str(e.get("path") or "")
        if e.get("in_harness") and p.startswith(rules._PHASE_PREFIX):
            name = p[len(rules._PHASE_PREFIX):]
            if name.startswith(("mcp-", "skill-")):
                phase = name.split("-", 1)[1]
            continue
        if start is not None and i <= start:
            continue
        if e.get("call") in ("execve", "execveat") and e.get("ok"):
            prog[e.get("proc")] = (_program(p, e.get("argv") or []), [str(a) for a in e.get("argv") or []])
            continue
        if e.get("call") != "openat" or e.get("in_harness"):
            continue
        name, argv = prog.get(e.get("proc"), (None, []))
        if p in own and name in own[p][1]:
            rel = own[p][0]
            if not e.get("write"):
                keep_idx.add(i)
                reads.append(f"{name} read ~/{rel}")
            elif not _SETTINGS_RISK.search(" ".join(argv[1:]).replace(rel, "")):
                keep_idx.add(i)
                writes.append(f"{name} changed ~/{rel}: {' '.join(argv)[:120]}")
        elif p in rc and e.get("write") and _EXPORT_ONLY.match(phase_code.get(phase, "")):
            keep_idx.add(i)
            exports.append(f"~/{posixpath.basename(p)}: {phase_code.get(phase, '').strip()[:140]}")
    findings = []
    if reads:
        findings.append(Finding("skill_tool_own_config", INFO,
                                "Package tools read their own login files (normal on every install)",
                                list(dict.fromkeys(reads))[:8]))
    if writes:
        findings.append(Finding("skill_tool_own_config", LOW, "Package tools changed their own settings",
                                list(dict.fromkeys(writes))[:8]))
    if exports:
        findings.append(Finding("skill_tool_own_config", LOW,
                                "Added an environment variable to a shell start-up file, as its instructions say",
                                list(dict.fromkeys(exports))[:8]))
    if not keep_idx:
        return out, findings
    canary = str(out.get("canary") or raw.get("canary") or "")
    tokens = {}
    for rel, (_progs, hosts) in _OWN_CONFIG.items():
        tag = {".npmrc": "-npm-0015", ".pypirc": "-0016"}.get(rel)
        if tag and hosts and canary:
            tokens[(f"pypi-{canary}{tag}" if rel == ".pypirc" else f"{canary}{tag}")] = hosts
    sink = out.get("sink") or {}
    tcp = []
    for e in sink.get("tcp") or []:
        host = str(e.get("host") or "").split(":")[0].lower()
        drop = [t for t, hosts in tokens.items() if host in hosts]
        tcp.append({**e, "data": mcp._strip(str(e.get("data") or ""), drop)} if drop else e)
    new = dict(out)
    new["trace"] = {**trace, "events": [e for i, e in enumerate(events) if i not in keep_idx]}
    new["sink"] = {**sink, "tcp": tcp}
    return new, findings


def _step_labels(raw: dict) -> dict:
    labels = {}
    for s in raw.get("steps") or []:
        labels[str(s.get("phase"))] = f"while running {s.get('label')}"
    for s in (raw.get("late") or {}).get("steps") or []:
        labels[str(s.get("phase"))] = f"while running {s.get('label')}, clock moved forward"
    return labels


def coverage(raw: dict) -> dict:
    steps = raw.get("steps") or []
    ok = [s for s in steps if s.get("exit") == 0 and not s.get("not_found")]
    nf = [s for s in steps if s.get("not_found")]
    to = [s for s in steps if s.get("timed_out")]
    failed = [s for s in steps if s not in ok and s not in nf and s not in to]
    real_ok = [s for s in ok if not str(s.get("label", "")).endswith("--help")]
    return {"planned": len((raw.get("plan") or {}).get("steps") or []), "ran": len(steps), "ok": len(ok),
            "not_found": len(nf), "timed_out": len(to), "failed": len(failed),
            "skipped": [*(raw.get("plan") or {}).get("planned_skips", []),
                        *[f"{s.get('label')}: {s.get('why')}" for s in raw.get("skipped_steps") or []]][:20],
            "low": bool(steps) and not real_ok,
            "lines": [f"{'ok' if s in ok else 'not found' if s in nf else 'timed out' if s in to else 'exit ' + str(s.get('exit'))}"
                      f": {s.get('label')}" for s in steps][:40]}


def _marker_hits(out: dict) -> list:
    """Downloaded stand-in scripts that ran (sandbox/monitor/sink.py serves them)."""
    served = [e for e in (out.get("sink") or {}).get("tcp") or [] if e.get("served")]
    markers = {str(e.get("marker")) for e in served if str(e.get("marker") or "").startswith("detonator-fetched-")}
    if not markers:
        return []
    hits = []
    for e in (out.get("trace") or {}).get("events") or []:
        if e.get("in_harness"):
            continue
        blob = str(e.get("path") or "") + " " + " ".join(str(a) for a in e.get("argv") or [])
        if any(m in blob for m in markers):
            hits.append(e)
    if not hits:
        return []
    return served


def _marker_findings(raw: dict, served: list) -> list:
    """How bad running a download is depends on where it came from: a publisher's https install
    script that the skill's own instructions name is how many tools install; a raw address, a paste
    or tunnel site, plain http, or a host the text never names is how droppers work."""
    named = set(raw.get("mentioned_hosts") or [])
    bad, plain, documented = [], [], []
    for e in served:
        host = str(e.get("host") or "").split(":")[0].lower()
        line = f'{rules._safe_name(host, 80)}:{e.get("port")} ({e.get("served")} script)'
        if re.fullmatch(r"[\d.]+", host) or text.PASTE_HOST_RE.search(host) or re.search(text._FREE_HOSTS, host, re.I) \
                or not any(host == h or host.endswith("." + h) for h in named):
            bad.append(line)
        elif e.get("port") == 80 or not e.get("tls_server_name"):
            plain.append(line)
        else:
            documented.append(line)
    out = []
    if bad:
        out.append(Finding("skill_ran_downloaded_code", CRITICAL,
                           "Downloaded a script from an address its instructions hide or a throwaway host, and ran it "
                           "(Detonator's harmless stand-in ran)", bad[:6]))
    if plain:
        out.append(Finding("skill_ran_downloaded_code", HIGH,
                           "Downloaded a script over plain http and ran it (anyone on the network could swap it)",
                           plain[:6]))
    if documented:
        out.append(Finding("skill_ran_downloaded_code", LOW,
                           "Ran an install script from a site its instructions name (check you trust that site)",
                           documented[:6]))
    return out


def _host_named(host: str, named) -> bool:
    return any(host == h or host.endswith("." + h) for h in named)


def _network(raw: dict, out: dict, nets: list) -> list:
    """Declared vs observed: hosts the skill's own text names are expected; others are not."""
    findings = []
    mentioned = set(raw.get("mentioned_hosts") or [])
    named = mentioned | mcp.fake_hosts(raw.get("declared_env"))
    tcp = (out.get("sink") or {}).get("tcp") or []
    seen = {}
    for e in tcp:
        host = str(e.get("host") or "").split(":")[0].lower()
        if host:
            seen.setdefault(host, []).append(e)
    expected, other = [], []
    for host, es in seen.items():
        line = f"{rules._safe_name(host, 80)} ({len(es)} connection{'s' if len(es) > 1 else ''}, " \
               f"{sum(int(x.get('bytes') or 0) for x in es)} bytes sent)"
        (expected if _host_named(host, named) or any(h.endswith("." + host) for h in mentioned)
         else other).append(line)
    if other:
        findings.append(Finding("skill_undeclared_host", MEDIUM,
                                "Contacted hosts the skill never mentions", other[:8]))
    if expected:
        findings.append(Finding("skill_declared_host", INFO, "Contacted hosts its own instructions name",
                                expected[:8]))
    if nets and not tcp:
        findings.append(Finding("skill_undeclared_host", LOW, "Tried to connect to the network",
                                [f"{a} ({label})" for _, label, a in nets][:6]))
    return findings


def evaluate(raw: dict) -> dict:
    raw = raw or {}
    findings = [Finding(**f) for f in raw.get("text_findings") or []]
    out = raw.get("outside") if isinstance(raw.get("outside"), dict) else {}
    summary = rules.outside_summary(raw) if out.get("ran") else out
    cov = coverage(raw)
    flood = rules.disk_flood_finding(raw)
    if flood and not out.get("ran"):
        findings.append(flood)
    if raw.get("fatal") and not out.get("ran"):
        findings.sort(key=lambda f: rules.SEVERITY_ORDER.index(f.severity))
        return {"verdict": rules._verdict(findings) if flood else rules.VERDICT_ERROR,
                "findings": [f.to_dict() for f in findings],
                "detail": str(raw["fatal"])[:2000], "outside": summary, "coverage": cov, "layers": _layers(raw, cov)}
    if out.get("ran"):
        out, own = _tool_own_config(raw, out)
        findings += own
        shaped = {**raw, "mode": "skill", "step_labels": _step_labels(raw)}
        b, _ = mcp._behaviour(shaped, out)
        findings += b
        findings += _network(raw, out, shaped.get("_nets") or [])
        findings += _marker_findings(raw, _marker_hits(out))
        stray = [f"{c} (left by {s.get('label')})" for s in (raw.get("steps") or []) + list(
            (raw.get("late") or {}).get("steps") or []) for c in s.get("left_running") or []]
        if stray:
            findings.append(Finding("skill_left_running", MEDIUM,
                                    "Left a program running in the background after its command ended",
                                    [text._defang(x, 240) for x in stray][:8]))
        canary = str(out.get("canary") or raw.get("canary") or "")
        declared = mcp.fake_keys(canary, [str(n) for n in raw.get("declared_env") or []])
        stripped = dict(out)
        # The hosts its text names, and the fake addresses given to its declared address variables
        # (SIYUAN_URL): where the person's own settings would send it.
        own_hosts = set(raw.get("mentioned_hosts") or []) | mcp.fake_hosts(raw.get("declared_env"))
        # A declared key sent to a host the skill names is how an API skill works; anywhere else it is a leak.
        stripped["sink"] = {**(out.get("sink") or {}), "tcp": [
            {**e, "data": mcp._strip(str(e.get("data") or ""), declared)
             if _host_named(str(e.get("host") or "").split(":")[0].lower(), own_hosts) else e.get("data")}
            for e in (out.get("sink") or {}).get("tcp") or []]}
        stripped["trace"] = {**(out.get("trace") or {}), "start_index": None, "events": [
            {**e, "data": mcp._strip(str(e.get("data") or ""), declared)} for e in (out.get("trace") or {}).get("events") or []]}
        findings += [f for f in rules._outside_findings({**raw, "events": [], "outside": stripped})
                     if f.rule == "secret_sent_out"]
        findings += [f for f in rules._outside_findings({**raw, "events": []})
                     if f.rule in ("result_forged", "monitor_tamper", "log_flood", "disk_flood")]
        collectors = rules.collection_hosts(out)
        if collectors:
            findings.append(Finding("collection_service", HIGH,
                                    "Sent data to a tunnel or data-collection service", collectors[:6]))
    findings = _merge(findings)
    findings = _late_only(raw, findings)
    findings.sort(key=lambda f: rules.SEVERITY_ORDER.index(f.severity))
    verdict = rules._verdict(findings)
    detail = None
    cut_short = raw.get("disk_flood") in ("uncountable", "freespace")
    if raw.get("fatal") and out.get("ran") and (verdict in (rules.VERDICT_NO_FINDINGS, VERDICT_LOW_COVERAGE)
                                                or (cut_short and verdict == rules.VERDICT_REVIEW)):
        verdict = rules.VERDICT_ERROR
        detail = ("The sandbox stopped before the run finished (" + str(raw["fatal"])[:300] + "), so its result "
                  "is incomplete. A skill that floods memory or kills the sandbox ends up here; what the "
                  "outside monitor saw until then is listed below.")
    if verdict in (rules.VERDICT_NO_FINDINGS, rules.VERDICT_REVIEW, VERDICT_LOW_COVERAGE) and not raw.get("text_only") \
            and not raw.get("nothing_to_run") and not out.get("ran"):
        verdict = rules.VERDICT_ERROR
        detail = ("The outside monitor did not run (" + str(out.get("reason") or "unknown reason")[:300] +
                  "), so the skill's scripts and commands were not watched. Only its text was checked. "
                  "Run /detonate check, fix what it reports, and try again.")
    if verdict == rules.VERDICT_NO_FINDINGS and not raw.get("text_only") and not raw.get("nothing_to_run") \
            and cov["low"]:
        verdict = VERDICT_LOW_COVERAGE
    blind = rules.fail_closed_on_blind_tracer({"verdict": verdict, "detail": detail}, raw, "a skill's scripts and commands",
                                              (rules.VERDICT_NO_FINDINGS, rules.VERDICT_REVIEW, VERDICT_LOW_COVERAGE))
    verdict, detail = blind["verdict"], blind["detail"]
    return {"verdict": verdict, "findings": [f.to_dict() for f in findings], "outside": summary,
            **({"detail": detail} if detail else {}), "coverage": cov, "layers": _layers(raw, cov),
            "skill": raw.get("skill") or {}}


def _merge(findings: list) -> list:
    """One finding per rule and title, evidence joined."""
    merged: dict = {}
    for f in findings:
        key = (f.rule, f.title)
        if key in merged:
            m = merged[key]
            m.evidence = list(dict.fromkeys(m.evidence + f.evidence))[:12]
            if rules.SEVERITY_ORDER.index(f.severity) < rules.SEVERITY_ORDER.index(m.severity):
                m.severity = f.severity
        else:
            merged[key] = f
    return list(merged.values())


def _late_only(raw: dict, findings: list) -> list:
    late = [s for s in (raw.get("late") or {}).get("steps") or []]
    if not late:
        return findings
    marks = [f for f in findings if f.severity in (CRITICAL, HIGH, MEDIUM)
             and f.evidence and all("clock moved forward" in str(e) for e in f.evidence)]
    if marks:
        findings.append(Finding("time_triggered", HIGH,
                                "Did new things only after its clock was moved forward (time bomb)",
                                [f"+{(raw.get('late') or {}).get('clock_days')} days: {f.title}" for f in marks][:6]))
    return findings


def _layers(raw: dict, cov: dict) -> list:
    sk = raw.get("skill") or {}
    out = raw.get("outside") if isinstance(raw.get("outside"), dict) else {}
    ran = bool(out.get("ran"))
    blocks = [s for s in (raw.get("plan") or {}).get("steps") or [] if s.get("kind") in ("block", "inline")]
    scripts = [s for s in (raw.get("plan") or {}).get("steps") or [] if s.get("kind") == "script"]
    return [
        f"Text: read {sk.get('files', 0)} file(s), the description and front matter, for planted instructions, "
        "hidden text, download-and-run commands, installer lures and requests for your keys. Plain-English "
        "instructions are only judged here (no AI model followed them).",
        (f"Scripts: ran {len({s.get('script') for s in scripts})} script(s) with no arguments and with --help, "
         "watched by the outside monitor." if scripts and ran else
         "Scripts: none shipped." if not scripts else "Scripts: not run (" + (
             "text-only check" if raw.get("text_only") else "the outside monitor did not start") + ")."),
        (f"Commands: ran {len(blocks)} shell block(s) and inline command(s) from the skill's documents, each on its "
         f"own, as the agent would. {cov['ok']} finished, {cov['not_found']} needed something missing here, "
         f"{cov['timed_out']} timed out, {cov['failed']} failed." if blocks and ran else
         "Commands: the documents show none." if not blocks else "Commands: not run (" + (
             "text-only check" if raw.get("text_only") else "the outside monitor did not start") + ")."),
    ]


CAVEAT = ("This report is advisory evidence, not proof. Detonator did not use an AI model: instructions written as "
          "plain sentences were only read, not followed, and a skill can still talk an agent into things no command "
          "here shows. Scripts and commands ran on Linux; instructions only for macOS or Windows may do more on "
          "those systems. The run was watched from separate containers the skill cannot reach (a tracer and a "
          "fake internet). A clean run does not mean a skill is safe.")

def test_mode(evaluation: dict) -> str:
    out = evaluation.get("outside") or {}
    if out.get("chosen_off"):
        return "Test mode: text only (the skill's files were read; nothing was run)."
    if out.get("ran"):
        return "Test mode: full (text read, scripts and commands run, watched by the outside monitor)."
    return "Test mode: text only (the scripts and commands could not be run: " + str(out.get("reason") or "")[:200] + ")."


LOW_COVERAGE_TEXT = report.VERDICT_TEXT[VERDICT_LOW_COVERAGE]


def _plain(value, limit: int) -> str:
    """One line of report text: no control characters or backticks, links defanged."""
    t = "".join(c if c.isprintable() else " " for c in str(value)).replace("`", "'")
    return text._defang(t, limit)


def render(label: str, evaluation: dict, raw: dict | None = None) -> str:
    raw = raw or {}
    ev = dict(evaluation)
    verdict = ev.get("verdict")
    body = report.render(label, ev, raw)
    body = body.replace("# Detonator report:", "# Detonator skill report:", 1)
    body = body.replace(f"**{report.test_mode(ev.get('outside'))}**", f"**{test_mode(ev)}**", 1)
    body = body.replace(report.CAVEAT, CAVEAT).replace(report.CAVEAT_NO_OUTSIDE, CAVEAT)
    for a, b in (("the plugin's", "the skill's"), ("the plugin", "the skill"), ("a plugin", "a skill")):
        body = body.replace(a, b)
    marker = "## How it was tested"
    cov = ev.get("coverage") or {}
    sk = ev.get("skill") or {}
    extra = ["## What was checked", ""] + [f"- {x}" for x in ev.get("layers") or []] + [""]
    if cov.get("lines"):
        extra += ["Each script and command:", ""] + [f"- `{_plain(x, 160)}`" for x in cov["lines"]] + [""]
    if cov.get("skipped"):
        extra += ["Not run:", ""] + [f"- {_plain(x, 200)}" for x in cov["skipped"]] + [""]
    if sk.get("declared_env"):
        extra += [f"Keys the skill declares (given fake values): {', '.join(sk['declared_env'])}", ""]
    how = ("Disposable Docker container: no real network, read-only root, all capabilities dropped, non-root user, "
           "fake Hermes home with decoy keys, credentials, browser data, wallets, memory and chat history. The skill "
           "was installed where Hermes keeps skills (HERMES_SKILL_DIR set as Hermes sets it) and its commands ran in "
           "a work folder of harmless sample files, with stand-ins for macOS-only commands. A fake internet answered "
           "every address; requests for scripts got a harmless stand-in that only leaves a mark if it is run.")
    if marker in body:
        head, tail = body.split(marker, 1)
        tail = tail.split("\n\n", 2)
        body = head + "\n".join(extra) + "\n" + marker + "\n\n" + how + "\n\n" + (tail[2] if len(tail) > 2 else "")
    return body


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Check a skill folder (developer entry point; no approval prompt).")
    ap.add_argument("skill")
    ap.add_argument("--text-only", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="detonator-skill-") as work:
        target = resolve(args.skill, Path(work))
        raw = detonate(target, text_only=args.text_only)
    ev = evaluate(raw)
    print(json.dumps(ev, indent=1, default=str) if args.json else render(target.label, ev, raw))
    return 0
