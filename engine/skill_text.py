"""Layer 1 of /detonate-skill: read a skill's text and look for planted instructions.

A Hermes skill is a folder with a SKILL.md (YAML front matter plus instructions for the agent)
and optional scripts/, references/, templates/, assets/ and examples/. The agent reads SKILL.md
and follows it, usually by running the commands it shows through its terminal tool. So what a
skill *tells the agent to do* matters as much as the code it ships.

Everything here reads files as text on the host. Nothing is imported, run or followed.
The rules are deliberately cautious: text alone is evidence of intent, not of behaviour, so most
text findings stay at REVIEW level and only clear signs (hidden instructions, encoded download-
and-run commands, password-protected installers) go higher. What the code really does is
judged by layers 2 and 3 in the sandbox (engine/skill.py).
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from .rules import CRITICAL, HIGH, INFO, LOW, MEDIUM, Finding

SKILL_FILE = "SKILL.md"
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 400
MAX_TOTAL_BYTES = 20_000_000
TEXT_EXT = {".md", ".markdown", ".txt", ".rst", ".yaml", ".yml", ".json", ".toml", ".html", ".htm", ".xml",
            ".csv", ".ini", ".cfg", ".tmpl", ".template", ".j2", ".jinja", ".mdx"}
CODE_EXT = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".psm1",
            ".bat", ".cmd", ".php", ".lua", ".go", ".applescript", ".scpt", ".command"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "site-packages"}
SHELL_LANGS = {"", "bash", "sh", "shell", "zsh", "console", "terminal", "shell-session", "sh-session", "cmd",
               "powershell", "ps1", "pwsh", "fish", "ksh"}

_FRONT_RE = re.compile(r"\A\ufeff?---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.S)
_FENCE_OPEN = re.compile(r"^([ \t]{0,3})(`{3,}|~{3,})[ \t]*([\w+#.-]*)")


def fenced_blocks(text: str):
    """(start offset, end offset, language, code) for each fenced block, in one pass over the lines
    (a regex here was quadratic on thousands of unclosed fences). A block closes at a line holding
    only the same fence character, at least as many times; an unclosed one runs to the end, as in
    CommonMark. Code comes back with Windows line ends turned into plain newlines, so a SKILL.md
    saved on Windows gives the same commands (bash would read a stray carriage return as part of
    the command)."""
    out, pos, open_ = [], 0, None
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if open_ is None:
            m = _FENCE_OPEN.match(line)
            if m and not (m.group(2)[0] == "`" and "`" in line[m.end():]):
                open_ = (pos, m.group(2), m.group(3).lower(), pos + len(line))
        else:
            ch, n = open_[1][0], len(open_[1])
            if stripped and set(stripped) == {ch} and len(stripped) >= n:
                out.append((open_[0], pos + len(line), open_[2], _lf(text[open_[3]:pos])))
                open_ = None
        pos += len(line)
    if open_ is not None:
        out.append((open_[0], len(text), open_[2], _lf(text[open_[3]:])))
    return out


def _lf(code: str) -> str:
    return code.replace("\r\n", "\n")
_INLINE_SHELL_RE = re.compile(r"!`([^`\n]{1,500})`")
_INLINE_CODE_RE = re.compile(r"(?<![!`])`([^`\n]{3,400})`(?!`)")
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)   # reference for the parity test only: slow on repeated "<!--", use _comments()


@dataclass
class Skill:
    root: Path
    name: str = ""
    description: str = ""
    front: dict = field(default_factory=dict)
    front_error: str = ""
    body: str = ""
    files: dict = field(default_factory=dict)       # rel path -> text (text and code files)
    binaries: list = field(default_factory=list)    # rel paths that are not text
    scripts: list = field(default_factory=list)     # rel paths of code files
    skipped: list = field(default_factory=list)     # (rel, why) not read: too big, links, ...
    odd_encoding: list = field(default_factory=list)  # (rel, label) text that is not plain UTF-8
    blocks: list = field(default_factory=list)      # {"file", "lang", "code", "line"} fenced shell blocks
    inline: list = field(default_factory=list)      # {"file", "code"} `inline` commands


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def _yaml(text: str):
    from .runner import _yaml_safe_load

    return _yaml_safe_load(text)


def find_skill_file(folder: Path) -> Path | None:
    p = folder / SKILL_FILE
    if p.is_file() and not p.is_symlink():
        return p
    for alt in ("skill.md", "Skill.md"):
        if (folder / alt).is_file() and not (folder / alt).is_symlink():
            return folder / alt
    return None


def _is_text(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return False
    try:
        data[:65536].decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        return exc.start > 65000     # cut in the middle of a character at the end of the sample


def _decode_odd(data: bytes, must: bool) -> tuple[str, str] | None:
    """Text that is not plain UTF-8: UTF-16 (with or without a byte-order mark), UTF-8 with stray NUL
    bytes, or a one-byte encoding such as Latin-1. The agent may still read such a file, and an
    unusual encoding is also a way to keep text away from scanners, so it is decoded and labelled
    rather than skipped as binary. `must` (SKILL.md) always gives text; other files only when the
    result looks like text."""
    sample = data[:8192]
    cands = []
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        cands.append(("utf-16", "UTF-16"))
    elif len(sample) >= 4:
        even, odd = sample[0::2], sample[1::2]
        if odd.count(0) > len(odd) * 0.3 and even.count(0) < len(even) * 0.05:
            cands.append(("utf-16-le", "UTF-16"))
        elif even.count(0) > len(even) * 0.3 and odd.count(0) < len(odd) * 0.05:
            cands.append(("utf-16-be", "UTF-16"))
    for codec, label in cands:
        text = data.decode(codec, "replace")
        if text.count("\ufffd") < max(4, len(text) // 50):
            return text.lstrip("\ufeff"), label
    stripped = data.replace(b"\x00", b"")
    nul = len(stripped) != len(data)
    try:
        text, label = stripped.decode("utf-8"), "UTF-8 with NUL bytes"
    except UnicodeDecodeError:
        text, label = stripped.decode("latin-1"), "Latin-1 or another one-byte encoding"
        if nul:
            label += ", with NUL bytes"
    if not must:
        bad = sum(1 for c in text[:8192] if (ord(c) < 32 and c not in "\t\r\n\f") or 0x7f <= ord(c) < 0xa0)
        if bad > len(text[:8192]) * 0.02:
            return None
    return text.lstrip("\ufeff"), label


def read_skill(folder: Path) -> Skill:
    """Read the skill folder as text. Symlinks are never followed (one could point at a real
    key file on this computer), and sizes are capped."""
    folder = Path(folder)
    sk = Skill(root=folder)
    total = 0
    # SKILL.md first, then the shallowest files: the cap on files must never skip the instructions.
    for path in sorted(folder.rglob("*"), key=lambda p: (p.name != SKILL_FILE, len(p.parts), str(p))):
        rel = path.relative_to(folder).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(folder).parts[:-1]):
            continue
        if path.is_symlink():
            sk.skipped.append((rel, "symbolic link (not followed)"))
            continue
        if not path.is_file():
            continue
        if len(sk.files) + len(sk.binaries) >= MAX_FILES:
            sk.skipped.append((rel, "too many files"))
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES and total + MAX_FILE_BYTES <= MAX_TOTAL_BYTES:
            # Read the start and the end of a huge file, and say so. SKILL.md is what the agent always
            # reads, so a huge one counts as a reason to look; a long reference document does not.
            with open(path, "rb") as f:
                head = f.read(MAX_FILE_BYTES // 2)
                f.seek(max(size - MAX_FILE_BYTES // 2, len(head)))
                data = head + b"\n" + f.read(MAX_FILE_BYTES // 2)
            sk.skipped.append((rel, f"{'too big' if path.name == SKILL_FILE else 'long'} ({size} bytes), "
                                    "only its start and end were read"))
            size = len(data)
        elif size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
            sk.skipped.append((rel, f"too big ({size} bytes)"))
            continue
        else:
            data = path.read_bytes()
        total += size
        ext = path.suffix.lower()
        if not _is_text(data):
            odd = None
            if path.name == SKILL_FILE or ext in TEXT_EXT or ext in CODE_EXT:
                odd = _decode_odd(data, path.name == SKILL_FILE)
            if odd is None:
                sk.binaries.append(rel)
                continue
            text, label = odd
            sk.odd_encoding.append((rel, label))
        else:
            text = data.decode("utf-8", "replace")
        sk.files[rel] = text
        first = text[:2].startswith("#!")
        if ext in CODE_EXT or first:
            sk.scripts.append(rel)
    skill_file = find_skill_file(folder)
    main = skill_file.relative_to(folder).as_posix() if skill_file else None
    text = sk.files.get(main, "") if main else ""
    m = _FRONT_RE.match(text)
    if m:
        try:
            data = _yaml(m.group(1))
            sk.front = data if isinstance(data, dict) else {}
            if not isinstance(data, dict):
                sk.front_error = "front matter is not a mapping"
        except Exception as exc:
            sk.front_error = f"front matter is not valid YAML: {str(exc)[:200]}"
        sk.body = text[m.end():]
    else:
        sk.body = text
    sk.name = str(sk.front.get("name") or folder.name)[:200]
    sk.description = str(sk.front.get("description") or "")[:5000]
    for rel, t in sk.files.items():
        if posixpath.splitext(rel)[1].lower() in (".md", ".markdown", ".mdx", ".txt", ".rst") or rel == main:
            blocks = fenced_blocks(t)
            for start, _end, lang, code in blocks:
                if lang in SHELL_LANGS and len(sk.blocks) < 2000:
                    sk.blocks.append({"file": rel, "lang": lang or "text", "code": code[:20000],
                                      "line": t.count("\n", 0, start) + 1})
            parts, last = [], 0
            for start, end, _lang, _code in blocks:
                parts.append(t[last:start])
                last = end
            no_fences = "".join(parts) + t[last:]
            for im in _INLINE_CODE_RE.finditer(no_fences):
                code = im.group(1).strip()
                if _looks_command(code):
                    sk.inline.append({"file": rel, "code": code})
    return sk


_CMD_START = re.compile(r"^(?:sudo\s+)?(?:\$\s*)?(?:curl|wget|bash|sh|zsh|python3?|node|npx|npm|pnpm|yarn|bun|deno|"
                        r"pip3?|uv|uvx|pipx|git|brew|apt(?:-get)?|chmod|cd|cp|mv|rm|mkdir|export|echo|cat|tar|unzip|"
                        r"xattr|open|osascript|powershell|pwsh|iwr|irm|Invoke-\w+|base64|eval|source|\./|"
                        r"hermes|docker|go|cargo|make|jq|ssh|scp|nc|ncat|crontab|launchctl|systemctl)\b")


def _looks_command(code: str) -> bool:
    return bool(_CMD_START.match(code.strip())) and len(code.split()) >= 2


def all_text(sk: Skill) -> list[tuple[str, str]]:
    """(where, text) for every text file, plus the description on its own."""
    out = [("description", sk.description)] if sk.description else []
    out += list(sk.files.items())
    return out


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
_FETCH = r"(?:\bcurl|\bwget|\biwr|\birm|Invoke-WebRequest|Invoke-RestMethod)\b"
FETCH_EXEC_RE = re.compile(
    _FETCH + r"[^\n|;&]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|"
    + _FETCH + r"[^\n|;&]{0,300}\|\s*(?:sudo\s+)?(?:(?:python3?|node|perl|ruby)(?:\s+-)?\s*(?:$|[;&|)`\"'])|iex\b|"
    r"Invoke-Expression\b)|"
    r"(?:ba|z)?sh\s+-c\s+[\"']?\$\(\s*" + _FETCH + r"|"
    r"(?:ba|z)?sh\s+<\(\s*" + _FETCH + r"|"
    r"\b(?:iex|Invoke-Expression)\s*\(?\s*(?:\(?\s*New-Object\s+Net\.WebClient\)?\.DownloadString|iwr|irm|Invoke-WebRequest)|"
    + _FETCH + r"[^\n]{0,300}(?:&&|;)\s*(?:sudo\s+)?chmod\s+\+?[0-7]*x[^\n]{0,120}(?:&&|;)\s*(?:\./|/tmp/|~/|\$HOME)",
    re.I)
DECODE_EXEC_RE = re.compile(r"base64\s+(?:-d|-D|--decode)[^\n|]{0,80}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|"
                            r"echo\s+['\"]?([A-Za-z0-9+/=]{24,})['\"]?\s*\|\s*base64\s+(?:-d|-D|--decode)|"
                            r"FromBase64String\(", re.I)
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
PASSWORD_ARCHIVE_RE = re.compile(
    r"(?:password|passcode|pass|pwd|pw)\s*(?:is|:|=|-)?\s*[`\"'*]*[\w@#$!.-]{3,40}[`\"'*]*[^\n]{0,80}"
    r"\.(?:zip|7z|rar)\b|\.(?:zip|7z|rar)\b[^\n]{0,120}(?:password|passcode|archive pass)|"
    r"(?:extract|unzip|open)[^\n]{0,60}(?:with|using)\s+(?:the\s+)?(?:password|pass(?:word)?)\b|"
    r"\.(?:zip|7z|rar)\b[^\n]{0,80}\(\s*(?:extract|unzip|unpack)\s+(?:using|with)\s*:?\s*[`\"']?[\w@#$!.-]{3,40}", re.I)
# Web addresses are capped at 500 characters here and in RELEASE_EXEC_RE and INSTALLER_RE below: without a cap, a file of one address
# repeated with no space made each match scan to the end of the file (time grew with its square).
ARCHIVE_URL_RE = re.compile(r"https?://[^\s)\]'\"<>`]{1,500}?\.(?:zip|7z|rar|tar\.gz|tgz)\b", re.I)
# "Run this command in Terminal" pointing at a page, not at a command written in the skill.
PASTE_RUN_RE = re.compile(r"(?:visit|open|go to|copy|see)[^\n]{0,120}(?:https?://|\]\()[^\n]{0,160}\b(?:execute|run|paste)"
                          r"[^\n]{0,60}\b(?:command|terminal|script|installer)", re.I)
# A tool the skill "needs" that is downloaded from a free web host or a stranger's release page and run.
_FREE_HOSTS = (r"(?:[\w-]+\.)+(?:vercel\.app|netlify\.app|pages\.dev|github\.io|glitch\.me|repl\.co|replit\.app|"
               r"web\.app|firebaseapp\.com|herokuapp\.com|onrender\.com|surge\.sh|framer\.website|"
               r"wixsite\.com|weebly\.com|blogspot\.com|forum|top|xyz|click|shop|online|site|live|icu)(?=[/:\s)\]'\"`]|$)")
PREREQ_RE = re.compile(r"\b(?:must|needs? to|have to|required to|requires?)\b[^\n]{0,40}\b(?:be\s+)?(?:installed|install|"
                       r"download\w*|run(?:ning)?)\b[^\n]{0,40}\b(?:before|first|prior)\b|\bprerequisites?\b", re.I)
DOWNLOAD_FROM_RE = re.compile(r"\b(?:download|install|get|grab)\w*\b[^\n]{0,80}(?:from|at|here|:)?[^\n]{0,40}"
                              r"https?://" + _FREE_HOSTS, re.I)
RELEASE_EXEC_RE = re.compile(r"github\.com/[\w.-]{1,100}/[\w.-]{1,100}/releases/download/[^\s)\]]{1,500}?\.(?:zip|7z|rar|exe|dmg|pkg)\b"
                             r"[^\n]{0,200}\b(?:run|launch|execute|open|double-click)\b[^\n]{0,40}"
                             r"\b(?:executable|exe|installer|app|binary|it)\b", re.I)
INSTALLER_RE = re.compile(r"https?://[^\s)'\"<>`]{1,500}?\.(?:exe|msi|dmg|pkg|scr|apk|jar|app\.zip)\b|"
                          r"spctl\s+--master-disable|Set-MpPreference\s+-Disable", re.I)
PASTE_HOST_RE = re.compile(r"\b(?:glot\.io|pastebin\.com|paste\.ee|hastebin|rentry\.co|ghostbin|"
                           r"transfer\.sh|tmpfiles\.org|catbox\.moe|gofile\.io|bore\.pub|file\.io|temp\.sh|0x0\.st|bit\.ly|tinyurl\.com|is\.gd|t\.co|"
                           r"webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|"
                           r"trycloudflare\.com|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|"
                           r"interact\.sh|oast\.\w+|burpcollaborator\.net|serveo\.net|localtunnel\.me|"
                           r"workers\.dev|duckdns\.org|no-ip\.\w+)", re.I)
RAW_IP_URL_RE = re.compile(r"\b(?:https?|ftp)://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
                           r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)", re.I)
QUARANTINE_RE = re.compile(r"xattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine", re.I)
# Installers honest projects publish (the person can check the host); still reported, at a low level.
KNOWN_INSTALLERS = re.compile(
    r"https?://(?:sh\.rustup\.rs|static\.rust-lang\.org|bun\.sh|deno\.land|get\.docker\.com|astral\.sh|"
    r"install\.python-poetry\.org|pyenv\.run|get\.pnpm\.io|ollama\.com|cli\.github\.com|claude\.ai|"
    r"raw\.githubusercontent\.com/(?:nvm-sh|Homebrew|pnpm|astral-sh|denoland|ohmyzsh|cli|foundry-rs|"
    r"anthropics|openai|NousResearch|nousresearch)/|install\.determinate\.systems|nixos\.org|"
    r"sdk\.cloud\.google\.com|aka\.ms/install-azd|cli\.doppler\.com|fly\.io/install|get\.helm\.sh|"
    r"starship\.rs|mise\.run|tailscale\.com/install|opencode\.ai/install|hermes-agent\.nousresearch\.com|"
    r"foundry\.paradigm\.xyz|get\.volta\.sh|downloads\.1password\.com|cdn\.jsdelivr\.net/gh/[\w-]+/[\w-]+@[\w.]+/)",
    re.I)

_SECRET_PATHS = re.compile(
    r"~?/?\.ssh/(?:id_\w+|authorized_keys|config)?|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials|\.netrc\b|"
    r"\.git-credentials|\.docker/config\.json|\.kube/config|gh/hosts\.yml|\.hermes/\.env\b|\.hermes/auth\.json|"
    r"\bauth\.json\b|\.npmrc\b|\.pypirc\b|keychain|login\.keychain|Login Data|Cookies\b|logins\.json|key[34]\.db|"
    r"wallet\.dat|\.ethereum/keystore|\.solana/id\.json|Exodus|MetaMask|Phantom|seed phrase|mnemonic|"
    r"private key|\.config/gcloud|application_default_credentials|\.azure/|\.claude/\.credentials|"
    r"\.codex/auth\.json|\.openclaw/|\.env\b", re.I)
_STRONG_SECRET = re.compile(r"\.ssh/|id_(?:rsa|ed25519)|\.aws/credentials|\.hermes/\.env|\.hermes/auth\.json|"
                            r"wallet\.dat|keystore|Login Data|logins\.json|keychain|seed phrase|mnemonic|"
                            r"\.git-credentials|\.claude/\.credentials|\.codex/auth\.json", re.I)
_SECRET_ACTION = re.compile(r"\b(?:cat|less|head|tail|read|open|copy|cp|scp|rsync|send|upload|grep|"
                            r"base64|tar|zip|curl|wget|source|steal|collect|harvest|dump|find|ls|"
                            r"glob|walk|extract|print|echo|include|attach|post)\b|open\(|readFile|read_text|"
                            r"Get-Content|\$\(<", re.I)
_WRITE_ACTION = re.compile(r"\b(?:edit|write|writes|append|overwrite|modify|replace|patch|update|add|insert|"
                           r"set|change|sync|install|copy|cp|mv|ln|tee|sed\s+-i|echo)\b|>>?\s*[~/$\"']|\bhermes\s+config\s+set\b",
                           re.I)
_SWITCH = re.compile(r"approvals?\s*[:=]\s*(?:off|false|never|none|yolo)|yolo\s+mode|inline_shell\s*[:=]?\s*true|tirith\s*[:=]\s*false|"
                     r"security\.\w+\s*[:=]\s*(?:false|off)|skills\s+(?:trust|install)[^\n]{0,80}--force", re.I)
_SEND = re.compile(r"\b(?:send|upload|post|exfiltrat\w*|forward|transmit|sync|copy|share|beacon|report)\b"
                   r"[^.\n]{0,80}\b(?:to|into)\b[^.\n]{0,80}(?:https?://|webhook|server|endpoint|discord|telegram|"
                   r"slack|email|gist|pastebin|bucket|\b[\w-]+\.(?:com|net|io|xyz|ru|top|app|dev)\b)", re.I)
_SEND_CMD = re.compile(r"curl\b[^\n]{0,200}(?:-d\s*@|--data(?:-binary|-raw)?\s*[@\"'$]|-F\s*[\"']?\w+=@|-T\s|"
                       r"--upload-file)|wget\b[^\n]{0,200}--post-(?:file|data)|nc\s+[\w.-]+\s+\d+\s*<|"
                       r"Invoke-(?:WebRequest|RestMethod)[^\n]{0,200}-Method\s+Post", re.I)

INJECTION_RE = re.compile(
    r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|other|system|safety)\s+"
    r"(?:instructions?|prompts?|rules?|messages?|guidelines?)|"
    r"\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|system|safety)\b|"
    r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention\s+(?:this|it)\s+to|alert|notify|show|reveal\s+(?:this|it)\s+to)"
    r"\s+(?:the\s+)?(?:user|human|person|operator|owner)\b(?!\s+(?:to|that\s+they|they\s+need))|"
    r"\b(?:do\s+not|don'?t|never)\s+ask\s+(?:the\s+)?(?:user|human|person)\s+(?:for\s+)?(?:permission|confirmation|"
    r"approval|consent)\b|"
    r"\bwithout\s+(?:asking|telling|informing|notifying|alerting|confirming\s+with)\s+(?:the\s+)?"
    r"(?:user|human|person|operator)\b|"
    r"\b(?:silently|secretly|covertly|discreetly)\s+(?:\w+\s+){0,2}(?:run|execute|send|upload|read|copy|install|"
    r"download|collect|delete|exfiltrate|forward)\b|"
    r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|unrestricted|god)\b|"
    r"\bnew\s+system\s+(?:prompt|instructions?)\b|\boverride\s+(?:your|the|all)\s+(?:system|safety|previous)\b|"
    r"\bdo\s+not\s+(?:show|print|display|log)\s+(?:this|the\s+output|output|these)\b",
    re.I)
CATCH_ALL_RE = re.compile(r"\b(?:use|load|invoke|apply|activate|run)\s+(?:this\s+skill\s+)?(?:for|on|before|with)\s+"
                          r"(?:every|all|any)\s+(?:task|request|message|conversation|prompt|question|turn)s?\b|"
                          r"\balways\s+(?:use|load|invoke|run|activate)\s+this\s+skill\b|"
                          r"\b(?:must|should)\s+be\s+(?:used|loaded|invoked)\s+(?:for|on|before)\s+(?:every|all|any)\b",
                          re.I)
_CONFIG_TARGETS = re.compile(
    r"\.hermes/(?:config\.ya?ml|SOUL\.md|memories?/|MEMORY\.md|USER\.md|skills/|plugins/|cron)|\bSOUL\.md\b|"
    r"\bAGENTS\.md\b|\bCLAUDE\.md\b|\.claude/settings|\.codex/config|\.openclaw/openclaw\.json|"
    r"approvals?\s*[:=]\s*(?:off|false|never|none|yolo)|\byolo\s+mode\b|"
    r"skills\.inline_shell\s*[:=]?\s*true|inline_shell:\s*true|hermes\s+(?:config\s+set|skills\s+(?:trust|install)[^\n]{0,80}"
    r"--force)|tirith\s*[:=]\s*false|security\.\w+\s*[:=]\s*(?:false|off)", re.I)
_PERSIST = re.compile(r"\bcrontab\b|/etc/cron|LaunchAgents|LaunchDaemons|launchctl\s+load|systemctl\s+(?:--user\s+)?enable|"
                      r"\.config/systemd|\.config/autostart|(?:>>|tee\s+-a)\s*~?/?[\w/$.{}]*\.(?:bashrc|zshrc|profile|"
                      r"bash_profile|zprofile)\b|authorized_keys|HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion"
                      r"\\\\Run|schtasks\s+/create", re.I)
_AGENT_TOOLS = re.compile(r"\b(?:skill_manage|cronjob_manage|send_message|memory|delegate_task|browser_exec|"
                          r"browser_vault|computer_use|session_search|execute_code)\b", re.I)
_TOOL_ABUSE_VERB = re.compile(r"\b(?:create|write|add|save|install|schedule|send|forward|store|remember|patch|"
                              r"update|edit|overwrite|replace|copy)\b", re.I)
_DESTRUCTIVE = re.compile(r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?(?:/|~/?|\$HOME/?|\$\{HOME\}/?)(?:\s|$|\*|[`'\"])|"
                          r"\bmkfs\.|\bdd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/|:\(\)\s*\{\s*:\|:&\s*\};:|"
                          r"\bshred\s+[^\n]{0,40}(?:~|/home|\$HOME)|Remove-Item\s+[^\n]{0,40}-Recurse[^\n]{0,40}"
                          r"(?:C:\\\\|\$env:USERPROFILE|~)", re.I)
_REVSHELL = re.compile(r"/dev/(?:tcp|udp)/[\w.-]+/\d+|\b(?:nc|ncat|netcat)\b[^\n]{0,40}\s-[a-z]*e\s|"
                       r"socket\.socket\([^\n]{0,200}(?:dup2|pty\.spawn|subprocess)|\bbash\s+-i\s+>&|mkfifo\s+/tmp/",
                       re.I)

_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\u206a-\u206f\ufeff]")
_TAG_RANGE = re.compile("[\U000E0000-\U000E007F]+")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_PRIVATE_USE = re.compile("[\ue000-\uf8ff\U000F0000-\U000FFFFD\U00100000-\U0010FFFD]")
_IMPERATIVE = re.compile(r"\b(?:run|execute|send|upload|read|ignore|curl|wget|install|download|delete|copy|"
                         r"tell|don'?t|never|always|must|secret|key|password|token|ssh|\.env)\b", re.I)


def _defang(text: str, limit: int = 160) -> str:
    """Report-safe form of a quoted line: links cannot be clicked and nothing reads as a live instruction."""
    t = " ".join(str(text).split())
    t = re.sub(r"https?://", lambda m: m.group(0).replace("http", "hxxp"), t, flags=re.I)
    t = re.sub(r"(?<=\w)\.(?=(?:com|net|org|io|ai|dev|app|xyz|ru|cn|top|me|co|sh|site|info|vercel|forum)\b)", "[.]", t)
    t = _ZERO_WIDTH.sub("", _TAG_RANGE.sub("", t))
    return (t[:limit] + "…") if len(t) > limit else t


# How much of a line around a match is looked at. A file of one huge line (a hostile SKILL.md of
# the same phrase repeated) would otherwise make every match search the whole file again.
LINE_WINDOW = 1000


def line_start(text: str, start: int) -> int:
    return max(text.rfind("\n", max(0, start - LINE_WINDOW), start) + 1, start - LINE_WINDOW, 0)


def _line_of(text: str, start: int) -> str:
    """The line that holds position start, cut to LINE_WINDOW characters either side of it."""
    a = line_start(text, start)
    b = text.find("\n", start, start + LINE_WINDOW)
    return text[a:b if b != -1 else min(len(text), start + LINE_WINDOW)]


def _comments(text: str):
    """The bodies of <!-- ... --> comments, in order (as the lazy regex would find them), in one
    pass: an unclosed "<!--" repeated many times must not make every one scan to the end."""
    i = text.find("<!--")
    while i != -1:
        j = text.find("-->", i + 4)
        if j == -1:
            return
        yield text[i + 4:j]
        i = text.find("<!--", j + 3)


# A time budget for the whole text check: it runs on the person's computer, inside Hermes, before any
# sandbox starts. Past it the check stops, says so, and the verdict cannot be clean.
TEXT_BUDGET_S = 30.0


class _OutOfTime(Exception):
    pass


_DEADLINE = threading.local()    # per thread, so two checks at once never share a deadline


def _tick():
    end = getattr(_DEADLINE, "end", None)
    if end is not None and time.monotonic() > end:
        raise _OutOfTime()


def _quoted(line: str, m_text: str) -> bool:
    """The phrase is quoted as an example ("reject phrases like 'ignore previous instructions'")."""
    i = line.find(m_text)
    return i > 0 and line[i - 1] in "\"'“‘`" or bool(re.search(r"\b(?:like|such as|e\.g\.|example|phrases?|"
                                                              r"patterns?|detect\w*|block\w*|reject\w*)\b", line[:max(0, i)], re.I))


_HONEST_GUARD = re.compile(r"\b(?:never|don'?t|do not|must not|should not)\b[^.\n]{0,80}\bwithout\s+(?:asking|confirming|"
                           r"telling|checking)", re.I)


# `echo 'export NAME="value"' >> ~/.zshrc`: sets one plain variable for new shells (an API key, a
# setting). Not persistence, unless the variable changes what runs or where traffic goes.
EXPORT_ONLY = re.compile(r"""^\s*echo\s+(['"])export\s+(?!(?:PATH|LD_\w*|DYLD_\w*|PYTHON\w*|NODE_\w*|PROMPT_COMMAND|BASH_ENV|ENV|PS\d|\w*_PROXY|\w*_proxy|HOME|SHELL|EDITOR|PAGER|GIT_\w*|SSL_\w*|REQUESTS_\w*|CURL_\w*|\w*_BASE_URL|\w*_API_BASE)=)[A-Za-z_][A-Za-z0-9_]*=(?:(?!\1)[^`$;&|()<>\\\n])*\1\s*>>\s*\S+\s*$""")


def _hits(regex, text, where, limit=4):
    out = []
    for m in regex.finditer(text):
        _tick()
        if regex is INJECTION_RE:
            line = _line_of(text, m.start())
            if _quoted(line, m.group(0)) or _HONEST_GUARD.search(line):
                continue
        out.append(f"{where}: {_defang(_line_of(text, m.start()))}")
        if len(out) >= limit:
            break
    return out


def _decode_b64_strings(text: str) -> list[str]:
    out = []
    for m in _B64_RE.finditer(text):
        s = m.group(0)
        if len(s) > 20000:
            continue
        try:
            raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            dec = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if sum(c.isprintable() or c in "\n\t" for c in dec) / max(1, len(dec)) > 0.95:
            out.append(dec)
    return out


def hidden_tag_text(text: str) -> str:
    """Text written in Unicode tag characters (invisible, but models read it)."""
    return "".join(chr(ord(c) - 0xE0000) for run in _TAG_RANGE.findall(text) for c in run
                   if 0x20 <= ord(c) - 0xE0000 < 0x7F)


def _host_of_url(url: str) -> str:
    m = re.match(r"[a-z]+://([^/:?#\s]+)", url, re.I)
    return m.group(1).lower() if m else ""


URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s)'\"<>`\]]+", re.I)


# Package tools a skill tells the agent to run reach their own registries; naming the tool names them.
_IMPLIED_HOSTS = [
    (re.compile(r"\b(?:pip3?|uv\s+pip|pipx|python3?\s+-m\s+pip)\s+install\b"), ("pypi.org", "files.pythonhosted.org")),
    (re.compile(r"\b(?:npm\s+(?:install|i|ci|add|exec|update)|npx|pnpm\s+(?:add|install|dlx)|yarn\s+(?:add|install|dlx)|bunx?\s+(?:add|install)?)\b"),
     ("registry.npmjs.org", "registry.yarnpkg.com")),
]


def mentioned_hosts(sk: Skill) -> set[str]:
    hosts = set()
    for _, t in all_text(sk):
        for m in URL_RE.finditer(t):
            h = _host_of_url(m.group(0))
            if h:
                hosts.add(h)
        for rx, implied in _IMPLIED_HOSTS:
            if rx.search(t):
                hosts.update(implied)
    return hosts


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def text_findings(sk: Skill, budget_s: float | None = None) -> list[Finding]:
    findings: list[Finding] = []
    budget = TEXT_BUDGET_S if budget_s is None else budget_s
    _DEADLINE.end = time.monotonic() + budget
    try:
        return _text_findings(sk, findings)
    except _OutOfTime:
        findings.append(Finding("skill_not_fully_read", HIGH,
                                f"The text check ran out of time ({budget:g} s) and stopped, so the rest of the "
                                "skill's text was not checked", [f"{len(findings)} finding(s) made before it stopped; "
                                "a file built to slow scanners down can hide instructions after that point"]))
        return calibrate(findings)
    finally:
        _DEADLINE.end = None


def _text_findings(sk: Skill, findings: list) -> list[Finding]:
    texts = all_text(sk)
    mds = [(w, t) for w, t in texts if w not in sk.scripts]

    # ---- download and run: the most common real skill attack (fake "prerequisite" installers)
    fetch_known, fetch_other, fetch_bad = [], [], []
    for where, t in texts:
        _tick()
        for m in FETCH_EXEC_RE.finditer(t):
            _tick()
            line = _line_of(t, m.start())
            ev = f"{where}: {_defang(line)}"
            if RAW_IP_URL_RE.search(line) or PASTE_HOST_RE.search(line):
                fetch_bad.append(ev)
            elif re.search(_FREE_HOSTS, line, re.I):
                fetch_bad.append(ev)
            elif re.search(r"\bhttp://", line, re.I) and not re.search(r"http://(?:localhost|127\.|0\.0\.0\.0)", line):
                fetch_other.append(ev)     # plain http: anyone on the network can swap the script
            else:
                fetch_known.append(ev)
    encoded = []
    for where, t in texts:
        _tick()
        for m in DECODE_EXEC_RE.finditer(t):
            _tick()
            encoded.append(f"{where}: {_defang(_line_of(t, m.start()))}")
        for dec in _decode_b64_strings(t):
            if FETCH_EXEC_RE.search(dec) or _REVSHELL.search(dec) or RAW_IP_URL_RE.search(dec):
                encoded.append(f"{where}: hidden in base64: {_defang(dec, 120)}")
    if encoded:
        findings.append(Finding("skill_fetch_exec", CRITICAL,
                                "Tells the agent to decode a hidden command and run it",
                                list(dict.fromkeys(encoded))[:6], attack=["T1140", "T1027.013"]))
    if fetch_bad:
        findings.append(Finding("skill_fetch_exec", HIGH,
                                "Downloads a script from a raw IP address or a paste/tunnel site and runs it",
                                list(dict.fromkeys(fetch_bad))[:6]))
    if fetch_other:
        findings.append(Finding("skill_fetch_exec", MEDIUM,
                                "Downloads a script over plain http (not https) and runs it straight away",
                                list(dict.fromkeys(fetch_other))[:6]))
    if fetch_known:
        findings.append(Finding("skill_fetch_exec", LOW,
                                "Installs a tool by downloading its install script and running it (check you trust the site)",
                                list(dict.fromkeys(fetch_known))[:6]))

    lures, soft_lures = [], []
    for where, t in texts:
        _tick()
        lures += _hits(PASSWORD_ARCHIVE_RE, t, where, 3)
        lures += _hits(INSTALLER_RE, t, where, 3)
        lures += _hits(RELEASE_EXEC_RE, t, where, 3)
        for m in PASTE_RUN_RE.finditer(t):
            _tick()
            line = _line_of(t, m.start())
            if PASTE_HOST_RE.search(line) or RAW_IP_URL_RE.search(line) or re.search(_FREE_HOSTS, line, re.I):
                lures.append(f"{where}: {_defang(line)}")
        for m in ARCHIVE_URL_RE.finditer(t):
            _tick()
            near = t[max(0, m.start() - 400): m.end() + 400]
            if re.search(r"\b(?:password|passcode|passwd|pass)\b|\(\s*extract\s+using", near, re.I) or \
                    re.search(r"\.(?:exe|app|dmg|pkg|msi)\b[^\n]{0,80}|\b(?:run|open|launch|execute)\b[^\n]{0,40}"
                              r"\.(?:exe|app)\b", near, re.I):
                lures.append(f"{where}: {_defang(_line_of(t, m.start()))}")
        if PREREQ_RE.search(t):
            for m in DOWNLOAD_FROM_RE.finditer(t):
                _tick()
                line = _line_of(t, m.start())
                ev = f"{where}: {_defang(line)}"
                (lures if re.search(r"\b(?:windows|mac\s?os|macos|osx|\.exe|\.dmg|installer)\b", line, re.I)
                 else soft_lures).append(ev)
    if lures:
        # Password-protected downloads exist to get past virus scanners; skills have no honest need.
        findings.append(Finding("skill_installer_lure", HIGH,
                                "Asks you or the agent to download and open an installer or password-protected archive",
                                list(dict.fromkeys(lures))[:6]))
    quarantine = []
    for where, t in texts:
        _tick()
        quarantine += _hits(QUARANTINE_RE, t, where, 2)
    if quarantine:
        findings.append(Finding("skill_installer_lure", MEDIUM if lures or soft_lures else LOW,
                                "Removes macOS's download warning (quarantine flag) from a program", quarantine[:4]))
    if soft_lures and not lures:
        findings.append(Finding("skill_installer_lure", MEDIUM,
                                "Says a tool must be installed first, from a free web host instead of a package registry",
                                list(dict.fromkeys(soft_lures))[:6]))

    # ---- planted instructions
    inj_desc = _hits(INJECTION_RE, sk.description, "description")
    inj_body = []
    for where, t in mds:
        _tick()
        inj_body += _hits(INJECTION_RE, t, where, 3)
    if inj_desc:
        findings.append(Finding("skill_instruction_injection", HIGH,
                                "The description (always shown to the model) tries to steer the agent", inj_desc))
    if inj_body:
        findings.append(Finding("skill_instruction_injection", MEDIUM,
                                "Tells the agent to hide what it does, skip approvals or ignore its other instructions",
                                list(dict.fromkeys(inj_body))[:6]))
    catch = _hits(CATCH_ALL_RE, sk.description, "description")
    if catch:
        findings.append(Finding("skill_catch_all", MEDIUM,
                                "Asks to be used for every task, so it is loaded far more often than needed", catch))

    # ---- hidden text
    hidden = []
    for where, t in texts:
        _tick()
        tag = hidden_tag_text(t)
        if tag.strip():
            hidden.append(f"{where}: invisible tag text says: {_defang(tag, 120)}")
        zw = len(_ZERO_WIDTH.findall(t))
        if zw >= 8:
            hidden.append(f"{where}: {zw} zero-width characters")
        if _BIDI.search(t):
            hidden.append(f"{where}: right-to-left override characters (text shows differently from what is read)")
        if len(_PRIVATE_USE.findall(t)) >= 20:
            hidden.append(f"{where}: many private-use characters")
    comment_hits = []
    for where, t in mds:
        _tick()
        for body in _comments(t):
            _tick()
            if len(body) > 20 and _IMPERATIVE.search(body) and (INJECTION_RE.search(body) or FETCH_EXEC_RE.search(body)
                                                                  or _SECRET_PATHS.search(body) or _SEND.search(body)):
                comment_hits.append(f"{where}: hidden comment: {_defang(body, 120)}")
    if hidden:
        tag_instr = any("invisible tag text" in h and _IMPERATIVE.search(h) for h in hidden)
        findings.append(Finding("skill_hidden_text", CRITICAL if tag_instr else HIGH,
                                "Hides text that the model reads but you do not see", hidden[:6]))
    if comment_hits:
        findings.append(Finding("skill_hidden_text", HIGH,
                                "Puts instructions inside a comment that Markdown viewers hide", comment_hits[:6]))

    # ---- secrets and sending data out
    secret_lines, strong = [], False
    for where, t in texts:
        _tick()
        if where.lower().endswith((".json", ".csv")):
            continue
        for m in _SECRET_PATHS.finditer(t):
            _tick()
            line = _line_of(t, m.start())
            if re.search(r"\b(?:never|don'?t|do not|avoid|must not)\b[^.\n]{0,60}(?:commit|share|paste|upload|log|"
                         r"print|expose|read)", line, re.I):
                continue    # advice about keeping secrets safe
            rest = re.match(r"[^\s\"'`)]*", t[m.end():m.end() + 200]).group(0)
            if (m.group(0) + rest).lower().endswith(".pub"):
                continue    # a public key
            pre = t[line_start(t, m.start()):m.start()]
            if not _SECRET_ACTION.search(pre[-80:]):
                continue    # only mentioned (where a token is stored, setup docs), not acted on
            secret_lines.append(f"{where}: {_defang(line)}")
            strong = strong or bool(_STRONG_SECRET.search(m.group(0)))
            break
    cred_files = sk.front.get("required_credential_files") or []
    cred_bad = []
    for c in cred_files if isinstance(cred_files, list) else []:
        p = str(c.get("path") if isinstance(c, dict) else c)
        if _SECRET_PATHS.search(p) and not re.match(r"^[\w.-]*(?:token|credentials?)[\w.-]*\.json$", p, re.I):
            cred_bad.append(f"required_credential_files: {_defang(p)}")
    send = []
    for where, t in texts:
        _tick()
        send += _hits(_SEND, t, where, 2) + _hits(_SEND_CMD, t, where, 2)
    if cred_bad:
        findings.append(Finding("skill_secret_request", HIGH,
                                "Asks Hermes to hand it credential files that hold other keys", cred_bad[:5],
                                atlas=["AML.T0083"]))
    if secret_lines:
        sev = HIGH if strong and send else MEDIUM if strong else LOW
        findings.append(Finding("skill_secret_request", sev,
                                "Points the agent at key, password or wallet files"
                                + (" and tells it to send data out" if send and strong else ""),
                                list(dict.fromkeys(secret_lines))[:6] + (send[:3] if send and strong else []),
                                atlas=["AML.T0083"]))
    if send and not (secret_lines and strong):
        findings.append(Finding("skill_exfil_instruction", MEDIUM if any(PASTE_HOST_RE.search(s) or
                                RAW_IP_URL_RE.search(s.replace("hxxp", "http")) for s in send) else LOW,
                                "Tells the agent to send files or data to an outside address",
                                list(dict.fromkeys(send))[:6]))

    # ---- the agent's own setup, persistence and other tools
    cfg = []
    for where, t in texts:
        _tick()
        for m in _CONFIG_TARGETS.finditer(t):
            _tick()
            line = _line_of(t, m.start())
            if _SWITCH.search(line) or _WRITE_ACTION.search(line):
                cfg.append(f"{where}: {_defang(line)}")
            if len(cfg) >= 6:
                break
    if cfg:
        findings.append(Finding("skill_config_tamper", MEDIUM,
                                "Tells the agent to change its own settings, memory, personality or safety switches",
                                list(dict.fromkeys(cfg))[:6]))
    nosafety = []
    for where, t in texts:
        _tick()
        nosafety += _hits(re.compile(r"--dangerously-skip-permissions|--yolo\b|--dangerously-bypass-approvals", re.I),
                          t, where, 2)
    if nosafety:
        findings.append(Finding("skill_config_tamper", LOW, "Runs another coding agent with its safety checks off",
                                list(dict.fromkeys(nosafety))[:4]))
    persist = []
    for where, t in texts:
        _tick()
        persist += [h for h in _hits(_PERSIST, t, where, 6)
                    if not EXPORT_ONLY.match(h.split(": ", 1)[1] if ": " in h else h)][:3]
    if persist:
        findings.append(Finding("skill_persistence_instruction", MEDIUM,
                                "Tells the agent to add something that starts automatically (cron, login items, shell start-up)",
                                list(dict.fromkeys(persist))[:6]))
    tool_abuse = []
    for where, t in mds:
        _tick()
        for m in _AGENT_TOOLS.finditer(t):
            _tick()
            line = _line_of(t, m.start())
            if _TOOL_ABUSE_VERB.search(line) and (INJECTION_RE.search(line) or _SEND.search(line) or
                                                 _SECRET_PATHS.search(line) or "skill_manage" in line.lower()
                                                 or "cronjob" in line.lower()):
                tool_abuse.append(f"{where}: {_defang(line)}")
    if tool_abuse:
        findings.append(Finding("skill_agent_tool_abuse", MEDIUM,
                                "Tells the agent to use its other tools (messages, memory, cron, new skills) for the skill's own ends",
                                list(dict.fromkeys(tool_abuse))[:6]))
    destructive, revshell = [], []
    for where, t in texts:
        _tick()
        destructive += _hits(_DESTRUCTIVE, t, where, 2)
        revshell += _hits(_REVSHELL, t, where, 2)
    if revshell:
        findings.append(Finding("skill_reverse_shell_text", HIGH,
                                "Contains a reverse-shell command (gives someone remote control of the computer)",
                                list(dict.fromkeys(revshell))[:5]))
    if destructive:
        findings.append(Finding("skill_destructive_text", MEDIUM,
                                "Contains a command that wipes your home folder or disk",
                                list(dict.fromkeys(destructive))[:5]))

    # ---- front matter features
    inline = []
    for where, t in mds:
        _tick()
        inline += [f"{where}: !`{_defang(m.group(1), 100)}`" for m in _INLINE_SHELL_RE.finditer(t)][:4]
    if inline:
        risky = any(FETCH_EXEC_RE.search(x) or _SECRET_PATHS.search(x) or _SEND_CMD.search(x) for x in inline)
        findings.append(Finding("skill_inline_shell", MEDIUM if risky else LOW,
                                "Uses inline !`command` snippets, which run on your computer before the model reads "
                                "the skill (only when skills.inline_shell is on)", inline[:6]))
    meta = sk.front.get("metadata") if isinstance(sk.front.get("metadata"), dict) else {}
    hermes_meta = meta.get("hermes") if isinstance(meta.get("hermes"), dict) else {}
    bp = hermes_meta.get("blueprint") or sk.front.get("blueprint")
    if bp:
        bp_text = str(bp)[:400]
        findings.append(Finding("skill_blueprint_cron", MEDIUM if (FETCH_EXEC_RE.search(bp_text) or
                                                                   _SECRET_PATHS.search(bp_text) or
                                                                   INJECTION_RE.search(bp_text)) else LOW,
                                "Proposes a scheduled job (a cron task that keeps running once you accept it)",
                                [_defang(bp_text, 200)]))
    cfg_items = hermes_meta.get("config") if isinstance(hermes_meta.get("config"), list) else []
    phish = []
    for item in cfg_items:
        if isinstance(item, dict):
            words = " ".join(str(item.get(k) or "") for k in ("key", "description", "prompt"))
            if re.search(r"password|passphrase|private key|seed|mnemonic|api[_ ]?key|secret|token", words, re.I):
                phish.append(f"metadata.hermes.config: {_defang(words, 140)}")
    if phish:
        findings.append(Finding("skill_config_phish", MEDIUM,
                                "Asks for a secret through a plain setting (settings are not stored as secrets)",
                                phish[:4]))
    fallback = [k for k in ("fallback_for_toolsets", "fallback_for_tools") if hermes_meta.get(k)]
    if fallback:
        findings.append(Finding("skill_shadowing", LOW,
                                "Replaces built-in tools when they are missing (fallback_for_*)",
                                [f"{k}: {_defang(str(hermes_meta.get(k)), 120)}" for k in fallback]))

    # ---- packaging
    if sk.binaries:
        risky_bin = [b for b in sk.binaries if posixpath.splitext(b)[1].lower() not in (
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".ttf", ".otf", ".woff", ".woff2",
            ".mp3", ".wav", ".mp4", ".webm", ".pptx", ".docx", ".xlsx", ".pyc")]
        magic = []
        for b in risky_bin:
            try:
                head = (sk.root / b).read_bytes()[:4]
            except OSError:
                continue
            if head[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe") or head[:2] == b"MZ":
                magic.append(f"{b}: a compiled program")
            elif head[:2] == b"PK" or head[:3] == b"7z\xbc" or head[:4] == b"Rar!":
                magic.append(f"{b}: an archive")
        if magic:
            findings.append(Finding("skill_binary", MEDIUM,
                                    "Ships compiled programs or archives that cannot be read", magic[:6]))
    packed = []
    for rel in sk.scripts:
        t = sk.files.get(rel, "")
        lines = t.splitlines() or [""]
        longest = max(len(x) for x in lines)
        decoded_code = [d for d in _decode_b64_strings(t) if re.search(r"\b(?:import|require|exec|eval|curl|bash|"
                                                                      r"subprocess|socket|function)\b", d)]
        if decoded_code:
            packed.append(f"{rel}: code hidden in base64 ({_defang(decoded_code[0], 80)})")
        elif longest > 3000 and len(lines) < 10 and not rel.endswith((".min.js",)):
            packed.append(f"{rel}: packed into very long lines ({longest} characters)")
        elif re.search(r"\b(?:eval|exec)\s*\(\s*(?:atob|base64\.b64decode|zlib\.decompress|bytes\.fromhex|"
                       r"codecs\.decode|Buffer\.from)\b|String\.fromCharCode\((?:\s*\d+\s*,){20,}", t):
            packed.append(f"{rel}: decodes and runs hidden code")
    if packed:
        findings.append(Finding("skill_packed_script", MEDIUM, "Ships scripts that are packed or encoded to hide "
                                "what they do", packed[:6]))
    mentioned = " ".join(t for w, t in mds)
    unlisted = [s for s in sk.scripts if posixpath.basename(s) not in mentioned and s not in mentioned]
    if unlisted:
        findings.append(Finding("skill_unlisted_script", INFO,
                                "Ships scripts that SKILL.md never mentions",
                                unlisted[:8] + ([f"and {len(unlisted) - 8} more"] if len(unlisted) > 8 else [])))
    disguised = [s for s in sk.scripts if posixpath.splitext(s)[1].lower() in TEXT_EXT]
    if disguised:
        findings.append(Finding("skill_disguised_code", MEDIUM,
                                "Has code files named like documents", disguised[:6]))
    unread = [f"{r} ({why})" for r, why in sk.skipped if "link" not in why and not why.startswith("long")]
    partly = [f"{r} ({why})" for r, why in sk.skipped if why.startswith("long")]
    if unread:
        findings.append(Finding("skill_not_fully_read", MEDIUM,
                                "Some files were too big or too many to read in full (padding can hide text)",
                                unread[:6] + ([f"and {len(unread) - 6} more"] if len(unread) > 6 else [])))
    if partly:
        findings.append(Finding("skill_not_fully_read", INFO, "Long documents were read only at their start and end",
                                partly[:6]))
    if sk.odd_encoding:
        main = [f"{r} ({lab})" for r, lab in sk.odd_encoding if posixpath.basename(r) == SKILL_FILE]
        rest = [f"{r} ({lab})" for r, lab in sk.odd_encoding if posixpath.basename(r) != SKILL_FILE]
        if main:
            findings.append(Finding("skill_odd_encoding", MEDIUM,
                                    "SKILL.md is not plain UTF-8 text (read anyway; an odd encoding can hide "
                                    "text from scanners)", main + rest[:5]))
        else:
            findings.append(Finding("skill_odd_encoding", LOW, "Some files are not plain UTF-8 text (read anyway)",
                                    rest[:6] + ([f"and {len(rest) - 6} more"] if len(rest) > 6 else [])))
    if sk.skipped:
        links = [f"{r} ({why})" for r, why in sk.skipped if "link" in why]
        if links:
            findings.append(Finding("skill_symlink", MEDIUM,
                                    "Contains links to files outside the skill (not followed)", links[:6]))
    return calibrate(findings)


# Things honest skills also do (set up cron, edit config, read a token file, use other tools).
# On their own they are listed at LOW; next to a clear sign of attack they count fully.
CONTEXT_RULES = {"skill_config_tamper", "skill_persistence_instruction", "skill_agent_tool_abuse",
                 "skill_destructive_text", "skill_secret_request", "skill_instruction_injection",
                 "skill_exfil_instruction", "skill_disguised_code", "skill_binary"}
CLEAR_SIGNS = {"skill_fetch_exec", "skill_installer_lure", "skill_hidden_text", "skill_reverse_shell_text",
               "skill_secret_request", "skill_instruction_injection", "skill_exfil_instruction"}


def calibrate(findings: list) -> list:
    clear = any(f.rule in CLEAR_SIGNS and f.severity in (HIGH, CRITICAL) for f in findings)
    if clear:
        return findings
    for f in findings:
        if f.rule in CONTEXT_RULES and f.severity == MEDIUM and not f.title.startswith("The description"):
            f.severity = LOW
            f.title += " (on its own this is common in honest skills)"
    return findings


def summary(sk: Skill) -> dict:
    return {"name": sk.name, "description": _defang(sk.description, 300), "files": len(sk.files) + len(sk.binaries),
            "scripts": sk.scripts[:50], "code_blocks": len(sk.blocks), "inline_commands": len(sk.inline),
            "front_error": sk.front_error,
            "declared_env": declared_env(sk), "skipped": [f"{r}: {w}" for r, w in sk.skipped][:20]}


def declared_env(sk: Skill) -> list[str]:
    out = []
    for item in sk.front.get("required_environment_variables") or []:
        name = item.get("name") if isinstance(item, dict) else item
        if isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,80}", name):
            out.append(name)
    meta = sk.front.get("metadata") if isinstance(sk.front.get("metadata"), dict) else {}
    for key in ("openclaw", "clawdbot", "clawdis"):     # other agents' skill formats name env needs here
        oc = meta.get(key) if isinstance(meta.get(key), dict) else {}
        req = oc.get("requires") if isinstance(oc.get("requires"), dict) else {}
        for name in req.get("env") or []:
            if isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,80}", name):
                out.append(name)
    return sorted(set(out))[:30]


def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text)
