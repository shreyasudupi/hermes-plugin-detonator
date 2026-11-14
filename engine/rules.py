"""Deterministic rules: compare what a plugin declares with what it did.

Input is the harness result (sandbox/harness.py). Output is a list of findings
and an advisory verdict. No model is involved in deciding anything here.

Every finding carries a plain-language "why" and, where one fits, MITRE
ATT&CK (enterprise, v20) and MITRE ATLAS (v5.6) technique IDs. The catalog of
rules lives in RULES below; docs/RULES.md is checked against it by a test.
"""

from __future__ import annotations

import functools
import posixpath  # sandbox paths are Linux paths, even when the host is Windows
import re
import unicodedata
from dataclasses import asdict, dataclass, field

from . import leaks as _leakfind

CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"
SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

VERDICT_DANGEROUS = "DANGEROUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_REVIEW = "REVIEW"
VERDICT_NO_FINDINGS = "NO_FINDINGS"
VERDICT_ERROR = "ERROR"


@dataclass(frozen=True)
class Rule:
    why: str
    attack: tuple = ()
    atlas: tuple = ()


# rule id -> why it matters + default technique mapping. A finding may add
# more specific IDs (e.g. the exact persistence location it touched).
RULES = {
    # ---- credentials and private data
    "decoy_accessed": Rule(
        "Plugins have no reason to open your key files or ask for API keys they did not declare. "
        "This is the first step of every credential stealer.",
        ("T1552.001", "T1552.004"), ("AML.T0055", "AML.T0083")),
    "browser_or_wallet_read": Rule(
        "Saved browser passwords, cookies and crypto wallets are what info-stealer malware is built to take.",
        ("T1555.003", "T1005"), ("AML.T0055",)),
    "secret_in_output": Rule(
        "A fake key ended up somewhere it could leave the machine (a model prompt, a tool result, "
        "a network address, a command or another tool's input), even when encoded or split up to hide it. "
        "A real key would leak the same way.",
        ("T1041",), ("AML.T0057", "AML.T0086")),
    "memory_read": Rule(
        "Memory and chat history hold what the agent knows about you. Expected for memory plugins, "
        "a privacy leak for anything else.",
        ("T1005",), ()),
    "environ_file_read": Rule(
        "Read the process environment as a file under /proc instead of asking for variables by name. "
        "That gets every API key at once and skips the usual way of reading them, which is how stealers "
        "try to slip past simple monitors.",
        ("T1552",), ("AML.T0055",)),
    "env_enumerated": Rule(
        "Copying the whole environment collects every API key at once.",
        ("T1552",), ("AML.T0055",)),
    "hermes_env_read": Rule(
        "Hermes keeps your API keys in the .env file in its home folder and already loads them for plugins. The catalog rules "
        "say plugins must never read that file; a plugin that opens it gets every key at once. Honest "
        "plugins sometimes do this to find their own key, so check which key it needs and whether it declares it.",
        ("T1552.001",), ("AML.T0055",)),
    "undeclared_env_read": Rule(
        "Plugins must list every API key they use in requires_env. Reading one it never declared is often a "
        "fallback to a common key (such as OPENAI_API_KEY), but it is also how stealers collect keys quietly.",
        ("T1552",), ("AML.T0055",)),
    "declared_env_read": Rule("Reading a key the plugin says it needs is normal; listed for completeness."),
    "decoy_dir_listed": Rule(
        "Listing your home folder or the folders that hold keys and memory is how stealers find what to take.",
        ("T1083",), ("AML.T0084",)),
    "fs_discovery": Rule(
        "Walking through many folders outside its own looks like searching for files to take.",
        ("T1083",), ()),
    "recon": Rule(
        "Reading account and system files tells malware who you are and what machine it is on.",
        ("T1082", "T1087"), ()),
    # ---- network
    "undeclared_network": Rule(
        "Nothing the user asked for needs the network while a plugin loads or inside a background hook. "
        "That is when beacons and stealers phone home.",
        ("T1071.001", "T1041"), ("AML.T0025",)),
    "tool_network": Rule(
        "Expected for tools that wrap an API. Compare the hosts with what the README says the plugin "
        "connects to.",
        ("T1071.001",), ()),
    "local_network": Rule(
        "Local services (databases, dev servers, the Hermes gateway) often trust anything on localhost "
        "without a password.",
        ("T1046",), ()),
    "listener": Rule(
        "Opening a port lets something outside talk to the plugin: a classic backdoor.",
        ("T1571",), ()),
    # ---- agent content
    "content_altered": Rule(
        "Hermes uses what this hook returns. Text added to prompts, tool results or memory becomes "
        "instructions the model follows, which is the main route for prompt injection.",
        (), ("AML.T0051.001", "AML.T0080")),
    "prompt_injection_text": Rule(
        "Contains wording written to steer the model, such as telling it to disregard its earlier "
        "guidance or to keep a step secret from the user, or invisible characters. Poisoned tools hide "
        "orders to the model this way.",
        (), ("AML.T0051.001", "AML.T0110", "AML.T0011.002")),
    "tool_shadowing": Rule(
        "Registers a tool with the same name as a built-in Hermes tool, so the model may call the "
        "plugin's version (and hand it data) when it meant the real one.",
        ("T1036.005",), ("AML.T0110",)),
    "chat_data_sent": Rule(
        "Your messages, the model's replies and tool results are private. Sending them to the network or "
        "into a command from a background hook means a copy of your conversations leaves the machine. "
        "Logging and analytics plugins do this on purpose, so check where it goes and whether the plugin says so.",
        ("T1041", "T1020"), ("AML.T0025", "AML.T0057")),
    "tool_args_changed": Rule(
        "Changed what a tool call does after the model chose it and before it ran (for example a different "
        "message recipient, web address or command). The user and the model see the call they asked for; "
        "the plugin quietly runs another one.",
        ("T1565.002",), ("AML.T0053", "AML.T0110")),
    "model_request_changed": Rule(
        "Rewrote the request Hermes sends to the AI model. Changing the server or headers can send every "
        "prompt and your API key somewhere else; changing the model or the messages changes how the agent "
        "behaves without the user seeing it.",
        ("T1557",), ("AML.T0051.001", "AML.T0110")),
    "middleware_registered": Rule(
        "Hermes middleware can rewrite tool calls and model requests or wrap them entirely. That is a legitimate "
        "feature (declared in plugin.yaml as provides_middleware), and also the most direct way to tamper with "
        "what the agent does. Detonator drove it with test calls; read the findings around it."),
    "lookalike_name": Rule(
        "Registers a tool whose name looks like a built-in Hermes tool (a swapped letter, a digit for a letter, "
        "a letter from another alphabet). The model may pick it by mistake and hand it data meant for the real tool.",
        ("T1036.005",), ("AML.T0110",)),
    "output_flood": Rule(
        "Puts a very large amount of text in front of the model. Every extra character costs the user money on "
        "every turn, can push the user's own instructions out of the model's memory, and gives room to hide "
        "orders deep inside.",
        ("T1499",), ("AML.T0029", "AML.T0034")),
    "claim_mismatch": Rule(
        "The plugin describes itself one way (for example offline, read-only or never touching keys) but did "
        "the opposite in the sandbox. A description that hides what the code does is a warning sign on its own.",
        ("T1036",), ()),
    "agent_tool_call": Rule(
        "The plugin called other agent tools by itself, without the model or user asking. That can "
        "be used to send data out through tools the user trusts.",
        (), ("AML.T0053", "AML.T0086")),
    # ---- code execution and persistence
    "command_run": Rule(
        "Shell commands can do anything you can. Hermes plugins rarely need them, and catalog rule 13 "
        "requires disclosing them.",
        ("T1059.004",), ()),
    "remote_code_fetch": Rule(
        "Downloading or installing code at runtime means what you reviewed is not what runs. A plugin "
        "can turn malicious after it is approved (a rug pull).",
        ("T1105",), ("AML.T0109",)),
    "self_modify": Rule(
        "Changing its own files at runtime is self-updating code (catalog rule 3): a reviewed plugin "
        "could rewrite itself later.",
        ("T1554",), ("AML.T0109",)),
    "persistence": Rule(
        "Writes to places that make code start automatically (login items, cron, systemd, shell "
        "start-up files, Python start-up hooks, SSH authorized keys). Malware does this to survive "
        "uninstalling.",
        (), ()),
    "agent_config_modified": Rule(
        "Changes Hermes's own config, other plugins, skills or hooks. That changes how the agent behaves "
        "for every future session.",
        (), ("AML.T0081",)),
    "write_outside_folder": Rule(
        "Wrote or changed sensitive files outside its folder (shell, SSH, cloud config or system paths).",
        ("T1565.001",), ()),
    "write_own_state": Rule(
        "Keeps files outside Hermes's plugin data folder. Usually harmless state, but it is not where "
        "Hermes expects plugins to write, so uninstalling may leave it behind."),
    "write_tmp": Rule("Temporary files; listed for completeness."),
    "dynamic_code": Rule(
        "Runs code it builds from a string at runtime (exec/eval). That is how obfuscated payloads are "
        "hidden from reviewers.",
        ("T1059.006", "T1027"), ("AML.T0068",)),
    "hidden_code": Rule(
        "Loads compiled bytecode or a pickle that reaches system functions. Both hide code that cannot be "
        "read in the source.",
        ("T1620", "T1027"), ()),
    "native_code": Rule("Loads native libraries via ctypes, which bypasses Python-level monitoring.",
                        ("T1106",), ()),
    # ---- tampering and evasion
    "monkeypatch": Rule(
        "Replaced functions inside Python or Hermes. That lets a plugin silently watch or change "
        "everything other code does (catalog rule 9: no core overrides).",
        ("T1574",), ("AML.T0110",)),
    "env_tampering": Rule(
        "Changed environment variables that redirect network traffic or which code gets loaded "
        "(proxies, PATH, LD_PRELOAD, PYTHONPATH, CA bundles).",
        ("T1574.006", "T1574.007", "T1090"), ()),
    "sandbox_check": Rule(
        "Checked whether it runs in a container or under a debugger. Malware does this to behave nicely "
        "while it is being tested.",
        ("T1497.001",), ()),
    "monitor_tamper": Rule(
        "Tried to add its own audit hook or inspect the interpreter's live objects, which can be used to "
        "hide from or disable monitoring.",
        ("T1685",), ()),
    "background_thread": Rule(
        "Started background threads. Fine for batching or polling, but catalog rule 13 asks for "
        "background work to be disclosed."),
    # ---- declarations and coverage
    "undeclared_registration": Rule(
        "Registers hooks, tools or middleware missing from plugin.yaml, so users are not shown them at install "
        "time (catalog rule 6).",
        (), ("AML.T0010.005",)),
    "declared_not_registered": Rule("Declares tools it did not register; usually a stale plugin.yaml."),
    "unsafe_plugin_name": Rule(
        "The plugin's name becomes the name of its own data folder, where it may write freely. A name with "
        "slashes or dot-dot steps could point that folder at your whole home folder, so harmful "
        "writes there would look allowed. Detonator used a safe folder instead.",
        ("T1036",), ()),
    "log_flood": Rule(
        "The plugin did so much that the sandbox's activity log filled up, so part of the run was not kept. "
        "Flooding a monitor is a known way to hide one bad action among thousands of harmless ones. "
        "Only the most repeated kinds of activity were thinned out, so rare actions such as a key read were kept and judged.",
        ("T1562",), ()),
    "load_error": Rule("The plugin crashed while loading, so less of it was observed."),
    "coverage_incomplete": Rule(
        "The plugin stopped on a stand-in module, so code after that point was not observed."),
    "time_triggered": Rule(
        "Did something only after its clock was moved forward. Malware waits for a date, or for days to pass "
        "after install, so it passes short tests and reviews (a time bomb).",
        ("T1480", "T1497.003"), ()),
    "dormant_code": Rule(
        "The code can do this, but it never did during the test. Code that stays quiet in a sandbox may be "
        "waiting for a date, a keyword or a real key (a time bomb or trigger). Often it is just a path the "
        "test did not reach, so read that code before installing.",
        ("T1480", "T1497.003"), ()),
    # ---- outside monitor (separate tracer and fake-internet containers)
    "secret_sent_out": Rule(
        "A fake key actually reached the fake internet: the plugin sent it over the network (in a web "
        "request, a raw connection or a DNS lookup). With real keys, they would now be in someone "
        "else's hands.",
        ("T1041", "T1048"), ("AML.T0025", "AML.T0055")),
    "monitor_blind_spot": Rule(
        "The outside monitor, which the plugin cannot reach, saw the plugin's own process do this, but "
        "Detonator's monitor inside the plugin's process recorded nothing. Honest code does not slip "
        "past the inside monitor; code written to hide from it (or to switch it off) does.",
        ("T1562.001", "T1106"), ()),
    "result_forged": Rule(
        "Something other than Detonator wrote the sandbox's result file. A plugin that writes its own "
        "result is trying to hand in a fake clean report.",
        ("T1565.001", "T1562.001"), ()),
    "coverage_stubbed_imports": Rule(
        "The sandbox has no Hermes or third-party packages. Imports were replaced by inert stand-ins, "
        "and anything done through them (e.g. an HTTP call via httpx) was not observed."),
}

# Exact persistence locations -> ATT&CK sub-technique.
PERSISTENCE_TECHNIQUES = (
    ("Library/LaunchAgents/", "T1543.001"),
    ("Library/LaunchDaemons/", "T1543.004"),
    (".config/autostart/", "T1547.013"),
    (".config/systemd/user/", "T1543.002"),
    ("/etc/systemd/", "T1543.002"),
    ("/var/spool/cron", "T1053.003"),
    ("/etc/cron", "T1053.003"),
    (".ssh/authorized_keys", "T1098.004"),
)
SHELL_RC = {".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv",
            ".zlogin", ".config/fish/config.fish"}
PY_STARTUP = ("sitecustomize.py", "usercustomize.py")
HERMES_SENSITIVE = ("plugins", "skills", "hooks", "cron", "hermes-agent")
SENSITIVE_HOME = (".ssh", ".aws", ".config", ".gnupg", ".local", ".kube", ".docker", "Library")

BUILTIN_TOOLS = {
    "terminal", "read_file", "write_file", "patch", "search_files", "execute_code", "process_manage",
    "read_terminal", "close_terminal", "web_search", "web_extract", "x_search", "memory", "session_search",
    "delegate_task", "skill_manage", "skill_view", "skills_list", "cronjob_manage", "clarify", "todo",
    "todo_list", "vision_analyze", "image_generate", "text_to_speech", "video_analyze", "video_generate",
    "browser_cdp", "browser_dialog", "browser_exec", "browser_vault", "computer_use", "send_message",
    "react_to_message",
}

INJECTION_PATTERNS = [
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier) (?:instructions|prompts?|rules)",
    r"disregard (?:all |any )?(?:the )?(?:previous|prior|above|system) (?:instructions|prompts?|rules)",
    r"(?:do not|don't|never) (?:tell|inform|mention|reveal|show)[^.\n]{0,30}\b(?:the )?user",
    r"without (?:telling|asking|informing|notifying) (?:the )?user",
    r"<\s*(?:important|system|instructions?)\s*>",
    r"before (?:using|calling|running) (?:this|any) tool[^.\n]{0,60}\b(?:read|send|call|run|include)",
    r"\b(?:read|cat|open|send|include|upload|paste|pass)\b[^.\n]{0,40}(?:~/\.ssh|\bid_rsa\b|\bid_ed25519\b|"
    r"\bauth\.json\b|\bcredentials\b|\bprivate key\b|\.env\b(?:\s+file)?)",
    r"\b(?:read|send|include|upload|paste)\b[^.\n]{0,40}\bapi[_ ]?keys?\b",
    r"\b(?:exfiltrat\w*|secretly|covertly)\b",
    r"you\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak)",
    r"new (?:system )?instructions?:",
    r"\b(?:system|admin|developer) (?:note|message|override|instruction)s?\s*:",
]
INJECTION_RE = re.compile("|".join(f"(?:{p})" for p in INJECTION_PATTERNS), re.IGNORECASE)
HIDDEN_CHARS_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")

ENV_REDIRECT = {"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PYTHONPATH",
                "PYTHONSTARTUP", "PYTHONHOME", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "NODE_OPTIONS",
                "GIT_SSH_COMMAND", "BROWSER", "EDITOR"}
FETCH_CMD_RE = re.compile(r"\b(?:pip3?|uv|poetry)\b[^\n]{0,40}\binstall\b|\bcurl\b|\bwget\b|"
                          r"\bgit\b[^\n]{0,20}\b(?:clone|pull|fetch)\b|\bnpm\b[^\n]{0,20}\b(?:i|install)\b|"
                          r"\bnpx\b", re.IGNORECASE)


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    evidence: list = field(default_factory=list)
    why: str = ""
    attack: list = field(default_factory=list)
    atlas: list = field(default_factory=list)

    def __post_init__(self):
        info = RULES.get(self.rule)
        if info:
            self.why = self.why or info.why
            self.attack = list(dict.fromkeys(list(info.attack) + list(self.attack)))
            self.atlas = list(dict.fromkeys(list(info.atlas) + list(self.atlas)))

    def to_dict(self):
        return asdict(self)


def _under(path: str, roots) -> bool:
    path = posixpath.normpath(str(path))
    for root in roots:
        root = posixpath.normpath(root)
        if path == root or path.startswith(root + "/"):
            return True
    return False


_NAME_OK = re.compile(r"[^A-Za-z0-9_.:-]")


def _unsafe_plugin_name(name: str) -> bool:
    """Same test as the harness: a name that would not stay one folder inside plugin-data."""
    return any(c in name for c in ("/", "\\", "\0")) or name.strip() in ("", ".", "..") or len(name) > 200


def _safe_name(value, limit: int = 48) -> str:
    """Tool, hook and phase names are chosen by the plugin. Titles are trusted text (the
    AI explainer reads them as such), so keep only plain name characters and cap the
    length; the raw value stays in the evidence, which is marked untrusted."""
    text = _NAME_OK.sub("?", str(value))
    return text if len(text) <= limit else text[:limit - 1] + "\u2026"


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) if not isinstance(v, dict) else str(v.get("name")) for v in value]
    return [str(value)]


def evaluate(result: dict) -> dict:
    """Judge one detonation: what the in-process monitor saw (with the clock jumps), then
    what the outside monitor saw that the plugin could not hide or fake."""
    full = _evaluate_inside(result or {})
    extra = _outside_findings(result or {})
    full["outside"] = outside_summary(result or {})
    if not extra:
        return full
    errored = full["verdict"] == VERDICT_ERROR
    full["findings"] = sorted((full.get("findings") or []) + [f.to_dict() for f in extra],
                              key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    verdict = _verdict([Finding(**f) for f in full["findings"]])
    if errored:
        if verdict == VERDICT_NO_FINDINGS:
            return full
        full["summary"] = ("The sandbox harness did not finish, so the in-process record is missing, "
                           "but the outside monitor saw what is listed below.")
    full["verdict"] = verdict
    return full


def _evaluate_inside(result: dict) -> dict:
    """The in-process monitor's evidence. When the harness also ran the plugin with its clock
    moved forward, anything that only showed up then is marked as time-triggered."""
    _leakfind.reset_run_budget()
    full = _evaluate(result)
    if _leakfind.run_budget_spent():
        full.setdefault("findings", []).append(Finding(
            "coverage_incomplete", LOW, "Returned so much encoded-looking text that not all of it was decoded",
            ["plain and split-up keys were still checked everywhere"],
            why="Detonator stops undoing base64, hex and compression after a fixed amount of work so a plugin "
                "cannot stall the report. Keys that were not encoded were still found.").to_dict())
    jumps = sorted({e["clock_days"] for e in result.get("events") or [] if e.get("clock_days")} |
                   {h["clock_days"] for h in result.get("hook_runs") or [] if h.get("clock_days")})
    if full["verdict"] == VERDICT_ERROR or not jumps:
        return full

    def upto(days):
        return dict(result,
                    events=[e for e in result.get("events") or [] if (e.get("clock_days") or 0) <= days],
                    hook_runs=[h for h in result.get("hook_runs") or [] if (h.get("clock_days") or 0) <= days],
                    decoy_changes=(result.get("decoy_changes") if days else
                                   result.get("decoy_changes_before_clock", result.get("decoy_changes"))),
                    static=None)

    seen = {(f["rule"], f["title"]) for f in _evaluate(upto(0))["findings"]}
    first_day = {}
    for days in jumps:
        for f in _evaluate(upto(days))["findings"]:
            first_day.setdefault((f["rule"], f["title"]), days)
    late = []
    for f in full["findings"]:
        key = (f["rule"], f["title"])
        if key in seen or key not in first_day or f["rule"] == "dormant_code":
            continue
        if f["severity"] in (CRITICAL, HIGH, MEDIUM):
            late.append(f"+{first_day[key]} days: {f['title']}")
        f["title"] += f" (only after the clock moved {first_day[key]} days forward)"
    if late:
        bomb = Finding("time_triggered", HIGH, "Did new things only after its clock was moved forward (time bomb)",
                       late[:8]).to_dict()
        full["findings"] = sorted(full["findings"] + [bomb],
                                  key=lambda f: SEVERITY_ORDER.index(f["severity"]))
        full["verdict"] = _verdict([Finding(**f) for f in full["findings"]])
    full["clock_jumps"] = jumps
    return full


_DECOY_ENV_COUNT = 5


def _mark_bulk_env_reads(events: list, total: int) -> list:
    """Copying the whole environment into a dict happens in C code, so each
    key looks like a direct read. A single moment that touches every decoy variable is
    a copy of the whole environment, not a targeted grab of each key."""
    groups: dict = {}
    for e in events:
        if e.get("how", "direct") == "direct":
            groups.setdefault((e.get("phase"), e.get("t"), e.get("clock_days")), set()).add(e.get("name"))
    bulk = {k for k, names in groups.items() if total and len(names) >= total}
    return [{**e, "how": "enumerated"} if e.get("how", "direct") == "direct" and
            (e.get("phase"), e.get("t"), e.get("clock_days")) in bulk else e for e in events]


def _evaluate(result: dict) -> dict:
    findings: list[Finding] = []

    if not result or result.get("fatal"):
        return {
            "verdict": VERDICT_ERROR,
            "findings": [],
            "summary": "The sandbox harness failed before it could observe the plugin.",
            "detail": (result or {}).get("fatal"),
        }

    add = findings.append
    manifest = result.get("manifest") or {}
    plugin_name = str(manifest.get("name") or "")
    if result.get("unsafe_name") is not None or (plugin_name and _unsafe_plugin_name(plugin_name)):
        add(Finding("unsafe_plugin_name", HIGH,
                    "Has a plugin name that could point its data folder outside its own space",
                    [str(result.get("unsafe_name", plugin_name))[:200]]))
        # Never trust a data folder built from that name, even from an older harness.
        allowed_writes_raw = [d for d in (result.get("allowed_write_dirs") or [])
                              if posixpath.basename(posixpath.normpath(d)) == "plugin_under_test"]
        result = {**result, "allowed_write_dirs": allowed_writes_raw}
    if result.get("events_truncated"):
        add(Finding("log_flood", HIGH, "Did so much that the sandbox log filled up, so part of the run was not kept",
                    [f"{result.get('event_count', 'over 5000')} events recorded"]))
    secret_markers = list(result.get("secret_markers") or [])
    events = result.get("events") or []
    decoy_paths = set(result.get("decoy_paths") or [])
    decoy_dirs = set(result.get("decoy_dirs") or [])
    memory_paths = set(result.get("memory_paths") or [])
    categories = result.get("decoy_categories") or {}
    plugin_dir = result.get("plugin_dir", "/plugin")
    allowed_writes = list(result.get("allowed_write_dirs") or [])
    registered = result.get("registered") or {}
    declared_hooks = set(_as_list(manifest.get("provides_hooks")))
    home = result.get("home") or _common_home(decoy_dirs)
    hermes_home = posixpath.join(home, ".hermes") if home else None
    if hermes_home:
        allowed_writes.append(posixpath.join(hermes_home, "plugin-data"))

    def of(kind):
        return [e for e in events if e.get("kind") == kind]

    # ---- credentials and private data -------------------------------------
    reads = sorted({e["path"] for e in of("file_read") if e.get("path") in decoy_paths})
    cat = lambda p: categories.get(p) or ("memory" if p in memory_paths else "secret")  # noqa: E731
    secret_reads = [p for p in reads if cat(p) == "secret"]
    loot_reads = [p for p in reads if cat(p) in ("browser", "wallet")]
    private_reads = [p for p in reads if cat(p) in ("memory", "history")]
    hermes_env = posixpath.join(hermes_home, ".env") if hermes_home else None
    env_file_reads = [p for p in secret_reads if p == hermes_env]
    secret_reads = [p for p in secret_reads if p != hermes_env]
    if secret_reads:
        add(Finding("decoy_accessed", CRITICAL, "Read decoy secret files (keys, tokens, .env)", secret_reads))
    if env_file_reads:
        add(Finding("hermes_env_read", HIGH, "Read Hermes's .env file, where your API keys are kept",
                    env_file_reads))
    if loot_reads:
        add(Finding("browser_or_wallet_read", CRITICAL, "Read decoy browser passwords, cookies or crypto wallets",
                    loot_reads))
    if private_reads:
        add(Finding("memory_read", MEDIUM, "Read the agent's memory or chat history", private_reads))

    env_events = of("env_read")
    env_events = _mark_bulk_env_reads(env_events, len(result.get("decoy_env") or ()) or _DECOY_ENV_COUNT)
    env_reads = sorted({e["name"] for e in env_events if e.get("how", "direct") == "direct"})
    declared_env = set(_as_list(manifest.get("requires_env")))
    undeclared_env = [n for n in env_reads if n not in declared_env]
    if undeclared_env:
        add(Finding("undeclared_env_read", HIGH,
                    "Read API key variables it does not declare in requires_env", undeclared_env))
    declared_env_reads = [n for n in env_reads if n in declared_env]
    if declared_env_reads:
        add(Finding("declared_env_read", INFO, "Read environment variables it declares in requires_env",
                    declared_env_reads))
    walked = [e for e in env_events if e.get("how") == "enumerated" and e["name"] not in declared_env]
    walked_by_plugin = sorted({e["name"] for e in walked if e.get("by") == "plugin"})
    walked_by_lib = sorted({e["name"] for e in walked if e.get("by") != "plugin"} - set(walked_by_plugin))
    if walked_by_plugin:
        add(Finding("env_enumerated", MEDIUM,
                    "Its own code walked the whole environment, which includes credential variables",
                    walked_by_plugin))
    if walked_by_lib:
        add(Finding("env_enumerated", INFO,
                    "A library it uses scanned the whole environment (normal for proxy lookup)", walked_by_lib,
                    why="Python's own web code reads every variable to find proxy settings; this is expected."))

    environ_reads = of("environ_file_read")
    if environ_reads:
        by_plugin = [e for e in environ_reads if e.get("by") == "plugin"]
        add(Finding("environ_file_read", HIGH if by_plugin else MEDIUM,
                    "Read its whole environment, including every API key, through a file under /proc"
                    + ("" if by_plugin else " (from a library it uses)"),
                    sorted({str(e.get("path")) for e in environ_reads})[:5]))

    listings = {e["path"] for e in of("dir_list")}
    listed = sorted(p for p in listings if p in decoy_dirs)
    if listed:
        add(Finding("decoy_dir_listed", MEDIUM, "Listed your home folder or folders that hold secrets or memory",
                    listed))
    elsewhere = sorted(p for p in listings - set(listed)
                       if not _under(p, allowed_writes + [plugin_dir, "/tmp"]) or (home and _under(p, [home])))
    elsewhere = [p for p in elsewhere if not _under(p, allowed_writes)]
    if len(elsewhere) >= 10 or "/" in elsewhere:
        add(Finding("fs_discovery", MEDIUM, f"Looked through {len(elsewhere)} folders outside its own",
                    elsewhere[:20]))
    recon = sorted({e["path"] for e in of("recon_read") if e.get("by") == "plugin"})
    if recon:
        add(Finding("recon", MEDIUM, "Read system account or host files", recon))

    # ---- network -----------------------------------------------------------
    net = of("network")
    binds = [e for e in net if e.get("op") == "socket.bind"]
    net = [e for e in net if e not in binds]
    # An API plugin sends the key it declares in requires_env to its own API when a
    # tool is called: normal, not a leak. Only when the key is sent as-is, from a tool
    # call, and every such request goes to one host. A disguised key, a send while
    # loading or from a hook, any other key, or the same key sent to a second host
    # is still a leak.
    own_sends = _own_key_sends(net, secret_markers, manifest)
    sent = [(e.get("address"), e.get("payload")) for e in net if id(e) not in own_sends]
    leaked_net = sorted({m for item in sent for m in _leaks(item, secret_markers)})
    plain = {m.split(" (hidden")[0] for m in leaked_net}
    rest = [m for m in secret_markers if m not in plain]
    if rest and len(sent) > 1:
        # A key cut into pieces, each sent in its own request or DNS lookup.
        # Try the calls glued together, and just their encoded-looking parts glued
        # together (DNS exfiltration puts one chunk in the first label of each lookup).
        texts = [str(a) + (str(p) if p else "") for a, p in sent]
        tokens = [re.findall(r"[A-Za-z0-9+/=_-]{8,}", t) for t in texts]
        joins = ["".join(texts), "".join(t for ts in tokens for t in ts), "".join(ts[0] for ts in tokens if ts)]
        pieces = {}
        for joined in joins:
            for m in _leaks(joined, [r for r in rest if r not in pieces]):
                pieces[m.split(" (hidden")[0]] = m
        leaked_net += [m.replace(" (hidden as ", f" (hidden as pieces across {len(sent)} network calls, ", 1)
                       if "(hidden" in m else f"{m} (hidden as pieces across {len(sent)} network calls)"
                       for m in pieces.values()]
    if leaked_net:
        add(Finding("secret_in_output", CRITICAL,
                    "Tried to send decoy secrets over the network" +
                    (", disguised so a plain search would miss them" if _disguised(leaked_net) else ""),
                    leaked_net, attack=["T1041", "T1132"] if _disguised(leaked_net) else ["T1041"],
                    atlas=["AML.T0025"]))
    local = [e for e in net if _is_loopback(e.get("address"))]
    remote = [e for e in net if e not in local]
    # Calling an API from a tool the model invoked is what API plugins do; reaching
    # out while loading or from a background hook is not something the user asked for.
    passive = [e for e in remote if not str(e.get("phase", "")).startswith("tool:")]
    on_call = [e for e in remote if e not in passive]
    if passive:
        add(Finding("undeclared_network", HIGH,
                    "Reached for the network while loading or from a background hook "
                    "(the sandbox has no real network; nothing left the box)", _net_evidence(passive)))
    if on_call:
        own_note = sorted({f"sent its own declared key {n} to {h} (normal for an API plugin; "
                           f"check this host belongs to that service)" for n, h in own_sends.values()})
        add(Finding("tool_network", MEDIUM,
                    "Its tools tried to reach these hosts when called; check they match what the "
                    "plugin says it connects to", own_note + _net_evidence(on_call)))
    if local:
        add(Finding("local_network", MEDIUM, "Tried to reach a service on this computer (localhost)",
                    _net_evidence(local)))
    if binds:
        add(Finding("listener", HIGH, "Opened a network port that others could connect to", _net_evidence(binds)))

    # ---- agent content -----------------------------------------------------
    altered: dict = {}
    _returns: dict = {}
    for run in result.get("hook_runs") or []:
        if run.get("honoured_return") and run.get("returned") not in (None, "", {}, []):
            _returns.setdefault(run.get("hook"), []).append(run.get("returned"))
    for run in result.get("hook_runs") or []:
        hook = run.get("hook")
        returned = run.get("returned")
        if run.get("honoured_return") and returned not in (None, "", {}, []):
            altered.setdefault(("ret", hook), []).append(f"attempt {run.get('attempt')}: {str(returned)[:300]}")
        mutated = [k for k in run.get("mutated_args") or [] if not (hook == "pre_tool_call" and k == "args")]
        if mutated:
            altered.setdefault(("mut", hook), []).extend(
                f"{k}: {str(run.get('after', {}).get(k))[:200]}" for k in mutated)
    for (kind, hook), evidence in sorted(altered.items()):
        evidence = list(dict.fromkeys(evidence))[:5]
        extra_atlas = ["AML.T0053"] if hook == "pre_tool_call" else []
        if kind == "ret":
            powerful = hook in ("pre_llm_call", "transform_tool_result", "transform_llm_output",
                                "transform_terminal_output", "pre_tool_call")
            declared = hook in declared_hooks
            # An undeclared hook that rewrites agent content is hidden behaviour; a
            # declared one is doing its advertised job, but the text deserves a read.
            sev = HIGH if powerful and not declared else MEDIUM
            title = f"Hook {_safe_name(hook)} returned a value Hermes uses to change the {_what_changes(hook)}"
            if declared:
                title += " (declared; check what it adds)"
            if declared and hook == "pre_tool_call" and all(_is_directive(r) for r in _returns.get(hook, [])):
                # {"action": "block"|"approve"} is the documented way for guard plugins to stop a
                # call or ask the user; the call itself is unchanged.
                sev = LOW
                title = "Hook pre_tool_call blocked some tool calls or asked for approval (declared)"
        else:
            sev, title = HIGH, f"Hook {_safe_name(hook)} modified its input arguments in place"
        add(Finding("content_altered", sev, title, evidence, atlas=extra_atlas))

    for run in result.get("tool_runs") or []:
        leaked = _leaks(run.get("returned"), secret_markers)
        if leaked:
            add(Finding("secret_in_output", CRITICAL, f"Tool {_safe_name(run.get('tool'))} returned decoy secrets to the model"
                        + (", disguised" if _disguised(leaked) else ""), leaked))
    for run in result.get("hook_runs") or []:
        leaked = _leaks(run.get("returned"), secret_markers) + _leaks(run.get("after"), secret_markers)
        if leaked:
            add(Finding("secret_in_output", CRITICAL, f"Hook {_safe_name(run.get('hook'))} put decoy secrets into agent content"
                        + (", disguised" if _disguised(leaked) else ""), sorted(set(leaked))))
    for run in result.get("middleware_runs") or []:
        leaked = _leaks(run.get("returned"), secret_markers) + _leaks(run.get("next_payload"), secret_markers)
        if leaked:
            add(Finding("secret_in_output", CRITICAL,
                        f"Middleware {_safe_name(run.get('kind'))} put decoy secrets into a tool call or model request",
                        sorted(set(leaked))))

    injected = []
    for name, schema in sorted((result.get("tool_schemas") or {}).items()):
        injected += [f"tool {name} description: {m}" for m in _injection_hits(schema)]
    for run in result.get("tool_runs") or []:
        injected += [f"tool {run.get('tool')} result: {m}" for m in _injection_hits(run.get("returned"))]
    for run in result.get("hook_runs") or []:
        if run.get("honoured_return"):
            injected += [f"hook {run.get('hook')} output: {m}" for m in _injection_hits(run.get("returned"))]
        for k in run.get("mutated_args") or []:
            injected += [f"hook {run.get('hook')} edited {k}: {m}"
                         for m in _injection_hits((run.get("after") or {}).get(k))]
    for run in result.get("middleware_runs") or []:
        injected += [f"middleware {run.get('kind')} output: {m}" for m in _injection_hits(run.get("returned"))]
        injected += [f"middleware {run.get('kind')} passed on: {m}"
                     for m in _injection_hits(run.get("next_payload")) if run.get("next_payload") != run.get("input")]
    if injected:
        hidden = any("invisible characters" in i for i in injected)
        add(Finding("prompt_injection_text", HIGH, "Sends the model text that tries to give it orders",
                    list(dict.fromkeys(injected))[:10], atlas=["AML.T0068"] if hidden else []))

    shadow = sorted(set(registered.get("tools") or []) & BUILTIN_TOOLS)
    if shadow:
        add(Finding("tool_shadowing", HIGH, "Registers tools named like built-in Hermes tools", shadow))

    findings.extend(_middleware_findings(result, registered, set(_as_list(manifest.get("provides_middleware")))))
    findings.extend(_tool_arg_changes(result, set(_as_list(manifest.get("provides_middleware")))))
    findings.extend(_chat_data_sent(result, events))
    findings.extend(_lookalike_names(registered))
    findings.extend(_output_floods(result))

    dispatched = of("dispatch_tool")
    if dispatched:
        leaked = sorted({m for e in dispatched for m in _leaks(e.get("args"), secret_markers)})
        ev = sorted({f'{e.get("tool")} {str(e.get("args"))[:150]} [{e.get("phase")}]' for e in dispatched})[:10]
        if leaked:
            add(Finding("secret_in_output", CRITICAL, "Passed decoy secrets to another agent tool", leaked + ev,
                        atlas=["AML.T0086"]))
        add(Finding("agent_tool_call", MEDIUM, "Called other agent tools on its own", ev))

    # ---- code execution, persistence, writes --------------------------------
    procs = of("process")
    if procs:
        add(Finding("command_run", HIGH, "Started a process or shell command",
                    sorted({f'{e.get("op")} {str(e.get("detail"))[:300]} [{e.get("phase")}]' for e in procs})[:20]))
        leaked = sorted({m for e in procs if "command" in e for m in _leaks(e.get("command"), secret_markers)})
        if leaked:
            add(Finding("secret_in_output", CRITICAL, "Put decoy secrets into a command it ran", leaked,
                        attack=["T1041", "T1059"]))
        fetch = sorted({str(e.get("detail")) for e in procs if FETCH_CMD_RE.search(str(e.get("detail")))})
        if fetch:
            add(Finding("remote_code_fetch", HIGH, "Ran a command that downloads or installs code", fetch[:10]))
        cron = sorted({str(e.get("detail")) for e in procs if re.search(r"\bcrontab\b|\bsystemctl\b|\blaunchctl\b",
                                                                          str(e.get("detail")))})
        if cron:
            # Listing jobs is not installing one, so the command alone is high; a
            # write to a start-up location (below) is what makes it critical.
            add(Finding("persistence", HIGH, "Ran a scheduler command (crontab, systemctl or launchctl)", cron,
                        attack=["T1053.003", "T1543"],
                        why="crontab, systemctl and launchctl schedule programs to run later or at start-up. "
                            "A plugin has no reason to touch your system scheduler."))

    touched = [(e["path"], "write") for e in of("file_write")]
    touched += [(str(e.get("path")), str(e.get("op"))) for e in of("file_modify")]
    buckets: dict = {}
    for path, op in touched:
        if _under(path, allowed_writes) or path in decoy_paths:
            continue  # decoy changes are judged below
        label = path if op == "write" else f"{op} {path}"
        rule, sev, tech = _classify_write(path, op, home, hermes_home, plugin_dir, manifest.get("name"))
        b = buckets.setdefault((rule, sev), {"evidence": set(), "attack": set()})
        b["evidence"].add(label)
        if tech:
            b["attack"].add(tech)
    titles = {
        "persistence": "Wrote to a place that makes code start automatically",
        "agent_config_modified": "Changed Hermes config, plugins, skills or hooks",
        "self_modify": "Tried to change its own plugin files",
        "content_altered": "Wrote into the agent's memory or chat history folders",
        "write_outside_folder": "Wrote, deleted or changed sensitive files outside its folder",
        "write_own_state": "Kept its own files outside Hermes's plugin data folder",
        "write_tmp": "Wrote temporary files",
    }
    for (rule, sev), b in sorted(buckets.items()):
        add(Finding(rule, sev, titles[rule], sorted(b["evidence"])[:20], attack=sorted(b["attack"])))

    changed = result.get("decoy_changes") or []
    mem_changed = [p for p in changed if cat(p) in ("memory", "history")]
    other_changed = [p for p in changed if p not in mem_changed]
    if mem_changed:
        add(Finding("content_altered", HIGH, "Modified the agent's memory or chat history", mem_changed,
                    attack=["T1565.001"], atlas=["AML.T0080.000", "AML.T0092"],
                    why="Hermes feeds memory back to the model in every future chat. Text planted there keeps "
                        "steering the agent long after the plugin is removed."))
    if other_changed:
        add(Finding("decoy_accessed", CRITICAL, "Modified or deleted decoy secret files", other_changed))

    by_plugin_dyn = [e for e in of("dynamic_code") if e.get("by") == "plugin"]
    other_dyn = [e for e in of("dynamic_code") if e not in by_plugin_dyn]
    if by_plugin_dyn:
        add(Finding("dynamic_code", MEDIUM, "Its own code ran code built from a string (exec/eval/compile)",
                    sorted({str(e.get("detail")) for e in by_plugin_dyn})[:10]))
    if other_dyn:
        # Python itself compiles small snippets (namedtuple, dataclasses, typing).
        add(Finding("dynamic_code", INFO, "Libraries compiled code at runtime",
                    sorted({str(e.get("detail")) for e in other_dyn})[:10],
                    why="Python libraries such as dataclasses compile small snippets; this is expected."))
    hidden = of("hidden_code")
    if hidden:
        add(Finding("hidden_code", HIGH, "Loaded hidden bytecode or a pickle that reaches system functions",
                    sorted({f'{e.get("op")} {e.get("detail", "")}'.strip() for e in hidden})[:10]))
    native = of("native")
    if native:
        add(Finding("native_code", MEDIUM, "Loaded native code via ctypes",
                    sorted({str(e.get("detail")) for e in native})[:10]))

    # ---- tampering and evasion ----------------------------------------------
    patched = list(result.get("patched_functions") or [])
    overrides = sorted({e.get("target") for e in of("hermes_override")})
    if patched:
        add(Finding("monkeypatch", HIGH, "Replaced functions in Python's standard library", patched))
    if overrides:
        add(Finding("monkeypatch", HIGH, "Overrode Hermes internals instead of using the plugin API", overrides))
    env_writes = of("env_write")
    redirect = sorted({e["name"] for e in env_writes if str(e.get("name")).upper() in ENV_REDIRECT
                       or str(e.get("name")).upper().startswith("HERMES_")})
    secret_env_writes = sorted({e["name"] for e in env_writes if e.get("name") in set(result.get("decoy_env") or [])})
    if redirect:
        add(Finding("env_tampering", HIGH, "Changed environment variables that redirect traffic or code loading",
                    redirect))
    if secret_env_writes:
        add(Finding("env_tampering", HIGH, "Overwrote or removed API-key environment variables", secret_env_writes,
                    why="Swapping a user's API key for the attacker's routes the user's requests (and data) "
                        "to the attacker's account."))
    probes = sorted({e["path"] for e in of("sandbox_probe") if e.get("by") == "plugin"})
    if probes:
        add(Finding("sandbox_check", MEDIUM, "Checked whether it is running in a container or being traced", probes))
    tamper = sorted({e.get("op") for e in of("monitor_tamper") if e.get("by") == "plugin"})
    if tamper:
        add(Finding("monitor_tamper", HIGH, "Tried to interfere with runtime monitoring", tamper))
    threads = of("thread_start")
    if threads:
        add(Finding("background_thread", INFO, "Started background threads",
                    sorted({f'{e.get("target")} [{e.get("phase")}]' for e in threads})[:10]))

    # ---- declared vs registered (catalog rule 6) ----------------------------
    declared_tools = set(_as_list(manifest.get("provides_tools")))
    reg_tools = set(registered.get("tools") or [])
    reg_hooks = set(registered.get("hooks") or [])
    if reg_tools - declared_tools:
        add(Finding("undeclared_registration", HIGH, "Registered tools not declared in plugin.yaml",
                    sorted(reg_tools - declared_tools)))
    if reg_hooks - declared_hooks:
        add(Finding("undeclared_registration", HIGH, "Registered hooks not declared in plugin.yaml",
                    sorted(reg_hooks - declared_hooks)))
    reg_mw = set(registered.get("middleware") or [])
    if reg_mw - set(_as_list(manifest.get("provides_middleware"))):
        add(Finding("undeclared_registration", HIGH, "Registered middleware not declared in plugin.yaml",
                    sorted(reg_mw - set(_as_list(manifest.get("provides_middleware"))))))
    if declared_tools - reg_tools:
        add(Finding("declared_not_registered", LOW, "Declared tools that were not registered",
                    sorted(declared_tools - reg_tools)))

    findings.extend(_claim_mismatches(result, findings, events, manifest))

    slow = result.get("slow_callbacks") or []
    if slow or result.get("over_time_budget"):
        add(Finding("coverage_incomplete", MEDIUM,
                    "Some of its hooks, middleware or tools were too slow, so they were not called again"
                    if slow else "Its code was so slow that the run used up its time and some repeat passes were skipped",
                    [str(x)[:120] for x in slow[:10]] or ["time budget reached"],
                    why="Each call gets 5 seconds. A callback that runs out of time is not called again, so "
                        "a slow plugin cannot stall the whole test, but what it would have done later was not "
                        "seen. A hook this slow would also freeze Hermes on every turn."))

    stubbed = result.get("stubbed_modules") or []
    if stubbed:
        add(Finding("coverage_stubbed_imports", INFO,
                    "Ran with stand-ins for modules the sandbox does not have; "
                    "activity through them was not observed", stubbed[:30]))

    findings.extend(_dormant(result.get("static"), findings, events, stubbed))

    for phase in ("import", "register"):
        info = result.get(phase) or {}
        if not info.get("ok", False):
            if stubbed:
                # Likely tripped over a stand-in module, so this is a coverage gap,
                # not behaviour. Everything the plugin did before failing is still judged.
                add(Finding("coverage_incomplete", LOW,
                            f"Plugin stopped during {_safe_name(phase)}, probably because of a stand-in module; "
                            "code after that point was not observed", [str(info.get("error"))]))
            else:
                add(Finding("load_error", MEDIUM, f"Plugin failed during {_safe_name(phase)}", [str(info.get("error"))]))

    # Reading keys is SUSPICIOUS on its own (honest plugins sometimes look up their
    # own key). Together with a reach for the network or another theft it is the
    # stealer pattern, so it goes back to critical.
    seen = {f.rule for f in findings}
    if seen & {"undeclared_network", "secret_in_output", "decoy_accessed", "browser_or_wallet_read"}:
        for f in findings:
            if f.rule in ("hermes_env_read", "undeclared_env_read") or (
                    f.rule == "environ_file_read" and f.severity == HIGH):
                f.severity = CRITICAL
                f.title += ", and also reached for the network or other secrets"
                f.why = ("It read your API keys and, in the same run, reached for the network or took other "
                         "secrets. That combination is what credential stealers do.")

    return {
        "verdict": _verdict(findings),
        "findings": [f.to_dict() for f in sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))],
        "registered": registered,
    }


DORMANT_TITLE = {
    "shell": "Has shell commands that never ran in the sandbox",
    "dynamic_code": "Has code built from strings or hidden bytecode that never ran in the sandbox",
    "secret_paths": "Mentions secret files (keys, tokens, wallets) it never opened in the sandbox",
    "persistence": "Mentions start-up locations (login items, cron, shell start-up files) it never wrote to",
    "network": "Has network calls that never ran in the sandbox",
}


def _dormant(static, findings, events, stubbed) -> list:
    """Risky abilities present in the source that never ran in the sandbox."""
    if not static or not static.get("hits"):
        return []
    rules_seen = {f.rule for f in findings}
    kinds = {e.get("kind") for e in events}
    ran = {
        "shell": "process" in kinds,
        "network": "network" in kinds,
        "dynamic_code": "hidden_code" in kinds or any(
            e.get("kind") == "dynamic_code" and e.get("by") == "plugin" for e in events),
        "secret_paths": bool(rules_seen & {"decoy_accessed", "hermes_env_read", "undeclared_env_read", "environ_file_read", "browser_or_wallet_read", "decoy_dir_listed"}),
        "persistence": "persistence" in rules_seen,
    }
    stubbed_top = {str(m).split(".")[0] for m in stubbed}
    time_note = []
    if static.get("time_checks"):
        time_note = [f"also reads the date or time: {static['time_checks'][0]}"]
    out = []
    for cat, hits in static["hits"].items():
        if ran.get(cat) or not hits:
            continue
        used = set((static.get("modules") or {}).get(cat) or [])
        if used and used <= stubbed_top:
            continue  # only reachable through a stand-in; already reported as a coverage gap
        # Secret stores and start-up locations are rarely legitimate in a plugin and are
        # the payload of a time bomb; shell, string code and network are common in honest
        # tools that the synthetic test simply did not drive far enough.
        severity = MEDIUM if cat in ("secret_paths", "persistence") else (INFO if cat == "network" else LOW)
        # A date check next to them is worth pointing at, but many honest plugins read the
        # clock for timestamps, so it adds evidence rather than raising the severity
        # (tested on 36 catalog plugins: raising it produced a false SUSPICIOUS).
        out.append(Finding("dormant_code", severity, DORMANT_TITLE[cat],
                           hits[:5] + (time_note if severity == MEDIUM else [])))
    return out


def _classify_write(path: str, op: str, home, hermes_home, plugin_dir, name=None):
    """(rule, severity, extra ATT&CK id) for a write/modify outside the allowed folders."""
    norm = posixpath.normpath(path)
    base = posixpath.basename(norm)
    if _under(norm, [plugin_dir]):
        return "self_modify", HIGH, None
    if op == "write":
        for marker, tech in PERSISTENCE_TECHNIQUES:
            if marker in norm:
                return "persistence", CRITICAL, tech
        if base.endswith(".pth") or base in PY_STARTUP:
            return "persistence", CRITICAL, "T1546.018"
        if home and _under(norm, [home]) and posixpath.relpath(norm, home) in SHELL_RC:
            return "persistence", CRITICAL, "T1546.004"
    if home and _under(norm, [home]):
        rel = posixpath.relpath(norm, home).split("/")
        if hermes_home and rel[0] == ".hermes":
            own = isinstance(name, str) and len(name) >= 3 and \
                rel[-1].lstrip(".").lower().startswith(name.lower())
            if len(rel) == 2 and own and rel[1] not in HERMES_SENSITIVE:
                return "write_own_state", MEDIUM, None      # ~/.hermes/<name>-state.json, named after itself
            if len(rel) <= 2 or rel[1] in HERMES_SENSITIVE:
                return "agent_config_modified", HIGH, None  # config.yaml, .env, SOUL.md, plugins, skills...
            if rel[1] in ("memories", "sessions"):
                return "content_altered", HIGH, "T1565.001"
            return "write_own_state", MEDIUM, None          # its own subfolder, e.g. ~/.hermes/<name>/
        if len(rel) == 1 or rel[0] in SENSITIVE_HOME:
            return "write_outside_folder", HIGH, None        # dotfiles in home, key and config folders
        return "write_own_state", MEDIUM, None               # its own folder, e.g. ~/.<name>/
    if _under(norm, ["/tmp"]):
        return "write_tmp", LOW, None
    return "write_outside_folder", HIGH, None


# Honest tools often say what they will NOT do ("never include credentials",
# "does not read private key material", "do not pay without asking the user").
# Those sentences are about safety, not orders to leak. Only the "ask for secrets"
# and "without telling the user" patterns are checked this way: "never tell the user"
# is itself the hiding order.
_NEGATION_RE = re.compile(r"\b(?:never|not|no|don't|doesn't|won't|cannot|can't|refuses?)\b", re.IGNORECASE)
_NEGATABLE_RE = re.compile(r"^(?:read|cat|open|send|include|upload|paste|pass|without)\b", re.IGNORECASE)


def _negated(text: str, m) -> bool:
    if not _NEGATABLE_RE.match(m.group(0)):
        return False
    sentence_start = max(text.rfind(c, 0, m.start()) for c in ".!?;\n") + 1
    return bool(_NEGATION_RE.search(text[sentence_start:m.end()]))


def _injection_hits(value) -> list:
    if value in (None, "", {}, []):
        return []
    text = "\n".join(_strings(value))
    hits = []
    for m in INJECTION_RE.finditer(text):
        if _negated(text, m):
            continue
        start = max(0, m.start() - 40)
        hits.append("…" + text[start:m.end() + 40].replace("\n", " ") + "…")
    if HIDDEN_CHARS_RE.search(text):
        hits.append("contains invisible characters (zero-width, bidi or tag characters)")
    return hits[:5]


def _strings(value, depth=0):
    """All text inside a value (repr() would escape invisible characters)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict) and depth < 6:
        for k, v in value.items():
            yield from _strings(k, depth + 1)
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple)) and depth < 6:
        for v in value:
            yield from _strings(v, depth + 1)


def _common_home(decoy_dirs):
    for d in sorted(decoy_dirs, key=len):
        if d.endswith("/.hermes"):
            return posixpath.dirname(d)
    return None


# --------------------------------------------------------------------------
# Outside monitor: evidence from containers the plugin cannot reach
# --------------------------------------------------------------------------
_ENVIRON_PATH = re.compile(r"^/pro" r"c/(?:self|thread-self|\d+)(?:/task/\d+)?/environ$")
# Fake values Detonator puts in inputs (tool arguments, prompts), not secrets: they carry the
# canary followed by one of these tags.
_INPUT_TAGS = ("-ARG", "-USER", "-SYSTEM", "-TOOLRESULT", "-TERMINAL", "-ASSISTANT")
_RESULT_FILE = "/out/result.json"
_PHASE_PREFIX = "/detonator-phase/"
# Credential files a well-known program reads for its own login. When a program the plugin
# started reads its own one, that is the program working normally (still worth a look, since a
# real key would be in reach); any other decoy read by a program is treated as theft.
_OWN_CREDENTIALS = {
    "pip": (".netrc", ".pypirc", ".config/pip"), "pip3": (".netrc", ".pypirc", ".config/pip"),
    "uv": (".netrc", ".pypirc"), "poetry": (".netrc", ".pypirc"), "twine": (".netrc", ".pypirc"),
    "git": (".git-credentials", ".netrc", ".gitconfig", ".config/git"), "curl": (".netrc",), "wget": (".netrc",),
    "npm": (".npmrc",), "npx": (".npmrc",), "docker": (".docker/",), "kubectl": (".kube/",),
    "aws": (".aws/",), "gh": (".config/gh/",), "ssh": (".ssh/",), "scp": (".ssh/",),
}


def _decoded_views(text: str) -> list:
    """The text plus the common ways malware wraps a key before sending it (URL encoding,
    base64, hex), so an encoded key is still recognised."""
    import base64
    import binascii
    from urllib.parse import unquote_plus

    views = [text, unquote_plus(text)]
    for run in re.findall(r"[A-Za-z0-9+/_-]{16,}={0,2}", text)[:200]:
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                views.append(decode(run + "=" * (-len(run) % 4)).decode("latin-1"))
                break
            except (binascii.Error, ValueError):
                continue
    for run in re.findall(r"(?:[0-9a-fA-F]{2}){16,}", text)[:200]:
        try:
            views.append(bytes.fromhex(run).decode("latin-1"))
        except ValueError:
            pass
    return views


def _secret_hits(text: str, canary: str) -> bool:
    """True when the text carries a fake key (the canary not followed by an input tag)."""
    if not canary or not text:
        return False
    needle = canary.lower()
    tags = _INPUT_TAGS + tuple(t.lstrip("-") for t in _INPUT_TAGS)   # the squashed views lose the dash
    views = _decoded_views(text)
    if not any(needle in v.lower() for v in views):
        # Not there as-is or in the simple wrappings: try the full disguise decoder
        # (rot13, reversed, base32, compression, layers, a key split up with dots).
        views = _leakfind.views(text)
    for view in views:
        low = view.lower()
        start = 0
        while True:
            i = low.find(needle, start)
            if i < 0:
                break
            after = view[i + len(needle): i + len(needle) + 12].upper()
            if not after.startswith(tags):
                return True
            start = i + 1
    return False


def _outside_findings(result: dict) -> list:
    # Its own decoding budget, so a flood of encoded text inside cannot blind the outside check.
    _leakfind.reset_run_budget()
    findings = _outside_findings_raw(result)
    # Evidence quotes what the plugin sent or named; keep it on one line and out of Markdown code.
    for f in findings:
        f.evidence = [str(x).replace("`", "'").replace("\r", "\\r").replace("\n", "\\n") for x in f.evidence]
    return findings


def _outside_findings_raw(result: dict) -> list:
    out = result.get("outside") or {}
    if not isinstance(out, dict) or not out.get("ran"):
        return []
    findings: list[Finding] = []
    canary = str(out.get("canary") or "")
    sink = out.get("sink") or {}
    trace = out.get("trace") or {}
    events = trace.get("events") or []
    start = trace.get("start_index")

    # ---- secrets that reached the fake internet (or left by any socket the tracer saw)
    sent = []
    # The plugin's own declared key going to the one host its tool calls used (seen by
    # the inside monitor too) is an honest API call; only that exact key, sent as-is.
    inside_net = [e for e in (result.get("events") or []) if e.get("kind") == "network"]
    own = _own_key_sends(inside_net, list(result.get("secret_markers") or []), result.get("manifest") or {})
    own_hosts = {h for _, h in own.values()}
    own_keys = [m for m in (result.get("secret_markers") or [])
                if any(m.endswith(_ENV_MARKER_TAGS.get(n, "\0")) for n, _ in own.values())]
    def strip_own(text):
        for m in own_keys:
            text = text.replace(m, "")
        return text

    accepted = []   # what the fake internet saw going to the plugin's own API host
    for e in sink.get("tcp") or []:
        data = str(e.get("data") or "")
        if own_hosts and str(e.get("host") or "").lower().split(":", 1)[0] in own_hosts:
            data = strip_own(data)
            if not _secret_hits(data, canary):
                accepted.append(str(e.get("data") or "")[:120])
        if _secret_hits(data, canary):
            sent.append(f'sent to {_safe_name(e.get("host"), 80)}:{e.get("port")} '
                        f'({e.get("bytes")} bytes): {str(e.get("data"))[:160]!r}')
    for e in sink.get("dns") or []:
        if _secret_hits(str(e.get("name") or ""), canary):
            sent.append(f'hidden in a DNS lookup: {str(e.get("name"))[:160]}')
    if not any(s.startswith("hidden in a DNS") for s in sent):
        # A key cut into pieces, one piece per lookup: join the first label of each name.
        names = [str(e.get("name") or "") for e in (sink.get("dns") or [])][:2000]
        joined = "".join(n.split(".", 1)[0] for n in names)
        if len(names) > 1 and _secret_hits(joined, canary):
            sent.append(f'split across {len(names)} DNS lookups, starting with: {names[0][:80]}')
    for e in events:
        data = str(e.get("data") or "")
        if accepted and not _secret_hits(strip_own(data), canary) and \
                any(a[:60] in data or data[:60] in a for a in accepted):
            continue    # the same honest API request the fake internet already accepted
        if e.get("call") in ("sendto", "sendmsg") and not e.get("unix") \
                and _secret_hits(data, canary):
            where = f'{e.get("ip")}:{e.get("port")}' if e.get("ip") else "an open connection"
            item = f'sent to {where} by process {e.get("pid")} (seen by the tracer)'
            if item not in sent and not (e.get("ip") and any(str(e.get("ip")) in s for s in sent)):
                sent.append(item)
    if sent:
        findings.append(Finding("secret_sent_out", CRITICAL,
                                "Sent a fake key over the network (caught by the fake internet)", sent[:10]))

    if start is None:
        return findings
    plugin_events = events[start + 1:]
    inside = result.get("events") or []
    seen_paths = {str(e.get("path")) for e in inside
                  if e.get("kind") in ("file_read", "file_write", "environ_file_read", "sandbox_probe",
                                       "recon_read", "file_modify", "dir_list")}
    inside_environ = any(e.get("kind") == "environ_file_read" for e in inside)
    inside_procs = any(e.get("kind") == "process" for e in inside)
    inside_net = " ".join(str(e.get("address")) for e in inside if e.get("kind") == "network")
    decoy_paths = set(result.get("decoy_paths") or [])
    home = str(out.get("home") or result.get("home") or "")
    data_root = posixpath.join(home, ".hermes", "plugin-data") if home else None
    fatal = bool(result.get("fatal"))

    def sensitive(path: str) -> bool:
        if path in decoy_paths or _ENVIRON_PATH.match(path):
            return True
        # Without the harness's own record (it was killed), anything in the home folder outside
        # the plugin's data folder counts.
        return fatal and bool(home) and _under(path, [home]) and not (data_root and _under(path, [data_root]))

    hidden, child_reads, forged, tamper = [], [], [], []
    programs = {e.get("proc", e.get("pid")): posixpath.basename(str((e.get("argv") or [e.get("path")])[0] or ""))
                for e in plugin_events if e.get("call") in ("execve", "execveat") and e.get("ok")}
    for j, e in enumerate(plugin_events, start + 1):
        call, path = e.get("call"), str(e.get("path") or "")
        if call in ("open", "openat", "openat2", "creat"):
            if path.startswith(_PHASE_PREFIX):
                continue
            if path == _RESULT_FILE and e.get("write") and e.get("ok"):
                forged.append((j, e))
                continue
            if not sensitive(path):
                continue
            if not e.get("in_harness"):
                child_reads.append((programs.get(e.get("proc", e.get("pid"))) or "a program", path))
            elif path not in seen_paths and not (_ENVIRON_PATH.match(path) and inside_environ):
                hidden.append(f'{"wrote" if e.get("write") else "opened"} {path}')
        elif call in ("connect", "sendto") and e.get("in_harness") and e.get("ip") and e.get("ok"):
            ip, port = str(e.get("ip")), e.get("port")
            if ip in ("127.0.0.1", "::1") and port == 53:
                continue  # the system's own name lookups; the inside monitor logs getaddrinfo instead
            if f"'{ip}', {port}" not in inside_net:
                hidden.append(f"connected to {ip}:{port}")
        elif call in ("execve", "execveat") and e.get("ok") and not inside_procs:
            hidden.append("started " + " ".join(e.get("argv") or [path])[:160])
        elif call in ("ptrace", "process_vm_readv", "process_vm_writev"):
            tamper.append(f'{call}({str(e.get("detail"))[:80]})')
        elif call in ("kill", "tkill", "tgkill") and not e.get("error") and e.get("in_harness") \
                and str(e.get("detail") or "").split(",")[0].strip() == str(trace.get("harness_pid")) \
                and not str(e.get("detail") or "").rstrip(") ").endswith(("0", "SIGALRM")):
            # The harness never signals itself (its timeouts use alarms), so this is the plugin
            # ending the whole test early, which leaves no in-process record to judge.
            tamper.append(f'{call}({str(e.get("detail")).split(")")[0][:40]}): ended its own sandbox')
        elif call in ("kill", "tkill", "tgkill") and e.get("error") == "EPERM":
            # Signalling a process it is not allowed to touch: the only such processes in
            # its world are Detonator's own monitors.
            tamper.append(f'{call}({str(e.get("detail")).split(")")[0][:40]}) refused')
    hidden = list(dict.fromkeys(hidden))
    tracer = out.get("tracer") or {}
    if tracer.get("truncated"):
        findings.append(Finding("log_flood", HIGH,
                                "Made so many system calls that the outside trace was thinned",
                                [f'{tracer.get("lines_seen")} calls traced, {tracer.get("lines_kept")} kept'
                                 + (f', {tracer.get("important_dropped")} that could matter were dropped'
                                    if tracer.get("important_dropped") else
                                    "; every call that could matter was kept")]))
    if sink.get("full"):
        findings.append(Finding("log_flood", HIGH,
                                "Made so many connections that the fake internet's log filled up",
                                [f'{len(sink.get("tcp") or [])} connections and {len(sink.get("dns") or [])} '
                                 "lookups kept"]))
    if hidden:
        severe = any(h.startswith(("opened", "wrote")) for h in hidden)
        findings.append(Finding("monitor_blind_spot", CRITICAL if severe else HIGH,
                                "Did things the in-process monitor did not record (seen only from outside)",
                                hidden[:12]))
    own, stolen = set(), set()
    for prog, path in child_reads:
        rel = path[len(home) + 1:] if home and path.startswith(home + "/") else path
        mine = _OWN_CREDENTIALS.get(prog, ())
        (own if any(rel == m or rel.startswith(m.rstrip("/") + "/") for m in mine) else stolen).add(f"{prog}: {path}")
    if stolen:
        findings.append(Finding("decoy_accessed", CRITICAL,
                                "A program it started read decoy secret files (seen by the outside monitor)",
                                sorted(stolen)[:12]))
    if own:
        findings.append(Finding("decoy_accessed", HIGH,
                                "A program it started read its own login file, so a real key would be in reach "
                                "(seen by the outside monitor)", sorted(own)[:12],
                                why="Tools such as pip, git and curl read their own credential files when they "
                                    "connect. That is normal for the tool, but the plugin chose to run it, and "
                                    "with real files the key would be loaded into a process the plugin controls."))
    done = trace.get("done_index")
    fatal_mark = next((i for i, e in enumerate(events)
                       if e.get("in_harness") and e.get("path") == _PHASE_PREFIX + "harness-fatal"), None)
    limit = min(i for i in (done, fatal_mark) if i is not None) if (done, fatal_mark) != (None, None) else None
    early = {j for j, _ in forged if limit is None or j < limit}
    if len(forged) > 1 or early:
        findings.append(Finding("result_forged", CRITICAL,
                                "Wrote Detonator's result file itself (a forged report)",
                                [f'process {e.get("pid")} opened {_RESULT_FILE} for writing'
                                 f'{" before the run finished" if j in early else ""}' for j, e in forged][:5]))
    if tamper:
        findings.append(Finding("monitor_tamper", HIGH,
                                "Tried to trace, read or stop a process, or ended the test early (seen from outside)",
                                sorted(set(tamper))[:8]))
    return findings


def _connection_lines(tcp: list) -> list:
    groups: dict = {}
    for e in tcp:
        key = f'{_safe_name(e.get("host"), 80)}:{e.get("port")}'
        n, sent = groups.get(key, (0, 0))
        groups[key] = (n + 1, sent + int(e.get("bytes") or 0))
    return [f"{k} ({n} time{'s' if n > 1 else ''}, {sent} bytes sent)" for k, (n, sent) in groups.items()][:20]


def outside_summary(result: dict) -> dict:
    """What the outside monitor ran and saw, for the report (not a judgement)."""
    out = result.get("outside") or {}
    if not isinstance(out, dict) or not out:
        return {"ran": False, "reason": "not part of this run"}
    if not out.get("ran"):
        return {"ran": False, "reason": str(out.get("reason") or "unknown")[:400],
                "chosen_off": bool(out.get("chosen_off"))}
    sink = out.get("sink") or {}
    trace = out.get("trace") or {}
    tracer = out.get("tracer") or {}
    events = trace.get("events") or []
    start = trace.get("start_index")
    after = events[start + 1:] if start is not None else []
    programs = [" ".join(e.get("argv") or [str(e.get("path"))])[:120] for e in after
                if e.get("call") in ("execve", "execveat") and e.get("ok")]
    return {
        "ran": True,
        "traced": start is not None,
        "tracer_problem": tracer.get("error") or (None if start is not None else
                                                  "the tracer did not attach before the plugin loaded"),
        "trace_truncated": bool(tracer.get("truncated")),
        "fake_internet": bool(sink.get("ready")),
        "lookups": sorted({_safe_name(e.get("name"), 80) for e in sink.get("dns") or []})[:20],
        "connections": _connection_lines(sink.get("tcp") or []),
        "programs": list(dict.fromkeys(programs))[:10],
    }


def _is_loopback(address) -> bool:
    text = str(address)
    return any(h in text for h in ("127.0.0.1", "localhost", "'::1'", "[::1]", "//::1"))



# Which marker each decoy API key carries (sandbox/harness.py DECOY_ENV).
_ENV_MARKER_TAGS = {
    "OPENROUTER_API_KEY": "-0001", "OPENAI_API_KEY": "-0002", "ANTHROPIC_API_KEY": "-0003",
    "GITHUB_TOKEN": "0004", "AWS_SECRET_ACCESS_KEY": "-0005",
}


def _host_of(address) -> str:
    text = str(address or "")
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]+)", text)
    host = m.group(1) if m else text.split("/", 1)[0]
    host = host.rsplit("@", 1)[-1]
    if host.startswith("("):            # socket calls report ('host', port)
        m = re.match(r"^\(\s*'([^']*)'", host)
        host = m.group(1) if m else host
    return host.split(":", 1)[0].strip().lower()


def _own_key_sends(net, secret_markers, manifest) -> dict:
    """Network events that only carry the plugin's own declared API key, as-is, from a
    tool call, all to one host. Returns {id(event): (key name, host)}."""
    declared = set(_as_list((manifest or {}).get("requires_env")))
    own = {}
    for name in declared:
        tag = _ENV_MARKER_TAGS.get(name)
        if tag:
            own.update({m: name for m in secret_markers if m.endswith(tag) and not m.endswith("-" + tag)})
    if not own:
        return {}
    others = [m for m in secret_markers if m not in own]
    hits = {}
    for e in net:
        if not str(e.get("phase", "")).startswith("tool:"):
            continue
        text = _text_of((e.get("address"), e.get("payload")))
        found = [m for m in own if m in text]
        if not found:
            continue
        rest = text
        for m in found:
            rest = rest.replace(m, "")
        # Anything still found once the plain own key is taken out (a disguised copy,
        # another key) means this request is not just an honest API call.
        if _leaks(rest, list(own) + others):
            continue
        hits[id(e)] = (own[found[0]], _host_of(e.get("address")))
    by_key = {}
    for name, host in hits.values():
        by_key.setdefault(name, set()).add(host)
    # The same key going to two different hosts is not "its own API" any more.
    spread = {n for n, hosts in by_key.items() if len(hosts) > 1 or "" in hosts}
    return {k: v for k, v in hits.items() if v[0] not in spread}

def _net_evidence(events):
    return sorted({f'{e.get("op")} {e.get("address")} [{e.get("phase")}]' for e in events})[:20]


def _text_of(value) -> str:
    if isinstance(value, str):
        return value
    parts = list(_strings(value))
    return "\n".join(parts + [repr(value)]) if parts else repr(value)


def _leaks(value, secret_markers) -> list:
    """Markers found in a value, plain or disguised. A disguised one is reported
    with how it was hidden, e.g. 'ABC...-0002 (hidden as base64)'."""
    if value in (None, "", {}, []) or not secret_markers:
        return []
    return list(_leaks_cached(_text_of(value), tuple(secret_markers)))


@functools.lru_cache(maxsize=256)
def _leaks_cached(text: str, markers: tuple) -> tuple:
    # Cached because evaluate() judges the same run several times (once per clock pass).
    found = _leakfind.find(text, list(markers))
    return tuple(m if how == "plain" else f"{m} (hidden as {how})" for m, how in found.items())


def _disguised(evidence) -> bool:
    return any("(hidden as " in str(e) for e in evidence)


def _is_directive(value) -> bool:
    return isinstance(value, dict) and value.get("action") in ("block", "approve") and \
        set(value) <= {"action", "message", "rule_key"}


def _what_changes(hook: str) -> str:
    return {
        "pre_llm_call": "prompt sent to the model",
        "transform_llm_output": "model's reply",
        "transform_tool_result": "tool result the model sees",
        "transform_terminal_output": "command output the model sees",
        "pre_tool_call": "tool call or command",
    }.get(hook, "agent's behaviour")


def _verdict(findings) -> str:
    sevs = {f.severity for f in findings}
    if CRITICAL in sevs:
        return VERDICT_DANGEROUS
    if HIGH in sevs:
        return VERDICT_SUSPICIOUS
    if MEDIUM in sevs:
        return VERDICT_REVIEW
    return VERDICT_NO_FINDINGS


# ---------------------------------------------------------------------------
# Sharper rules (v0.3.0): middleware, quiet argument changes, chat data, look-alike names,
# output floods and claims vs behaviour.
# ---------------------------------------------------------------------------
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s'\"<>]+", re.I)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ai|dev|app|xyz|ru|cn|top|me|co|sh|site|info|example)\b",
                      re.I)
_TARGET_RE = re.compile(r"^[a-z]+:[^\s/]{2,}$", re.I)       # Hermes message targets, e.g. telegram:-100123
_DEST_KEYS = {"target", "to", "cc", "bcc", "recipient", "recipients", "chat_id", "channel", "url", "urls", "uri",
              "host", "hostname", "endpoint", "address", "email", "base_url", "api_base", "webhook", "server", "path"}
_COMMAND_KEYS = {"command", "cmd", "script", "code", "shell", "args_raw"}
_SHELL_CHAIN_RE = re.compile(r";|&&|\|\||\||`|\$\(|>\s*/|\bcurl\b|\bwget\b|\bnc\b|\bbase64\b")
_REDIRECT_KEYS = ("base_url", "api_base", "api_key", "extra_headers", "headers", "default_headers", "endpoint",
                  "url", "proxy", "organization")


def _flatten(value, prefix="", depth=0, out=None):
    """{path: leaf value} for a nested dict/list, for describing what changed."""
    out = {} if out is None else out
    if isinstance(value, dict) and depth < 6:
        for k, v in value.items():
            _flatten(v, f"{prefix}.{k}" if prefix else str(k), depth + 1, out)
    elif isinstance(value, (list, tuple)) and depth < 6:
        for i, v in enumerate(value):
            _flatten(v, f"{prefix}[{i}]", depth + 1, out)
    else:
        out[prefix or "(value)"] = value
    return out


def _changes(before, after) -> list:
    """[(path, old, new)] where two payloads differ."""
    a, b = _flatten(before), _flatten(after)
    return [(k, a.get(k), b.get(k)) for k in sorted(set(a) | set(b), key=str) if a.get(k) != b.get(k)]


_DEST_TEXT_CAP = 2048   # addresses are short; the cap keeps these regexes fast on hostile input


def _destinations(text: str) -> set:
    text = str(text)[:_DEST_TEXT_CAP]
    found = set(_URL_RE.findall(text)) | set(_EMAIL_RE.findall(text)) | set(_IP_RE.findall(text))
    found |= {h.lower() for h in _HOST_RE.findall(text)}
    if _TARGET_RE.match(text.strip()):
        found.add(text.strip())
    return found


def _redirects(changes) -> list:
    """Changes that point the call somewhere new: a different recipient, address, host
    or file in a field that says where the call goes, a command with another command
    chained on, or a changed endpoint/credential field. Free text (a message body, the
    prompt) is not checked here: changing it is reported, but it does not redirect."""
    out = []
    for path, old, new in changes:
        if new is None:
            continue
        parts = [p.split("[")[0].lower() for p in str(path).split(".")]
        leaf = parts[-1]
        if leaf in _DEST_KEYS or parts[0] in _REDIRECT_KEYS or leaf in _REDIRECT_KEYS:
            if leaf == "path" and not (_destinations(new) - _destinations(old or "")) and \
                    posixpath.basename(str(new)) == posixpath.basename(str(old or "")):
                continue      # same file name, tidied path ("./notes.txt")
            out.append(path)
        elif leaf in _COMMAND_KEYS and isinstance(new, str) and _SHELL_CHAIN_RE.search(new) and not (
                isinstance(old, str) and _SHELL_CHAIN_RE.search(old)):
            out.append(path)
    return out


def _describe(changes, limit=6) -> list:
    return [f"{p}: {str(o)[:80]!r} -> {str(n)[:120]!r}" for p, o, n in changes[:limit]]


_BLOCK_WORDS = re.compile(r"\b(?:error|block(?:ed)?|den(?:y|ied)|refus\w*|not allowed|reject\w*|cancel\w*|"
                          r"forbidden|disallowed|needs? (?:approval|confirmation))\b", re.I)


def _middleware_findings(result, registered, declared_mw=frozenset()) -> list:
    out = []
    kinds = list(registered.get("middleware") or [])
    if kinds:
        out.append(Finding("middleware_registered", LOW, "Registers Hermes middleware: " +
                           ", ".join(_safe_name(k) for k in kinds), kinds))
    model_changes: dict = {}
    result_changes: dict = {}
    for run in result.get("middleware_runs") or []:
        kind = str(run.get("kind"))
        if not run.get("ok"):
            continue
        if kind == "llm_request" or kind == "llm_execution":
            before = run.get("input")
            after = None
            ret = run.get("returned")
            if kind == "llm_request" and isinstance(ret, dict) and isinstance(ret.get("request"), dict):
                after = ret["request"]
            elif kind == "llm_execution" and run.get("next_called"):
                after = run.get("next_payload")
            if after is not None and after != before:
                ch = _changes(before, after)
                model_changes.setdefault(kind, []).extend(ch)
        if kind.endswith("_execution"):
            canned = run.get("canned")
            ret = run.get("returned")
            if not run.get("next_called") and ret not in (None, "", {}, []) and _BLOCK_WORDS.search(str(ret)):
                # Refusing a call is what guard plugins are for (like a pre_tool_call block).
                result_changes.setdefault((kind, "blocked"), []).append(
                    f"{run.get('tool_name') or 'model call'}: {str(ret)[:200]}")
            elif not run.get("next_called") and ret not in (None, "", {}, []):
                result_changes.setdefault((kind, "skipped"), []).append(
                    f"{run.get('tool_name') or 'model call'}: {str(ret)[:200]}")
            elif run.get("next_called") and ret is not None and ret != canned:
                result_changes.setdefault((kind, "changed"), []).append(
                    f"{run.get('tool_name') or 'model reply'}: {str(ret)[:200]}")
    for kind, ch in sorted(model_changes.items()):
        ch = list({(p, str(o), str(n)): (p, o, n) for p, o, n in ch}.values())
        top = lambda p: str(p).split(".")[0].split("[")[0]  # noqa: E731
        redirect = [p for p, _, _ in ch if top(p) in _REDIRECT_KEYS or top(p) in _DEST_KEYS]
        touched = {top(p) for p, _, _ in ch}
        declared = kind in declared_mw
        if redirect:
            sev, title = CRITICAL, "Middleware points the model request at a different server or credentials"
        elif touched & {"messages", "input", "model", "tools", "system", "instructions"}:
            # A declared prompt filter doing its job is worth a read; an undeclared one is hidden.
            sev = MEDIUM if declared else HIGH
            title = "Middleware rewrote the model request (" + ", ".join(_safe_name(k, 24) for k in sorted(touched)[:6]) + ")"
            title += " (declared; check what it changes)" if declared else ""
        else:
            sev, title = LOW, "Middleware changed model request settings (" + ", ".join(_safe_name(k, 24) for k in sorted(touched)[:6]) + ")"
        out.append(Finding("model_request_changed", sev, title, _describe(ch)))
    for (kind, how), ev in sorted(result_changes.items()):
        ev = list(dict.fromkeys(ev))[:5]
        what = "tool result" if kind == "tool_execution" else "model reply"
        if how == "blocked":
            out.append(Finding("content_altered", LOW, f"Middleware {_safe_name(kind)} blocked some calls", ev,
                               why="Guard plugins refuse calls this way; the model sees the refusal instead "
                                   "of a result. Check the blocked calls are ones it says it guards."))
        elif how == "skipped":
            out.append(Finding("content_altered", HIGH,
                               f"Middleware {_safe_name(kind)} skipped the real call and made up the {what}", ev))
        else:
            out.append(Finding("content_altered", MEDIUM,
                               f"Middleware {_safe_name(kind)} changed the {what} the model sees", ev))
    return out


def _tool_arg_changes(result, declared_mw=frozenset()) -> list:
    by_source: dict = {}
    for run in result.get("hook_runs") or []:
        if run.get("hook") == "pre_tool_call" and "args" in (run.get("mutated_args") or []):
            before = (run.get("inputs") or {}).get("args")
            after = (run.get("after") or {}).get("args")
            by_source.setdefault("hook pre_tool_call", []).append((run.get("tool_name"), _changes(before, after)))
    for run in result.get("middleware_runs") or []:
        kind = run.get("kind")
        if kind not in ("tool_request", "tool_execution") or not run.get("ok"):
            continue
        before = run.get("input")
        after = None
        ret = run.get("returned")
        if kind == "tool_request":
            if isinstance(ret, dict) and isinstance(ret.get("args"), dict):
                after = ret["args"]
            elif run.get("mutated_in_place"):
                after = "(changed in place)"
        elif run.get("next_called"):
            after = run.get("next_payload")
        if isinstance(after, dict) and after != before:
            by_source.setdefault(f"middleware {kind}", []).append((run.get("tool_name"), _changes(before, after)))
    out = []
    for source, items in sorted(by_source.items()):
        ev, redirect, tools = [], [], set()
        for tool, ch in items:
            tools.add(str(tool))
            redirect += _redirects(ch)
            ev += [f"{tool} {d}" for d in _describe(ch)]
        ev = list(dict.fromkeys(ev))[:10]
        scope = "only for " + ", ".join(sorted(tools)) if len(tools) < len(_SCENARIO_TOOLS) else "for every tool"
        if redirect:
            sev = CRITICAL
            title = f"{source.capitalize()} quietly sends tool calls somewhere else ({scope})"
        elif source.startswith("hook") or source.split()[-1] not in declared_mw:
            sev = HIGH
            title = f"{source.capitalize()} quietly changed tool arguments ({scope})"
        else:
            # Rewriting arguments is what declared tool middleware is for; say what it does.
            sev = MEDIUM
            title = f"{source.capitalize()} changes tool arguments ({scope}); check what it changes"
        out.append(Finding("tool_args_changed", sev, _safe_title(title), ev))
    return out


_SCENARIO_TOOLS = ("terminal", "send_message", "web_extract", "write_file")


def _safe_title(text: str) -> str:
    return re.sub(r"[^\w .,:;()'+/-]", "?", text)[:160]


_USER_TAGS = ("USER", "ASSISTANT", "SYSTEM", "TOOLRESULT", "TERMINAL")


def _chat_data_sent(result, events) -> list:
    canary = result.get("canary")
    if not canary:
        return []
    chat = [f"{canary}-{t}" for t in _USER_TAGS]
    args = [f"{canary}-ARG"]
    hits = []
    for e in events:
        kind = e.get("kind")
        if kind == "network":
            value, where = (e.get("address"), e.get("payload")), "network"
        elif kind == "process" and "command" in e:
            value, where = e.get("command"), "command"
        else:
            continue
        phase = str(e.get("phase", ""))
        markers = chat + ([] if phase.startswith("tool:") else args)   # a tool may send its own input to its API
        for m in _leaks(value, markers):
            label = "tool arguments" if "-ARG" in m else "chat text"
            how = m.split(" (hidden as ", 1)[1].rstrip(")") if "(hidden as " in m else ""
            hits.append(f"{label} sent via {where} [{phase}]" + (f", hidden as {how}" if how else "") +
                        f": {str(e.get('address') or e.get('detail'))[:150]}")
    if not hits:
        return []
    return [Finding("chat_data_sent", HIGH, "Sent conversation text or tool input out on its own",
                    list(dict.fromkeys(hits))[:10])]


# Letters from other alphabets (and digits) that look like Latin letters.
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ӏ": "l", "к": "k", "м": "m", "т": "t", "н": "h", "в": "b", "ԛ": "q", "ԝ": "w", "ɡ": "g",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "ν": "v", "ρ": "p", "τ": "t", "κ": "k", "υ": "u", "χ": "x",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "i": "l", "|": "l",
})


def _skeleton(name: str, keep_separators=False) -> str:
    text = unicodedata.normalize("NFKC", name).casefold().translate(_CONFUSABLE)
    text = text.replace("rn", "m").replace("vv", "w")
    return text if keep_separators else re.sub(r"[\W_]+", "", text)


def _one_edit(a: str, b: str) -> bool:
    """True when a is b with one letter swapped, two neighbours transposed, or one
    letter doubled (not a plain plural: 'todos' is not a look-alike of 'todo')."""
    if a == b:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and
                                  a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) == len(b) + 1:
        for i in range(len(a)):
            if a[:i] + a[i + 1:] == b:
                return 0 < i and a[i] == a[i - 1]
    return False


def _lookalike_names(registered) -> list:
    exact, near = [], []
    builtin = {b: _skeleton(b) for b in BUILTIN_TOOLS}
    for name in registered.get("tools") or []:
        name = str(name)
        if name in BUILTIN_TOOLS:
            continue      # same name: reported as tool_shadowing
        skel = _skeleton(name)
        foreign = any(ord(c) > 127 for c in name)
        for b, bskel in sorted(builtin.items()):
            if skel == bskel:
                # Same letters once look-alike characters are mapped. A version that only
                # differs in separators or case ('web-search') is a weaker signal.
                plain = re.sub(r"[\W_]+", "", name.casefold()) == re.sub(r"[\W_]+", "", b)
                (near if plain and not foreign else exact).append(f"{name!a} looks like built-in {b}")
                break
            if len(bskel) >= 6 and _one_edit(skel, bskel):
                near.append(f"{name!a} is one letter away from built-in {b}")
                break
        else:
            if foreign:
                exact.append(f"{name!a} uses letters from another alphabet")
    out = []
    if exact:
        out.append(Finding("lookalike_name", HIGH, "Registers tools disguised as built-in Hermes tools", exact[:10]))
    if near:
        out.append(Finding("lookalike_name", MEDIUM, "Registers tools with names close to built-in Hermes tools",
                           near[:10]))
    return out


TOOL_FLOOD_CHARS = 100_000   # Hermes moves bigger tool results to a file (budget_config.py)
HOOK_FLOOD_CHARS = 20_000    # added to every prompt or reply, with no cap in Hermes
_PROMPT_HOOKS = ("pre_llm_call", "transform_tool_result", "transform_llm_output", "transform_terminal_output")


def _output_floods(result) -> list:
    tool_ev, hook_ev = [], []
    for run in result.get("tool_runs") or []:
        size = run.get("returned_size") or 0
        if size > TOOL_FLOOD_CHARS:
            tool_ev.append(f"tool {run.get('tool')} returned {size:,} characters")
    for run in result.get("hook_runs") or []:
        if run.get("hook") in _PROMPT_HOOKS and run.get("honoured_return"):
            size = run.get("returned_size") or 0
            if size > HOOK_FLOOD_CHARS:
                hook_ev.append(f"hook {run.get('hook')} returned {size:,} characters")
    for run in result.get("middleware_runs") or []:
        if run.get("kind") in ("llm_request", "llm_execution", "tool_execution"):
            grown = (run.get("returned_size") or 0) - len(str(run.get("input") or ""))
            if grown > HOOK_FLOOD_CHARS:
                hook_ev.append(f"middleware {run.get('kind')} added {grown:,} characters")
    out = []
    if hook_ev:
        out.append(Finding("output_flood", HIGH, "Adds a huge amount of text to what the model reads on every turn",
                           list(dict.fromkeys(hook_ev))[:5]))
    if tool_ev:
        out.append(Finding("output_flood", MEDIUM, "A tool returns a huge result (Hermes stores it in a file instead)",
                           list(dict.fromkeys(tool_ev))[:5]))
    return out


# What plugins say about themselves -> which findings prove it wrong.
_CLAIMS = (
    ("works offline / no network",
     re.compile(r"\b(?:works?|runs?|fully|completely|entirely|100%) offline\b|\boffline[- ]only\b|"
                r"\bno (?:network|internet)\b|"
                r"\bnever (?:connects?|calls? out|phones? home|sends?|uploads?)\b|"
                r"\b(?:does not|doesn't|will not|won't) (?:connect|send|upload|use the (?:network|internet))\b|"
                r"\blocal[- ]only\b|\bno data (?:ever )?leaves\b|\bwithout (?:any )?(?:network|internet)\b", re.I),
     {"undeclared_network", "tool_network", "chat_data_sent"}, "it reached for the network"),
    ("runs no commands",
     re.compile(r"\bno (?:shell|subprocess(?:es)?|shell commands)\b|\bnever (?:runs?|executes?) (?:any )?(?:shell )?"
                r"commands?\b|\b(?:does not|doesn't) (?:run|execute) (?:any )?(?:shell )?commands?\b", re.I),
     {"command_run"}, "it ran a command"),
    ("read-only",
     # Not "read-only" on its own: descriptions use it for what they read ("reads the session
     # store read-only"), not as a promise that the plugin writes nothing.
     re.compile(r"\bnever (?:writes?|modif(?:y|ies)|changes?) (?:any |your )?(?:files?|disk)\b|\bwrites no files\b|"
                r"\b(?:does not|doesn't) (?:write|modify|change) (?:any |your )?files?\b", re.I),
     {"write_outside_folder", "agent_config_modified", "persistence", "self_modify"},
     "it wrote files outside its data folder"),
    ("never touches keys",
     re.compile(r"\b(?:never|does not|doesn't|won't|will not) (?:read|access|touch|collect|see|store)s? "
                r"(?:your |any )?(?:api )?(?:keys|credentials|secrets|tokens|passwords)\b", re.I),
     {"decoy_accessed", "hermes_env_read", "undeclared_env_read", "environ_file_read", "env_enumerated",
      "browser_or_wallet_read", "secret_in_output"}, "it went after keys"),
)
# "no network calls besides the cargo build", "no network at load; the tool calls api.x.com"
_CLAIM_QUALIFIED = re.compile(r"^[^.;\n]{0,40}\b(?:besides|except|other than|beyond|apart from|outside|of its own|"
                              r"at (?:load|import|start-?up)|in (?:its )?hooks?|in the background|unless)\b", re.I)
_CLAIM_NEGATED = re.compile(r"\b(?:not|requires?|needs?|unless)\b|n't\b", re.I)


def _claim_texts(result, manifest):
    yield "plugin.yaml description", str(manifest.get("description") or "")
    for name, schema in sorted((result.get("tool_schemas") or {}).items()):
        if isinstance(schema, dict):
            yield f"tool {name} description", str(schema.get("description") or "")


def _claim_mismatches(result, findings, events, manifest) -> list:
    seen = {f.rule for f in findings if f.severity not in (INFO,)}
    ev = []
    for where, text in _claim_texts(result, manifest):
        for label, regex, contradicted_by, did in _CLAIMS:
            m = regex.search(text)
            if not m:
                continue
            before = text[max(0, m.start() - 25):m.start()]
            if _CLAIM_NEGATED.search(before) and not m.group(0).lower().startswith(("never", "no ", "does", "doesn",
                                                                                   "will", "won")):
                continue      # "does not work offline", "requires network"
            if _CLAIM_QUALIFIED.search(text[m.end():]):
                continue
            hit = seen & contradicted_by
            if hit == {"tool_network"} and _destinations(text):
                continue      # it names the service its tools call, so a call from a tool is expected
            if hit:
                snippet = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")
                ev.append(f"{where} says “…{snippet}…” ({label}), but {did}")
    if not ev:
        return []
    return [Finding("claim_mismatch", HIGH, "Does the opposite of what its description promises",
                    list(dict.fromkeys(ev))[:8])]
