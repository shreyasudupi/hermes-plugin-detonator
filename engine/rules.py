"""Deterministic rules: compare what a plugin declares with what it did.

Input is the harness result (sandbox/harness.py). Output is a list of findings
and an advisory verdict. No model is involved in deciding anything here.

Every finding carries a plain-language "why" and, where one fits, MITRE
ATT&CK (enterprise, v20) and MITRE ATLAS (v5.6) technique IDs. The catalog of
rules lives in RULES below; docs/RULES.md is checked against it by a test.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field

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
        "a network address or another tool's input). A real key would leak the same way.",
        ("T1041",), ("AML.T0057", "AML.T0086")),
    "memory_read": Rule(
        "Memory and chat history hold what the agent knows about you. Expected for memory plugins, "
        "a privacy leak for anything else.",
        ("T1005",), ()),
    "env_enumerated": Rule(
        "Copying the whole environment collects every API key at once.",
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
        "Registers hooks or tools missing from plugin.yaml, so users are not shown them at install "
        "time (catalog rule 6).",
        (), ("AML.T0010.005",)),
    "declared_not_registered": Rule("Declares tools it did not register; usually a stale plugin.yaml."),
    "load_error": Rule("The plugin crashed while loading, so less of it was observed."),
    "coverage_incomplete": Rule(
        "The plugin stopped on a stand-in module, so code after that point was not observed."),
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
    r"\bauth\.json\b|\bapi[_ ]?keys?\b|\bcredentials\b|\bprivate key\b|\.env\b(?:\s+file)?)",
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
    path = os.path.normpath(str(path))
    for root in roots:
        root = os.path.normpath(root)
        if path == root or path.startswith(root + os.sep):
            return True
    return False


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) if not isinstance(v, dict) else str(v.get("name")) for v in value]
    return [str(value)]


def evaluate(result: dict) -> dict:
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
    hermes_home = os.path.join(home, ".hermes") if home else None
    if hermes_home:
        allowed_writes.append(os.path.join(hermes_home, "plugin-data"))

    def of(kind):
        return [e for e in events if e.get("kind") == kind]

    # ---- credentials and private data -------------------------------------
    reads = sorted({e["path"] for e in of("file_read") if e.get("path") in decoy_paths})
    cat = lambda p: categories.get(p) or ("memory" if p in memory_paths else "secret")  # noqa: E731
    secret_reads = [p for p in reads if cat(p) == "secret"]
    loot_reads = [p for p in reads if cat(p) in ("browser", "wallet")]
    private_reads = [p for p in reads if cat(p) in ("memory", "history")]
    if secret_reads:
        add(Finding("decoy_accessed", CRITICAL, "Read decoy secret files (keys, tokens, .env)", secret_reads))
    if loot_reads:
        add(Finding("browser_or_wallet_read", CRITICAL, "Read decoy browser passwords, cookies or crypto wallets",
                    loot_reads))
    if private_reads:
        add(Finding("memory_read", MEDIUM, "Read the agent's memory or chat history", private_reads))

    env_events = of("env_read")
    env_reads = sorted({e["name"] for e in env_events if e.get("how", "direct") == "direct"})
    declared_env = set(_as_list(manifest.get("requires_env")))
    undeclared_env = [n for n in env_reads if n not in declared_env]
    if undeclared_env:
        add(Finding("decoy_accessed", CRITICAL,
                    "Read credential environment variables it does not declare in requires_env",
                    undeclared_env, attack=["T1552"]))
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
    leaked_net = sorted({m for e in net for m in _leaks(e.get("address"), secret_markers)})
    if leaked_net:
        add(Finding("secret_in_output", CRITICAL, "Tried to send decoy secrets over the network", leaked_net,
                    attack=["T1041"], atlas=["AML.T0025"]))
    local = [e for e in net if _is_loopback(e.get("address"))]
    remote = [e for e in net if e not in local]
    # Calling an API from a tool the model invoked is what API plugins do; reaching
    # out while loading or from a background hook is not something the user asked for.
    passive = [e for e in remote if not str(e.get("phase", "")).startswith("tool:")]
    on_call = [e for e in remote if e not in passive]
    if passive:
        add(Finding("undeclared_network", HIGH,
                    "Reached for the network while loading or from a background hook "
                    "(the sandbox has no network; nothing left the box)", _net_evidence(passive)))
    if on_call:
        add(Finding("tool_network", MEDIUM,
                    "Its tools tried to reach these hosts when called; check they match what the "
                    "plugin says it connects to", _net_evidence(on_call)))
    if local:
        add(Finding("local_network", MEDIUM, "Tried to reach a service on this computer (localhost)",
                    _net_evidence(local)))
    if binds:
        add(Finding("listener", HIGH, "Opened a network port that others could connect to", _net_evidence(binds)))

    # ---- agent content -----------------------------------------------------
    altered: dict = {}
    for run in result.get("hook_runs") or []:
        hook = run.get("hook")
        returned = run.get("returned")
        if run.get("honoured_return") and returned not in (None, "", {}, []):
            altered.setdefault(("ret", hook), []).append(f"attempt {run.get('attempt')}: {str(returned)[:300]}")
        if run.get("mutated_args"):
            altered.setdefault(("mut", hook), []).extend(
                f"{k}: {str(run.get('after', {}).get(k))[:200]}" for k in run["mutated_args"])
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
            title = f"Hook {hook} returned a value Hermes uses to change the {_what_changes(hook)}"
            if declared:
                title += " (declared; check what it adds)"
        else:
            sev, title = HIGH, f"Hook {hook} modified its input arguments in place"
        add(Finding("content_altered", sev, title, evidence, atlas=extra_atlas))

    for run in result.get("tool_runs") or []:
        leaked = _leaks(run.get("returned"), secret_markers)
        if leaked:
            add(Finding("secret_in_output", CRITICAL, f"Tool {run.get('tool')} returned decoy secrets to the model",
                        leaked))
    for run in result.get("hook_runs") or []:
        leaked = _leaks(run.get("returned"), secret_markers) + _leaks(run.get("after"), secret_markers)
        if leaked:
            add(Finding("secret_in_output", CRITICAL, f"Hook {run.get('hook')} put decoy secrets into agent content",
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
    if injected:
        hidden = any("invisible characters" in i for i in injected)
        add(Finding("prompt_injection_text", HIGH, "Sends the model text that tries to give it orders",
                    list(dict.fromkeys(injected))[:10], atlas=["AML.T0068"] if hidden else []))

    shadow = sorted(set(registered.get("tools") or []) & BUILTIN_TOOLS)
    if shadow:
        add(Finding("tool_shadowing", HIGH, "Registers tools named like built-in Hermes tools", shadow))

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
                    sorted({f'{e.get("op")} {e.get("detail")} [{e.get("phase")}]' for e in procs})[:20]))
        fetch = sorted({str(e.get("detail")) for e in procs if FETCH_CMD_RE.search(str(e.get("detail")))})
        if fetch:
            add(Finding("remote_code_fetch", HIGH, "Ran a command that downloads or installs code", fetch[:10]))
        cron = sorted({str(e.get("detail")) for e in procs if re.search(r"\bcrontab\b|\bsystemctl\b|\blaunchctl\b",
                                                                          str(e.get("detail")))})
        if cron:
            # Listing jobs is not installing one, so the command alone is high; a
            # write to a start-up location (below) is what makes it critical.
            add(Finding("persistence", HIGH, "Ran a scheduler command (crontab, systemctl or launchctl)", cron,
                        attack=["T1053.003", "T1543"]))

    touched = [(e["path"], "write") for e in of("file_write")]
    touched += [(str(e.get("path")), str(e.get("op"))) for e in of("file_modify")]
    buckets: dict = {}
    for path, op in touched:
        if _under(path, allowed_writes) or path in decoy_paths:
            continue  # decoy changes are judged below
        label = path if op == "write" else f"{op} {path}"
        rule, sev, tech = _classify_write(path, op, home, hermes_home, plugin_dir)
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
                    attack=["T1565.001"], atlas=["AML.T0080.000", "AML.T0092"]))
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
    if declared_tools - reg_tools:
        add(Finding("declared_not_registered", LOW, "Declared tools that were not registered",
                    sorted(declared_tools - reg_tools)))

    stubbed = result.get("stubbed_modules") or []
    if stubbed:
        add(Finding("coverage_stubbed_imports", INFO,
                    "Ran with stand-ins for modules the sandbox does not have; "
                    "activity through them was not observed", stubbed[:30]))

    for phase in ("import", "register"):
        info = result.get(phase) or {}
        if not info.get("ok", False):
            if stubbed:
                # Likely tripped over a stand-in module, so this is a coverage gap,
                # not behaviour. Everything the plugin did before failing is still judged.
                add(Finding("coverage_incomplete", LOW,
                            f"Plugin stopped during {phase}, probably because of a stand-in module; "
                            "code after that point was not observed", [str(info.get("error"))]))
            else:
                add(Finding("load_error", MEDIUM, f"Plugin failed during {phase}", [str(info.get("error"))]))

    return {
        "verdict": _verdict(findings),
        "findings": [f.to_dict() for f in sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))],
        "registered": registered,
    }


def _classify_write(path: str, op: str, home, hermes_home, plugin_dir):
    """(rule, severity, extra ATT&CK id) for a write/modify outside the allowed folders."""
    norm = os.path.normpath(path)
    base = os.path.basename(norm)
    if _under(norm, [plugin_dir]):
        return "self_modify", HIGH, None
    if op == "write":
        for marker, tech in PERSISTENCE_TECHNIQUES:
            if marker in norm:
                return "persistence", CRITICAL, tech
        if base.endswith(".pth") or base in PY_STARTUP:
            return "persistence", CRITICAL, "T1546.018"
        if home and _under(norm, [home]) and os.path.relpath(norm, home) in SHELL_RC:
            return "persistence", CRITICAL, "T1546.004"
    if home and _under(norm, [home]):
        rel = os.path.relpath(norm, home).split(os.sep)
        if hermes_home and rel[0] == ".hermes":
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


def _injection_hits(value) -> list:
    if value in (None, "", {}, []):
        return []
    text = "\n".join(_strings(value))
    hits = []
    for m in INJECTION_RE.finditer(text):
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
            return os.path.dirname(d)
    return None


def _is_loopback(address) -> bool:
    text = str(address)
    return any(h in text for h in ("127.0.0.1", "localhost", "'::1'", "[::1]", "//::1"))


def _net_evidence(events):
    return sorted({f'{e.get("op")} {e.get("address")} [{e.get("phase")}]' for e in events})[:20]


def _leaks(value, secret_markers) -> list:
    text = repr(value)
    return [m for m in secret_markers if m in text]


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
