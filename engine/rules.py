"""Deterministic rules: compare what a plugin declares with what it did.

Input is the harness result (sandbox/harness.py). Output is a list of findings
and an advisory verdict. No model is involved in deciding anything here.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field

CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"
SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

VERDICT_DANGEROUS = "DANGEROUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_REVIEW = "REVIEW"
VERDICT_NO_FINDINGS = "NO_FINDINGS"
VERDICT_ERROR = "ERROR"


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    evidence: list = field(default_factory=list)

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

    manifest = result.get("manifest") or {}
    secret_markers = list(result.get("secret_markers") or [])
    events = result.get("events") or []
    decoy_paths = set(result.get("decoy_paths") or [])
    decoy_dirs = set(result.get("decoy_dirs") or [])
    memory_paths = set(result.get("memory_paths") or [])
    allowed_writes = list(result.get("allowed_write_dirs") or []) + [result.get("plugin_dir", "/plugin")]
    registered = result.get("registered") or {}

    # ---- R1 decoy accessed -------------------------------------------------
    reads = sorted({e["path"] for e in events if e["kind"] == "file_read" and e.get("path") in decoy_paths})
    secret_reads = [p for p in reads if p not in memory_paths]
    memory_reads = [p for p in reads if p in memory_paths]
    if secret_reads:
        findings.append(Finding("decoy_accessed", CRITICAL, "Read decoy secret files (keys, tokens, .env)",
                                secret_reads))
    if memory_reads:
        # Memory plugins read these on purpose; still private data worth a look.
        findings.append(Finding("memory_read", MEDIUM, "Read the agent's memory files", memory_reads))
    env_events = [e for e in events if e["kind"] == "env_read"]
    env_reads = sorted({e["name"] for e in env_events if e.get("how", "direct") == "direct"})
    declared_env = set(_as_list(manifest.get("requires_env")))
    undeclared_env = [n for n in env_reads if n not in declared_env]
    if undeclared_env:
        findings.append(Finding("decoy_accessed", CRITICAL,
                                "Read credential environment variables it does not declare in requires_env",
                                undeclared_env))
    declared_env_reads = [n for n in env_reads if n in declared_env]
    if declared_env_reads:
        findings.append(Finding("declared_env_read", INFO,
                                "Read environment variables it declares in requires_env", declared_env_reads))
    walked = [e for e in env_events if e.get("how") == "enumerated" and e["name"] not in declared_env]
    walked_by_plugin = sorted({e["name"] for e in walked if e.get("by") == "plugin"})
    walked_by_lib = sorted({e["name"] for e in walked if e.get("by") != "plugin"} - set(walked_by_plugin))
    if walked_by_plugin:
        findings.append(Finding("env_enumerated", MEDIUM,
                                "Its own code walked the whole environment, which includes credential variables",
                                walked_by_plugin))
    if walked_by_lib:
        # e.g. urllib scanning every variable for proxy settings
        findings.append(Finding("env_enumerated", INFO,
                                "A library it uses scanned the whole environment (normal for proxy lookup)",
                                walked_by_lib))
    listed = sorted({e["path"] for e in events if e["kind"] == "dir_list" and e.get("path") in decoy_dirs})
    if listed:
        findings.append(Finding("decoy_dir_listed", MEDIUM, "Listed directories that hold secrets or memory", listed))

    # ---- R2 undeclared network ----------------------------------------------
    net = [e for e in events if e["kind"] == "network"]
    leaked_net = sorted({m for e in net for m in _leaks(e.get("address"), secret_markers)})
    if leaked_net:
        findings.append(Finding("secret_in_output", CRITICAL, "Tried to send decoy secrets over the network",
                                leaked_net))
    local = [e for e in net if _is_loopback(e.get("address"))]
    remote = [e for e in net if e not in local]
    # Calling an API from a tool the model invoked is what API plugins do; reaching
    # out while loading or from a background hook is not something the user asked for.
    passive = [e for e in remote if not str(e.get("phase", "")).startswith("tool:")]
    on_call = [e for e in remote if e not in passive]
    if passive:
        findings.append(Finding("undeclared_network", HIGH,
                                "Reached for the network while loading or from a background hook "
                                "(the sandbox has no network; nothing left the box)", _net_evidence(passive)))
    if on_call:
        findings.append(Finding("tool_network", MEDIUM,
                                "Its tools tried to reach these hosts when called; check they match what the "
                                "plugin says it connects to", _net_evidence(on_call)))
    if local:
        findings.append(Finding("local_network", MEDIUM,
                                "Tried to reach a service on this computer (localhost)", _net_evidence(local)))

    # ---- R3 prompt / command / tool result / memory altered ----------------
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
        if kind == "ret":
            powerful = hook in ("pre_llm_call", "transform_tool_result", "transform_llm_output",
                                "transform_terminal_output", "pre_tool_call")
            declared = hook in set(_as_list(manifest.get("provides_hooks")))
            # An undeclared hook that rewrites agent content is hidden behaviour; a
            # declared one is doing its advertised job, but the text deserves a read.
            sev = HIGH if powerful and not declared else MEDIUM
            title = f"Hook {hook} returned a value Hermes uses to change the {_what_changes(hook)}"
            if declared:
                title += " (declared; check what it adds)"
        else:
            sev, title = HIGH, f"Hook {hook} modified its input arguments in place"
        findings.append(Finding("content_altered", sev, title, evidence))
    for run in result.get("tool_runs") or []:
        leaked = _leaks(run.get("returned"), secret_markers)
        if leaked:
            findings.append(Finding("secret_in_output", CRITICAL,
                                    f"Tool {run.get('tool')} returned decoy secrets to the model", leaked))
    for run in result.get("hook_runs") or []:
        leaked = _leaks(run.get("returned"), secret_markers) + _leaks(run.get("after"), secret_markers)
        if leaked:
            findings.append(Finding("secret_in_output", CRITICAL,
                                    f"Hook {run.get('hook')} put decoy secrets into agent content",
                                    sorted(set(leaked))))
    changed = result.get("decoy_changes") or []
    mem_changed = [p for p in changed if p in memory_paths]
    other_changed = [p for p in changed if p not in memory_paths]
    if mem_changed:
        findings.append(Finding("content_altered", HIGH, "Modified the agent's memory files", mem_changed))
    if other_changed:
        findings.append(Finding("decoy_accessed", CRITICAL, "Modified or deleted decoy secret files", other_changed))

    # ---- R4 commands and writes outside own folder --------------------------
    procs = [e for e in events if e["kind"] == "process"]
    if procs:
        findings.append(Finding("command_run", HIGH, "Started a process or shell command",
                                sorted({f'{e.get("op")} {e.get("detail")} [{e.get("phase")}]' for e in procs})[:20]))
    home = result.get("home") or _common_home(decoy_dirs)
    hermes_home = os.path.join(home, ".hermes") if home else None
    if hermes_home:
        allowed_writes.append(os.path.join(hermes_home, "plugin-data"))
    touched = [(e["path"], "write") for e in events if e["kind"] == "file_write"]
    touched += [(str(e.get("path")), str(e.get("op"))) for e in events if e["kind"] == "file_modify"]
    buckets = {HIGH: set(), MEDIUM: set(), LOW: set()}
    for path, op in touched:
        if _under(path, allowed_writes) or path in decoy_paths:
            continue  # decoy changes are judged above
        label = path if op == "write" else f"{op} {path}"
        buckets[_write_severity(path, home, hermes_home)].add(label)
    if buckets[HIGH]:
        findings.append(Finding("write_outside_folder", HIGH,
                                "Wrote, deleted or changed sensitive files outside its folder "
                                "(shell/SSH/cloud config, Hermes config, plugins or skills, system paths)",
                                sorted(buckets[HIGH])[:20]))
    if buckets[MEDIUM]:
        findings.append(Finding("write_own_state", MEDIUM,
                                "Kept its own files outside Hermes's plugin data folder",
                                sorted(buckets[MEDIUM])[:20]))
    if buckets[LOW]:
        findings.append(Finding("write_tmp", LOW, "Wrote temporary files", sorted(buckets[LOW])[:20]))
    native = [e for e in events if e["kind"] == "native"]
    if native:
        findings.append(Finding("native_code", MEDIUM, "Loaded native code via ctypes",
                                sorted({str(e.get("detail")) for e in native})[:10]))
    dyn = [e for e in events if e["kind"] == "dynamic_code"]
    if dyn:
        # Python itself compiles small snippets (namedtuple, typing), so this is
        # context for a reviewer, not a verdict signal.
        findings.append(Finding("dynamic_code", INFO, "Compiled or executed code at runtime",
                                sorted({str(e.get("detail")) for e in dyn})[:10]))

    # ---- R5 declared vs registered (catalog rule 6) -------------------------
    declared_tools = set(_as_list(manifest.get("provides_tools")))
    declared_hooks = set(_as_list(manifest.get("provides_hooks")))
    reg_tools = set(registered.get("tools") or [])
    reg_hooks = set(registered.get("hooks") or [])
    if reg_tools - declared_tools:
        findings.append(Finding("undeclared_registration", HIGH, "Registered tools not declared in plugin.yaml",
                                sorted(reg_tools - declared_tools)))
    if reg_hooks - declared_hooks:
        findings.append(Finding("undeclared_registration", HIGH, "Registered hooks not declared in plugin.yaml",
                                sorted(reg_hooks - declared_hooks)))
    if declared_tools - reg_tools:
        findings.append(Finding("declared_not_registered", LOW, "Declared tools that were not registered",
                                sorted(declared_tools - reg_tools)))

    stubbed = result.get("stubbed_modules") or []
    if stubbed:
        findings.append(Finding("coverage_stubbed_imports", INFO,
                                "Ran with stand-ins for modules the sandbox does not have; "
                                "activity through them was not observed", stubbed[:30]))

    # ---- errors ---------------------------------------------------------------
    for phase in ("import", "register"):
        info = result.get(phase) or {}
        if not info.get("ok", False):
            if stubbed:
                # Likely tripped over a stand-in module, so this is a coverage gap,
                # not behaviour. Everything the plugin did before failing is still judged.
                findings.append(Finding("coverage_incomplete", LOW,
                                        f"Plugin stopped during {phase}, probably because of a stand-in module; "
                                        "code after that point was not observed", [str(info.get("error"))]))
            else:
                findings.append(Finding("load_error", MEDIUM, f"Plugin failed during {phase}",
                                        [str(info.get("error"))]))

    return {
        "verdict": _verdict(findings),
        "findings": [f.to_dict() for f in sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))],
        "registered": registered,
    }


SENSITIVE_HOME = (".ssh", ".aws", ".config", ".gnupg", ".local", ".kube", ".docker")
SENSITIVE_HERMES = ("plugins", "skills", "hooks", "memories", "hermes-agent", "cron")


def _write_severity(path: str, home, hermes_home) -> str:
    if home and _under(path, [home]):
        rel = os.path.relpath(os.path.normpath(path), home).split(os.sep)
        if hermes_home and rel[0] == ".hermes":
            if len(rel) <= 2 or rel[1] in SENSITIVE_HERMES:
                return HIGH  # config.yaml, .env, SOUL.md, other plugins, skills...
            return MEDIUM    # its own subfolder, e.g. ~/.hermes/<name>/
        if len(rel) == 1 or rel[0] in SENSITIVE_HOME:
            return HIGH      # ~/.bashrc, ~/.ssh/..., ~/.config/autostart/...
        return MEDIUM        # its own folder, e.g. ~/.<name>/
    if _under(path, ["/tmp"]):
        return LOW
    return HIGH


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
