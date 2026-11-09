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
    if reads:
        findings.append(Finding("decoy_accessed", CRITICAL, "Read decoy secret or memory files", reads))
    env_reads = sorted({e["name"] for e in events if e["kind"] == "env_read"})
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
    listed = sorted({e["path"] for e in events if e["kind"] == "dir_list" and e.get("path") in decoy_dirs})
    if listed:
        findings.append(Finding("decoy_dir_listed", MEDIUM, "Listed directories that hold secrets or memory", listed))

    # ---- R2 undeclared network ----------------------------------------------
    net = [e for e in events if e["kind"] == "network"]
    if net:
        findings.append(Finding("undeclared_network", HIGH,
                                "Attempted network access (the sandbox has no network; nothing left the box)",
                                sorted({f'{e.get("op")} {e.get("address")} [{e.get("phase")}]' for e in net})[:20]))

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
            sev = HIGH if hook in ("pre_llm_call", "transform_tool_result", "transform_llm_output",
                                   "transform_terminal_output", "pre_tool_call") else MEDIUM
            title = f"Hook {hook} returned a value Hermes uses to change the {_what_changes(hook)}"
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
    writes = sorted({e["path"] for e in events if e["kind"] == "file_write"})
    outside = [p for p in writes if not _under(p, allowed_writes)]
    tmp_only = [p for p in outside if _under(p, ["/tmp"]) and not _under(p, [os.path.dirname(d) for d in decoy_dirs])]
    serious = [p for p in outside if p not in tmp_only]
    if serious:
        findings.append(Finding("write_outside_folder", HIGH, "Wrote files outside its own plugin folder", serious))
    if tmp_only:
        findings.append(Finding("write_tmp", LOW, "Wrote temporary files", tmp_only[:20]))
    mods = [e for e in events if e["kind"] == "file_modify" and not _under(str(e.get("path")), allowed_writes)]
    if mods:
        findings.append(Finding("write_outside_folder", HIGH, "Deleted, renamed or changed permissions of files outside its folder",
                                sorted({f'{e.get("op")} {e.get("path")}' for e in mods})[:20]))
    native = [e for e in events if e["kind"] == "native"]
    if native:
        findings.append(Finding("native_code", MEDIUM, "Loaded native code via ctypes",
                                sorted({str(e.get("detail")) for e in native})[:10]))
    dyn = [e for e in events if e["kind"] == "dynamic_code"]
    if dyn:
        findings.append(Finding("dynamic_code", MEDIUM, "Compiled or executed code at runtime",
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

    # ---- errors ---------------------------------------------------------------
    for phase in ("import", "register"):
        info = result.get(phase) or {}
        if not info.get("ok", False):
            findings.append(Finding("load_error", MEDIUM, f"Plugin failed during {phase}", [str(info.get("error"))]))

    return {
        "verdict": _verdict(findings),
        "findings": [f.to_dict() for f in sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))],
        "registered": registered,
    }


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
