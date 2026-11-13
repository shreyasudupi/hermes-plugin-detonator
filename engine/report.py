"""Render an advisory Markdown report from rule results."""

from __future__ import annotations

import datetime as _dt

VERDICT_TEXT = {
    "DANGEROUS": "🔴 DANGEROUS: the plugin did something stealers and malware do (took or leaked decoy "
                 "secrets, set itself up to start automatically, or hid from or fooled the test).",
    "SUSPICIOUS": "🟠 SUSPICIOUS: the plugin did something risky (hidden, undeclared or aimed at the "
                  "model or your system) that needs a close look before you install it.",
    "REVIEW": "🟡 REVIEW: nothing clearly malicious, but some behaviour deserves a look.",
    "NO_FINDINGS": "🟢 NO FINDINGS: nothing risky was observed in this run.",
    "ERROR": "⚪ ERROR: the sandbox could not complete the run, so the plugin was NOT tested. Treat it as unknown, not as safe.",
}

CAVEAT = (
    "This report is advisory evidence, not proof. Detonator only sees what the plugin did "
    "during this run: time bombs, sandbox-aware code and paths the synthetic inputs did not "
    "trigger can evade it. The in-process monitor runs inside the plugin's own Python process, "
    "so a determined plugin could tamper with it; the outside monitor (a tracer and a fake internet "
    "in separate containers) checks it from where the plugin cannot reach. A clean run does not "
    "mean a plugin is safe."
)
CAVEAT_NO_OUTSIDE = (
    "This report is advisory evidence, not proof. Detonator only sees what the plugin did "
    "during this run: time bombs, sandbox-aware code and paths the synthetic inputs did not "
    "trigger can evade it. The outside monitor did not run, so only the in-process monitor watched, "
    "and it runs inside the plugin's own Python process: a determined plugin could tamper with it or "
    "fake a clean result. A clean run does not mean a plugin is safe."
)


def outside_lines(summary: dict | None) -> list:
    """The report's "Outside monitor" section."""
    s = summary or {}
    lines = ["## Outside monitor", ""]
    if not s.get("ran"):
        lines += [f"Did not run: {s.get('reason') or 'unknown reason'}. Only the in-process monitor "
                  "watched this plugin.", ""]
        return lines
    if s.get("traced"):
        lines.append("- Tracer: attached before the plugin loaded and followed every thread and program it started.")
    else:
        lines.append(f"- Tracer: ⚠️ {s.get('tracer_problem') or 'did not attach'}, so its cross-check is missing.")
    if s.get("trace_truncated"):
        lines.append("- ⚠️ The trace was very long, so its middle was cut; the start and end were kept.")
    lines.append("- Fake internet: " + ("answered every lookup and connection; no real network was reachable."
                                         if s.get("fake_internet") else "⚠️ did not start."))
    lines.append(f"- Names looked up: {', '.join(s.get('lookups') or []) or 'none'}")
    lines.append(f"- Connections: {'; '.join(s.get('connections') or []) or 'none'}")
    if s.get("programs"):
        lines.append(f"- Programs started: {'; '.join(s['programs'])}")
    lines.append("")
    return lines


def mitre_url(tech: str) -> str:
    if tech.startswith("AML."):
        return f"https://atlas.mitre.org/techniques/{tech}"
    return "https://attack.mitre.org/techniques/" + tech.replace(".", "/") + "/"


def mitre_links(finding: dict) -> str:
    parts = [f"[{t}]({mitre_url(t)})" for t in (finding.get("attack") or []) + (finding.get("atlas") or [])]
    return " · ".join(parts)


def render(label: str, evaluation: dict, raw: dict | None = None) -> str:
    raw = raw or {}
    verdict = evaluation.get("verdict", "ERROR")
    lines = [
        f"# Detonator report: {label}",
        "",
        f"**Verdict: {VERDICT_TEXT.get(verdict, verdict)}**",
        "",
        f"_Generated {_dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}. "
        "Verdict decided by deterministic rules only._",
        "",
    ]
    if verdict == "ERROR":
        lines += ["```", str(evaluation.get("detail") or raw.get("fatal") or "unknown error")[:2000], "```", ""]
    findings = evaluation.get("findings") or []
    if findings:
        lines += ["## Findings", "", "| Severity | What happened | MITRE |", "|---|---|---|"]
        for f in findings:
            ids = ", ".join((f.get("attack") or []) + (f.get("atlas") or [])) or "–"
            lines.append(f"| {f['severity']} | {f['title']} | {ids} |")
        lines.append("")
        lines.append("## Why each finding matters")
        lines.append("")
        for f in findings:
            lines.append(f"### {f['title']} ({f['severity']})")
            lines.append("")
            if f.get("why"):
                lines.append(f"**Why:** {f['why']}")
                lines.append("")
            refs = mitre_links(f)
            if refs:
                lines.append(f"**MITRE:** {refs}")
                lines.append("")
            lines.append("**Evidence:**")
            for ev in f.get("evidence") or []:
                lines.append(f"- `{str(ev)[:300]}`")
            lines.append("")
    reg = evaluation.get("registered") or raw.get("registered") or {}
    if reg:
        lines += [
            "## What the plugin registered",
            "",
            f"- Tools: {', '.join(reg.get('tools') or []) or 'none'}",
            f"- Hooks: {', '.join(reg.get('hooks') or []) or 'none'}",
            "",
        ]
    summary = evaluation.get("outside")
    lines += outside_lines(summary)
    ran = bool((summary or {}).get("ran"))
    lines += [
        "## How it was tested",
        "",
        "Disposable Docker container: no real network, read-only root, all capabilities dropped, "
        "non-root user, fake Hermes home with decoy API keys, SSH key, auth file, git/npm/PyPI/cloud "
        "credentials, browser passwords, crypto wallets, memory and chat history. "
        "Every registered hook was fired with synthetic inputs and every tool was called once."
        + (" Two more containers the plugin cannot reach watched it from outside: a tracer that "
           "records the files, programs and connections the kernel saw, and a fake internet that "
           "answers every address and logs what is sent." if ran else ""),
        "",
        "Technique IDs are from MITRE ATT&CK (Enterprise) and MITRE ATLAS (AI systems). They describe "
        "what the observed behaviour resembles; they are not a claim about the author's intent.",
        "",
        f"> {CAVEAT if ran else CAVEAT_NO_OUTSIDE}",
        "",
    ]
    return "\n".join(lines)
