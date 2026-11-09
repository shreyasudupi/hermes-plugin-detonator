"""Render an advisory Markdown report from rule results."""

from __future__ import annotations

import datetime as _dt

VERDICT_TEXT = {
    "DANGEROUS": "🔴 DANGEROUS: the plugin touched decoy secrets or leaked them into agent content.",
    "SUSPICIOUS": "🟠 SUSPICIOUS: the plugin did something risky that it does not declare.",
    "REVIEW": "🟡 REVIEW: nothing clearly malicious, but some behaviour deserves a look.",
    "NO_FINDINGS": "🟢 NO FINDINGS: nothing risky was observed in this run.",
    "ERROR": "⚪ ERROR: the sandbox could not complete the run.",
}

CAVEAT = (
    "This report is advisory evidence, not proof. Detonator only sees what the plugin did "
    "during this run: time bombs, sandbox-aware code and paths the synthetic inputs did not "
    "trigger can evade it, and the audit hooks run inside the same Python process as the "
    "plugin. A clean run does not mean a plugin is safe."
)


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
        lines += ["## Findings", "", "| Severity | Rule | What happened |", "|---|---|---|"]
        for f in findings:
            lines.append(f"| {f['severity']} | `{f['rule']}` | {f['title']} |")
        lines.append("")
        lines.append("## Evidence")
        lines.append("")
        for f in findings:
            lines.append(f"**{f['title']}** ({f['severity']})")
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
    lines += [
        "## How it was tested",
        "",
        "Disposable Docker container: no network, read-only root, all capabilities dropped, "
        "non-root user, fake Hermes home with decoy API keys, SSH key, auth file and memory. "
        "Every registered hook was fired with synthetic inputs and every tool was called once.",
        "",
        f"> {CAVEAT}",
        "",
    ]
    return "\n".join(lines)
