"""Compare two detonations of the same plugin (an older and a newer commit).

A plugin can pass review at one commit and change behaviour in the next
("rug pull"). The catalog pins exact commits and re-reviews every bump, so the
useful question at bump time is: what does the new commit DO that the old one
did not? This module answers that from two evaluations. It never decides on
its own: the verdict of each side still comes from the same rules.
"""

from __future__ import annotations

import json

from .rules import SEVERITY_ORDER

VERDICT_RANK = {"NO_FINDINGS": 0, "REVIEW": 1, "SUSPICIOUS": 2, "DANGEROUS": 3, "ERROR": -1}
CAPABILITY_KEYS = ("provides_tools", "provides_hooks", "requires_env")


def _key(finding: dict) -> tuple:
    return (finding.get("rule"), finding.get("title"))


def _item(value) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)


def _caps(manifest: dict | None) -> dict:
    manifest = manifest or {}
    out = {}
    for key in CAPABILITY_KEYS:
        value = manifest.get(key) or []
        if not isinstance(value, (list, tuple)):
            value = [value]
        out[key] = sorted(str(v.get("name") if isinstance(v, dict) else v) for v in value)
    return out


def compare(old_eval: dict, new_eval: dict, old_raw: dict | None = None, new_raw: dict | None = None) -> dict:
    """Return what changed between two evaluations, newest behaviour first by severity."""
    old_by = {_key(f): f for f in old_eval.get("findings") or []}
    new_by = {_key(f): f for f in new_eval.get("findings") or []}

    added, removed, grew = [], [], []
    for key, f in new_by.items():
        if key not in old_by:
            added.append(f)
            continue
        before = {_item(e) for e in old_by[key].get("evidence") or []}
        extra = [e for e in f.get("evidence") or [] if _item(e) not in before]
        if extra:
            grew.append({**f, "evidence": extra})
    for key, f in old_by.items():
        if key not in new_by:
            removed.append(f)

    order = lambda f: SEVERITY_ORDER.index(f["severity"]) if f.get("severity") in SEVERITY_ORDER else 99
    added.sort(key=order)
    grew.sort(key=order)
    removed.sort(key=order)

    old_caps = _caps((old_raw or {}).get("manifest"))
    new_caps = _caps((new_raw or {}).get("manifest"))
    declared = {}
    for key in CAPABILITY_KEYS:
        plus = sorted(set(new_caps[key]) - set(old_caps[key]))
        minus = sorted(set(old_caps[key]) - set(new_caps[key]))
        if plus or minus:
            declared[key] = {"added": plus, "removed": minus}

    old_v, new_v = old_eval.get("verdict", "ERROR"), new_eval.get("verdict", "ERROR")
    if "ERROR" in (old_v, new_v):
        direction = "error"
    elif VERDICT_RANK[new_v] > VERDICT_RANK[old_v]:
        direction = "worse"
    elif VERDICT_RANK[new_v] < VERDICT_RANK[old_v]:
        direction = "better"
    elif added or grew:
        direction = "changed"
    else:
        direction = "same"

    return {
        "old_verdict": old_v,
        "new_verdict": new_v,
        "direction": direction,
        "new_behaviour": added,
        "more_of": grew,
        "gone": removed,
        "declared_changes": declared,
    }


HEADLINE = {
    "worse": "⚠️ NEW VERSION IS RISKIER: it does things the old version did not.",
    "changed": "🟡 SAME VERDICT, NEW BEHAVIOUR: the new version does some things the old one did not.",
    "same": "🟢 NO NEW BEHAVIOUR: the new version did nothing the old one did not do.",
    "better": "🟢 NEW VERSION IS LESS RISKY: some risky behaviour went away.",
    "error": "⚪ COULD NOT COMPARE: one of the two runs failed (see its report).",
}

NOTABLE = ("critical", "high", "medium")


def _finding_line(f: dict) -> str:
    ids = ", ".join((f.get("attack") or []) + (f.get("atlas") or []))
    return f"[{f.get('severity')}] {f.get('title')}" + (f" ({ids})" if ids else "")


def summary(diff: dict, old_sha: str, new_sha: str, paths=()) -> str:
    lines = [HEADLINE[diff["direction"]],
             f"Verdict: {diff['old_verdict']} ({old_sha[:8]}) → {diff['new_verdict']} ({new_sha[:8]})"]
    shown = [f for f in diff["new_behaviour"] + diff["more_of"] if f.get("severity") in NOTABLE]
    if shown:
        lines.append("New in this version:")
        for f in shown[:6]:
            lines.append(f"+ {_finding_line(f)}")
            if f.get("severity") in ("critical", "high") and f.get("why"):
                lines.append(f"  Why: {f['why']}")
    gone = [f for f in diff["gone"] if f.get("severity") in NOTABLE]
    if gone:
        lines.append("No longer seen:")
        lines.extend(f"- {_finding_line(f)}" for f in gone[:4])
    for key, change in diff["declared_changes"].items():
        parts = [f"+{x}" for x in change["added"]] + [f"-{x}" for x in change["removed"]]
        lines.append(f"Declared {key} changed: {' '.join(parts)}")
    for p in paths:
        lines.append(f"Report: {p}")
    lines.append("Advisory only: this compares what each version did in the sandbox; you decide.")
    return "\n".join(lines)


def render(label: str, old_sha: str, new_sha: str, diff: dict) -> str:
    out = [f"# Detonator version diff: {label}", "",
           f"**{HEADLINE[diff['direction']]}**", "",
           f"| | Commit | Verdict |", "|---|---|---|",
           f"| Old | `{old_sha}` | {diff['old_verdict']} |",
           f"| New | `{new_sha}` | {diff['new_verdict']} |", ""]

    def table(title, items):
        if not items:
            return
        out.extend([f"## {title}", "", "| Severity | Finding | MITRE | Evidence |", "|---|---|---|---|"])
        for f in items:
            ids = ", ".join((f.get("attack") or []) + (f.get("atlas") or [])) or "—"
            ev = "; ".join(_item(e) for e in (f.get("evidence") or [])[:5]).replace("|", "\\|") or "—"
            out.append(f"| {f.get('severity')} | {f.get('title')} | {ids} | {ev} |")
        out.append("")

    table("New behaviour in the new version", diff["new_behaviour"])
    table("More of an existing behaviour", diff["more_of"])
    table("No longer seen", diff["gone"])
    if diff["declared_changes"]:
        out.extend(["## Declared capability changes", ""])
        for key, change in diff["declared_changes"].items():
            out.append(f"- `{key}`: added {change['added'] or 'nothing'}, removed {change['removed'] or 'nothing'}")
        out.append("")
    out.append("Each version also has its own full report. This diff is advisory: it shows what "
               "changed in observed behaviour, not whether the change is acceptable.")
    return "\n".join(out) + "\n"
