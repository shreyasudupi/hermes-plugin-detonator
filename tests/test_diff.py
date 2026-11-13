from engine import diff

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from test_skeleton import SHA, FakeCtx, _load_plugin  # noqa: E402

NEW = "b" * 40


def f(rule, sev, title, evidence=(), why="w"):
    return {"rule": rule, "severity": sev, "title": title, "evidence": list(evidence),
            "why": why, "attack": ["T1552.001"], "atlas": []}


CLEAN = {"verdict": "NO_FINDINGS", "findings": [f("write_own_state", "info", "Wrote own data", ["/x"])]}
STEALER = {"verdict": "DANGEROUS", "findings": [
    f("decoy_accessed", "critical", "Read decoy secret files", ["~/.hermes/.env"]),
    f("write_own_state", "info", "Wrote own data", ["/x"]),
]}


def test_new_theft_in_update_is_flagged_as_worse():
    d = diff.compare(CLEAN, STEALER, {"manifest": {"provides_tools": ["a"]}},
                     {"manifest": {"provides_tools": ["a", "b"]}})
    assert d["direction"] == "worse"
    assert [x["rule"] for x in d["new_behaviour"]] == ["decoy_accessed"]
    assert d["gone"] == [] and d["more_of"] == []
    assert d["declared_changes"] == {"provides_tools": {"added": ["b"], "removed": []}}
    text = diff.summary(d, SHA, NEW)
    assert "RISKIER" in text and "NO_FINDINGS (aaaaaaaa) → DANGEROUS (bbbbbbbb)" in text
    assert "+ [critical] Read decoy secret files" in text and "Why:" in text
    assert "+b" in text


def test_identical_runs_report_no_new_behaviour():
    d = diff.compare(STEALER, STEALER)
    assert d["direction"] == "same"
    assert "NO NEW BEHAVIOUR" in diff.summary(d, SHA, NEW)


def test_same_verdict_but_new_evidence_is_called_out():
    more = {"verdict": "DANGEROUS", "findings": [
        f("decoy_accessed", "critical", "Read decoy secret files", ["~/.hermes/.env", "~/.ssh/id_ed25519"])]}
    d = diff.compare(STEALER, more)
    assert d["direction"] == "changed"
    assert d["more_of"][0]["evidence"] == ["~/.ssh/id_ed25519"]


def test_fixed_version_is_better_and_lists_what_went_away():
    d = diff.compare(STEALER, CLEAN)
    assert d["direction"] == "better"
    assert [x["rule"] for x in d["gone"]] == ["decoy_accessed"]
    assert "No longer seen" in diff.summary(d, SHA, NEW)


def test_error_on_either_side_is_not_a_comparison():
    d = diff.compare({"verdict": "ERROR", "findings": []}, CLEAN)
    assert d["direction"] == "error"


def test_render_has_both_commits_and_a_table():
    md = diff.render("a/b", SHA, NEW, diff.compare(CLEAN, STEALER))
    assert SHA in md and NEW in md and "| critical | Read decoy secret files |" in md


def test_slash_command_parses_two_shas_and_asks_once(monkeypatch):
    plugin = _load_plugin()
    calls = []
    monkeypatch.setattr(plugin.commands, "run_comparison",
                        lambda repo, old, new, subdir, outside=None: calls.append((repo, old, new, subdir)) or "DIFF")
    ctx = FakeCtx(choice="run")
    plugin.register(ctx)
    assert ctx.commands["detonate"](f"a/b {SHA} {NEW} sub") == "DIFF"
    assert calls == [("a/b", SHA, NEW, "sub")]
    assert len(ctx.asked) == 1 and "compare" in ctx.asked[0]


def test_slash_command_compare_needs_approval(monkeypatch):
    plugin = _load_plugin()
    calls = []
    monkeypatch.setattr(plugin.commands, "run_comparison", lambda *a: calls.append(a))
    ctx = FakeCtx(choice=None)
    plugin.register(ctx)
    assert ctx.commands["detonate"](f"a/b {SHA} {NEW}").startswith("Not run")
    assert calls == []


def test_compare_rejects_same_sha_and_extra_args():
    plugin = _load_plugin()
    ctx = FakeCtx(choice="run")
    plugin.register(ctx)
    assert "same" in ctx.commands["detonate"](f"a/b {SHA} {SHA}")
    assert "Usage" in ctx.commands["detonate"](f"a/b {SHA} {NEW} sub extra")
    assert ctx.asked == []


def test_run_comparison_writes_a_diff_report(monkeypatch, tmp_path):
    plugin = _load_plugin()
    c = plugin.commands
    monkeypatch.setattr(c, "reports_dir", lambda: tmp_path)
    results = {SHA: (CLEAN, "", tmp_path / "old.md", {"manifest": {}}),
               NEW: (STEALER, "", tmp_path / "new.md", {"manifest": {}})}
    monkeypatch.setattr(c, "run_detonation", lambda repo, sha, subdir, with_raw=False, outside=None: results[sha])
    out = c.run_comparison("a/b", SHA, NEW, None)
    assert "RISKIER" in out
    reports = list(tmp_path.glob("*-vs-*.md"))
    assert len(reports) == 1 and "Detonator version diff" in reports[0].read_text(encoding="utf-8")


def test_tool_passes_new_sha_through():
    import json
    plugin = _load_plugin()
    ctx = FakeCtx()
    plugin.register(ctx)
    handler = ctx.tools["detonate_plugin"][2]
    ok = json.loads(handler({"repo": "a/b", "sha": SHA, "new_sha": NEW}))
    assert ok["command"] == f"/detonate a/b {SHA} {NEW}"
    assert "error" in json.loads(handler({"repo": "a/b", "sha": SHA, "new_sha": "main"}))
