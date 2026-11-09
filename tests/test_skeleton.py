import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load_plugin():
    spec = importlib.util.spec_from_file_location(
        "detonator_plugin", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["detonator_plugin"] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeCtx:
    def __init__(self, choice=None):
        self.tools, self.commands, self.cli = {}, {}, {}
        self.choice = choice
        self.asked = []

    def register_tool(self, name, toolset, schema, handler):
        self.tools[name] = (toolset, schema, handler)

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands[name] = handler

    def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
        self.cli[name] = (setup_fn, handler_fn)

    def ask_choice(self, question, choices):
        self.asked.append(question)
        return self.choice


SHA = "a" * 40


def test_register_matches_manifest():
    plugin = _load_plugin()
    ctx = FakeCtx()
    plugin.register(ctx)
    assert set(ctx.tools) == {"detonate_plugin"}
    assert set(ctx.commands) == {"detonate"}
    assert set(ctx.cli) == {"detonate"}
    text = (ROOT / "plugin.yaml").read_text()
    assert "- detonate_plugin" in text


def test_tool_never_runs_and_asks_for_user_command():
    plugin = _load_plugin()
    ctx = FakeCtx()
    plugin.register(ctx)
    handler = ctx.tools["detonate_plugin"][2]
    assert "error" in json.loads(handler({"repo": "x", "sha": "abc"}))
    ok = json.loads(handler({"repo": "a/b", "sha": SHA}))
    assert ok["status"] == "needs_user_approval"
    assert ok["command"] == f"/detonate a/b {SHA}"


def test_slash_command_refuses_without_approval(monkeypatch):
    plugin = _load_plugin()
    ran = []
    monkeypatch.setattr(plugin.commands, "run_detonation", lambda *a: ran.append(a))
    for answer in (None, "cancel", "something else"):
        ctx = FakeCtx(choice=answer)
        plugin.register(ctx)
        out = ctx.commands["detonate"](f"a/b {SHA}")
        assert out.startswith("Not run")
        assert ctx.asked, "must ask before running"
    assert ran == []


def test_slash_command_runs_only_after_yes(monkeypatch, tmp_path):
    plugin = _load_plugin()
    path = tmp_path / "r.md"
    monkeypatch.setattr(plugin.commands, "run_detonation",
                        lambda repo, sha, subdir: ({"verdict": "NO_FINDINGS", "findings": []}, "", path))
    ctx = FakeCtx(choice="run")
    plugin.register(ctx)
    out = ctx.commands["detonate"](f"a/b {SHA}")
    assert "NO FINDINGS" in out and str(path) in out


def test_slash_command_validates_input():
    plugin = _load_plugin()
    ctx = FakeCtx(choice="run")
    plugin.register(ctx)
    assert "Usage" in ctx.commands["detonate"]("")
    assert "40-character" in ctx.commands["detonate"]("a/b main")
    assert "relative" in ctx.commands["detonate"](f"a/b {SHA} ../etc")
    assert ctx.asked == []


def test_cli_refuses_when_not_a_terminal(monkeypatch, capsys):
    plugin = _load_plugin()
    import argparse
    monkeypatch.setattr(plugin.commands.sys.stdin, "isatty", lambda: False, raising=False)
    rc = plugin.commands.cli_handler(argparse.Namespace(repo="a/b", sha=SHA, subdir=None))
    assert rc == 2
    assert "Refusing" in capsys.readouterr().err


def test_docker_is_found_outside_path(tmp_path, monkeypatch):
    """Apps launched from the Dock don't read shell profiles; Detonator must still find Docker."""
    from engine import runner

    fake = tmp_path / "docker"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setattr(runner, "DOCKER_DIRS", (str(tmp_path),))
    assert runner.docker_bin() == str(fake)
    assert runner._env()["GIT_TERMINAL_PROMPT"] == "0"
