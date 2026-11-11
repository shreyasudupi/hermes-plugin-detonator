"""git and docker must not inherit Hermes's API keys (catalog review of 4026b2f8)."""

import subprocess

from engine import runner


def test_child_env_drops_api_keys_and_keeps_what_docker_needs(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-real-looking")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real-looking")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_real_looking")
    monkeypatch.setenv("SOME_RANDOM_SETTING", "x")
    monkeypatch.setenv("DOCKER_HOST", "unix:///tmp/colima.sock")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8080")
    monkeypatch.setenv("HOME", "/home/tester")
    env = runner._env()
    for secret in ("OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "SOME_RANDOM_SETTING"):
        assert secret not in env
    assert env["DOCKER_HOST"] == "unix:///tmp/colima.sock"
    assert env["HTTPS_PROXY"] == "http://proxy.example:8080"
    assert env["HOME"] == "/home/tester"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert "PATH" in env


def test_every_subprocess_gets_the_minimal_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-looking")
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs["env"])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    runner._run(["git", "--version"])
    assert seen and "OPENAI_API_KEY" not in seen


def test_real_child_process_sees_no_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-looking")
    out = runner._run(["env"], timeout=10).stdout
    assert "OPENAI_API_KEY" not in out and "GIT_TERMINAL_PROMPT=0" in out
