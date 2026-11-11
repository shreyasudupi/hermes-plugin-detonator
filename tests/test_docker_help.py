"""Plain-language Docker errors and `/detonate check` (no Docker needed for these tests)."""

import subprocess

import commands
from engine import runner

# Real error text from the Docker CLI and BuildKit.
NOT_RUNNING_LINUX = ("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
                     "Is the docker daemon running?")
NOT_RUNNING_MAC = ("Cannot connect to the Docker daemon at unix:///Users/a/.docker/run/docker.sock. "
                   "Is the docker daemon running?")
NO_PERMISSION = ("permission denied while trying to connect to the Docker daemon socket at "
                 "unix:///var/run/docker.sock: Get \"http://%2Fvar%2Frun%2Fdocker.sock/v1.47/info\": "
                 "dial unix /var/run/docker.sock: connect: permission denied")
NO_SPACE = "failed to copy files: write /var/lib/docker/tmp/x: no space left on device"
OFFLINE = ("ERROR: failed to solve: python:3.11-slim@sha256:abc: failed to resolve source metadata for "
           "docker.io/library/python: dial tcp: lookup registry-1.docker.io: no such host")
RATE_LIMIT = "toomanyrequests: You have reached your unauthenticated pull rate limit."
MOUNTS = "docker: Error response from daemon: Mounts denied: The path /var/folders/x is not shared from the host"


def test_each_common_problem_gets_a_specific_fix():
    assert "Open Docker Desktop" in runner.explain_docker_error(NOT_RUNNING_MAC, "mac")
    assert "systemctl start docker" in runner.explain_docker_error(NOT_RUNNING_LINUX, "linux")
    assert "docker group" in runner.explain_docker_error(NO_PERMISSION, "linux")
    assert "docker system prune" in runner.explain_docker_error(NO_SPACE)
    assert "download the base image" in runner.explain_docker_error(OFFLINE)
    assert "docker login" in runner.explain_docker_error(RATE_LIMIT)
    assert "File sharing" in runner.explain_docker_error(MOUNTS)
    assert runner.explain_docker_error("something nobody has seen before") is None


def test_permission_problem_is_not_mistaken_for_docker_being_stopped():
    msg = runner.explain_docker_error(NO_PERMISSION, "linux")
    assert "not running" not in msg


def test_missing_docker_says_where_to_get_it(monkeypatch):
    monkeypatch.setattr(runner, "docker_bin", lambda: None)
    mac = runner.docker_problem("mac")
    assert "Docker Desktop for Mac" in mac and "docs.docker.com" in mac
    assert not runner.docker_available()


def _fake_info(monkeypatch, returncode=1, stderr="", raises=None):
    monkeypatch.setattr(runner, "docker_bin", lambda: "/usr/bin/docker")

    def fake_run(cmd, timeout=600, **kwargs):
        if raises:
            raise raises
        return subprocess.CompletedProcess(cmd, returncode, stdout="27.0.1\n", stderr=stderr)

    monkeypatch.setattr(runner, "_run", fake_run)


def test_stopped_daemon_and_slow_start(monkeypatch):
    _fake_info(monkeypatch, stderr=NOT_RUNNING_MAC)
    assert "not running" in runner.docker_problem("mac")
    _fake_info(monkeypatch, raises=subprocess.TimeoutExpired("docker", 20))
    assert "still be starting" in runner.docker_problem("mac")


def test_unknown_error_still_shows_dockers_words(monkeypatch):
    _fake_info(monkeypatch, stderr="weird context error 42")
    assert "weird context error 42" in runner.docker_problem("linux")


def test_check_reports_ready_and_missing_image(monkeypatch):
    calls = []

    def fake_run(cmd, timeout=600, **kwargs):
        calls.append(cmd[1])
        return subprocess.CompletedProcess(cmd, 0 if cmd[1] == "info" else 1, stdout="", stderr="")

    monkeypatch.setattr(runner, "docker_bin", lambda: "/usr/bin/docker")
    monkeypatch.setattr(runner, "_run", fake_run)
    out = runner.docker_check()
    assert out.startswith("Docker: ready.") and "not built yet" in out
    assert calls == ["info", "image"]  # read-only: no build, pull or run


def test_slash_check_runs_nothing_and_asks_nothing(monkeypatch):
    class Ctx:
        def ask_choice(self, *a, **k):
            raise AssertionError("check must not ask to run anything")

    monkeypatch.setattr(commands, "runner", runner, raising=False)  # set by the package import in Hermes
    monkeypatch.setattr(runner, "docker_check", lambda: "Docker: ready.")
    handle = commands.make_slash_handler(Ctx())
    assert handle("check") == "Docker: ready."
    assert handle(" Doctor ") == "Docker: ready."


def test_build_failure_explains_the_fix(monkeypatch):
    monkeypatch.setattr(runner, "_run", lambda cmd, timeout=600, **k: subprocess.CompletedProcess(
        cmd, 1, stdout="", stderr=OFFLINE))
    try:
        runner.ensure_image()
    except runner.DetonatorError as exc:
        assert "download the base image" in str(exc) and "no such host" in str(exc)
    else:
        raise AssertionError("expected DetonatorError")
