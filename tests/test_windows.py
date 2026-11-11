"""Windows support checks that run on any OS (CI also runs the whole suite on Windows)."""

import subprocess
from pathlib import Path, PureWindowsPath

from engine import runner

ROOT = Path(__file__).resolve().parents[1]


def test_windows_containers_mode_gets_a_clear_fix(monkeypatch):
    """Docker Desktop on Windows can be switched to Windows containers; the sandbox needs Linux."""
    monkeypatch.setattr(runner, "docker_bin", lambda: "docker")
    monkeypatch.setattr(runner, "_run", lambda cmd, timeout=600, **kw:
                        subprocess.CompletedProcess(cmd, 0, stdout="27.4.0 windows\n", stderr=""))
    msg = runner.docker_problem("windows")
    assert msg and "Switch to Linux containers" in msg
    assert not runner.docker_available()


def test_linux_engine_is_ready(monkeypatch):
    monkeypatch.setattr(runner, "docker_bin", lambda: "docker")
    monkeypatch.setattr(runner, "_run", lambda cmd, timeout=600, **kw:
                        subprocess.CompletedProcess(cmd, 0, stdout="27.4.0 linux\n", stderr=""))
    assert runner.docker_problem("windows") is None


def test_windows_settings_reach_git_and_docker_but_keys_do_not(monkeypatch):
    for name, value in {"PROGRAMFILES": r"C:\Program Files", "PATHEXT": ".COM;.EXE",
                        "COMSPEC": r"C:\Windows\system32\cmd.exe", "USERPROFILE": r"C:\Users\t",
                        "WINDIR": r"C:\Windows", "OPENAI_API_KEY": "sk-real-looking"}.items():
        monkeypatch.setenv(name, value)
    env = runner._env()
    assert env["PROGRAMFILES"] == r"C:\Program Files" and env["USERPROFILE"] == r"C:\Users\t"
    assert "PATHEXT" in env and "COMSPEC" in env and "WINDIR" in env
    assert "OPENAI_API_KEY" not in env


def test_docker_run_mounts_use_clean_windows_paths():
    tmp = PureWindowsPath(r"C:\Users\t\AppData\Local\Temp\detonator-x")
    cmd = runner.docker_run_cmd("img:1", tmp / "plugin", tmp / "in", tmp / "out", runner.random_world(),
                                tmp / "etc")
    mounts = [cmd[i + 1] for i, c in enumerate(cmd) if c == "-v"]
    assert mounts[0] == rf"{tmp}\plugin:/plugin:ro"
    assert mounts[2] == rf"{tmp}\out:/out:rw"
    assert rf"{tmp}\etc\{runner._ACCOUNT_FILES[0]}:/etc/{runner._ACCOUNT_FILES[0]}:ro" in mounts
    assert all("/" not in m.split(":/")[0][2:] for m in mounts)  # no mixed \ and / in host paths


def test_files_are_checked_out_with_lf_everywhere():
    """Git for Windows converts line endings unless told not to; the sandbox image must not change."""
    assert "eol=lf" in (ROOT / ".gitattributes").read_text()


def test_sandbox_files_have_no_windows_line_endings():
    for f in (ROOT / "sandbox").iterdir():
        if f.is_file() and f.suffix != ".pyc":
            assert b"\r\n" not in f.read_bytes(), f.name
