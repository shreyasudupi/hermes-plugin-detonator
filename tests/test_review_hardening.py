"""Hardening from the Nov 20 project review (v0.5.2): personal git settings left out of fetches,
a run that fills the disk is stopped, and the test-only config switch stays in its folder."""

import os
import shutil
import subprocess
import sys
import time

import pytest

from engine import mcp, rules, runner

GIT = shutil.which("git")


@pytest.fixture
def fresh_git_cache(monkeypatch):
    monkeypatch.setattr(runner, "_git_keep_cache", None)


def _write_gitconfig(home, marker):
    home.mkdir(exist_ok=True)
    (home / ".gitconfig").write_text(
        '[filter "lfs"]\n'
        f"\tsmudge = {sys.executable} -c \"open(r'{marker}', 'w')\"\n"
        "\trequired = true\n"
        "[http]\n\tproxy = http://proxy.example:3128\n"
        "[core]\n\tpager = something-else\n", encoding="utf-8")


@pytest.mark.skipif(GIT is None, reason="needs git")
def test_git_keeps_only_proxy_and_certificate_settings(tmp_path, monkeypatch, fresh_git_cache):
    home = tmp_path / "home"
    _write_gitconfig(home, tmp_path / "ran")
    monkeypatch.setenv("HOME", str(home))
    kept = runner._git_kept_settings()
    assert kept == ["-c", "http.proxy=http://proxy.example:3128"]
    listing = runner._run(["git", "config", "--list"], cwd=str(tmp_path)).stdout
    assert "filter.lfs" not in listing and "core.pager" not in listing
    assert "http.proxy=http://proxy.example:3128" in listing


@pytest.mark.skipif(GIT is None, reason="needs git")
def test_a_filter_from_your_git_config_never_runs_on_a_downloaded_repo(tmp_path, monkeypatch, fresh_git_cache):
    marker = tmp_path / "ran"
    home = tmp_path / "home"
    _write_gitconfig(home, marker)
    # The source repo is made without any personal config, so its file is stored as is.
    src = tmp_path / "src"
    clean = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    for cmd in (["git", "init", "-q", str(src)],):
        subprocess.run(cmd, check=True, env=clean)
    (src / ".gitattributes").write_text("a.txt filter=lfs\n", encoding="utf-8")
    (src / "a.txt").write_text("hi\n", encoding="utf-8")
    for cmd in (["git", "-C", str(src), "add", "-A"],
                ["git", "-C", str(src), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                 "commit", "-qm", "x"]):
        subprocess.run(cmd, check=True, env=clean, capture_output=True)
    monkeypatch.setenv("HOME", str(home))
    dest = tmp_path / "dest"
    for cmd in (["git", "init", "-q", str(dest)],
                ["git", "-C", str(dest), "-c", "protocol.file.allow=always", "fetch", "-q", str(src), "HEAD"],
                ["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"]):
        assert runner._run(cmd, timeout=60).returncode == 0
    assert (dest / "a.txt").read_text(encoding="utf-8") == "hi\n"
    assert not marker.exists()


def test_folder_bytes_counts_files_and_never_follows_links(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f").write_bytes(b"x" * 100_000)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "big").write_bytes(b"y" * 2_000_000)
    try:
        os.symlink(outside, tmp_path / "link")
    except (OSError, NotImplementedError):
        pass
    n = runner.folder_bytes(tmp_path)
    assert 100_000 <= n < 1_000_000
    shutil.rmtree(outside)


def test_a_sparse_file_does_not_count_as_full(tmp_path):
    if not hasattr(os.stat(tmp_path), "st_blocks"):
        pytest.skip("no block counts on this system")
    with open(tmp_path / "sparse", "wb") as f:
        f.seek(10 * 1024 * 1024 * 1024)
        f.write(b"x")
    assert runner.folder_bytes(tmp_path) < 1024 * 1024


def test_run_is_stopped_when_the_watched_folder_grows_too_big(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "DISK_POLL_S", 0.05)
    out = tmp_path / "out"
    out.mkdir()
    writer = ("import sys, time\n"
              "f = open(sys.argv[1], 'wb')\n"
              "for _ in range(400):\n"
              "    f.write(b'z' * 65536); f.flush(); time.sleep(0.01)\n")
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    stopped = []

    def stop():
        stopped.append(True)
        proc.kill()
    # The "run" is a child that writes; stop() ends the sleeper standing in for the container.
    cmd = [sys.executable, "-c", writer + "import time; time.sleep(5)", str(out / "fill.bin")]
    started = time.monotonic()
    result, over = runner._run_watched(cmd, 30, stop, [(out, 1_000_000)])
    assert over == (out, 1_000_000) and stopped
    assert time.monotonic() - started < 25
    proc.wait(timeout=5)


def test_run_under_the_limit_is_left_alone(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    result, over = runner._run_watched([sys.executable, "-c", "print('ok')"], 30,
                                       lambda: pytest.fail("must not stop"), [(out, 1_000_000)])
    assert over is None and result.stdout.strip() == "ok"


def test_watched_run_times_out_like_run(tmp_path):
    with pytest.raises(subprocess.TimeoutExpired):
        runner._run_watched([sys.executable, "-c", "import time; time.sleep(5)"], 0.5,
                            lambda: None, [(tmp_path, 1_000_000)])


def _flood_result(where):
    return {"fatal": "sandbox stopped: the tested code wrote more than 256 MB to the sandbox's output "
                     "folder on your disk, so the run was ended early",
            "disk_flood": where, "outside": {"ran": False}}


def test_disk_flood_in_the_output_folder_is_a_high_finding():
    out = rules.evaluate(_flood_result("out"))
    assert out["verdict"] == rules.VERDICT_SUSPICIOUS
    assert [f["rule"] for f in out["findings"]] == ["disk_flood"]


def test_package_folder_growth_is_an_error_not_a_finding():
    out = rules.evaluate(_flood_result("package"))
    assert out["verdict"] == rules.VERDICT_ERROR and not out["findings"]


def test_config_switch_cannot_read_a_file_outside_the_tested_folder(tmp_path):
    secret_cfg = tmp_path / "elsewhere.yaml"
    secret_cfg.write_text("mcp_servers:\n  real:\n    command: npx\n    args: [\"-y\", \"x@1.0.0\"]\n",
                          encoding="utf-8")
    folder = tmp_path / "server"
    folder.mkdir()
    for ref in ("../elsewhere.yaml", str(secret_cfg)):
        (folder / "mcp-server.yaml").write_text(
            f"_detonator_config: {ref!r}\n_detonator_server: real\n", encoding="utf-8")
        with pytest.raises(mcp.McpError, match="inside the tested folder"):
            mcp.load_folder_entry(str(folder))


def test_config_switch_still_works_inside_the_folder(tmp_path):
    folder = tmp_path / "server"
    folder.mkdir()
    (folder / "config.yaml").write_text("mcp_servers:\n  real:\n    command: npx\n"
                                        "    args: [\"-y\", \"x@1.0.0\"]\n", encoding="utf-8")
    (folder / "mcp-server.yaml").write_text("_detonator_config: config.yaml\n_detonator_server: real\n",
                                            encoding="utf-8")
    target = mcp.load_folder_entry(str(folder))
    assert target.config_only


def _ran(io_uring):
    return {"outside": {"ran": True, "tracer": {"io_uring": io_uring},
                        "trace": {"events": [], "start_index": 0}, "sink": {"ready": True, "every_port": True}}}


def test_report_warns_when_docker_allows_io_uring():
    from engine import report
    lines = "\n".join(report.outside_lines(rules.outside_summary(_ran("allowed"))))
    assert "io_uring" in lines and "update Docker" in lines


def test_no_io_uring_warning_when_blocked_or_unknown():
    from engine import report
    for state in ("blocked", "unknown", None):
        assert "io_uring" not in "\n".join(report.outside_lines(rules.outside_summary(_ran(state))))


def test_npm_download_refuses_git_and_web_dependencies(tmp_path, monkeypatch):
    from engine import mcp_sources as sources
    seen = []
    monkeypatch.setattr(sources, "_run_fetch", lambda cmd, what: seen.append(cmd))

    class NoProxy:
        def __enter__(self):
            return []

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(sources, "_ProxySetup", NoProxy)
    sources.fetch_npm(sources.Plan(kind="npm", package="x", version="1.0.0", pinned=True), tmp_path / "w")
    argv = seen[0]
    assert "--ignore-scripts" in argv and "--allow-git=none" in argv and "--allow-remote=none" in argv


def test_ci_pins_the_fixtures_commit_and_keeps_the_token_in_one_step():
    import pathlib
    import re
    ci = (pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert re.search(r"FIXTURES_REF: [0-9a-f]{40}\n", ci)
    assert ci.count("secrets.FIXTURES_TOKEN") == 2      # the "is it set" check and the checkout step
    assert "FIXTURES_TOKEN: ${{" not in ci             # never in a job-wide environment


def test_a_flood_of_empty_files_counts_as_full(tmp_path):
    for i in range(300):
        (tmp_path / f"e{i}").touch()
    assert runner.folder_bytes(tmp_path) >= 300 * 4096
