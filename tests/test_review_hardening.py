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
        "[http \"https://git.example.com/\"]\n\tsslCAInfo = /etc/example-ca.pem\n"
        "[credential]\n\thelper = store\n"
        "[url \"https://mirror.example/\"]\n\tinsteadOf = https://github.com/\n"
        "[core]\n\tpager = something-else\n", encoding="utf-8")


@pytest.mark.skipif(GIT is None, reason="needs git")
def test_git_keeps_only_proxy_and_certificate_settings(tmp_path, monkeypatch, fresh_git_cache):
    home = tmp_path / "home"
    _write_gitconfig(home, tmp_path / "ran")
    monkeypatch.setenv("HOME", str(home))
    kept = runner._git_kept_settings()
    # The system config may add its own TLS settings (Git for Windows does); those are kept too.
    assert "http.proxy=http://proxy.example:3128" in kept
    assert not any(k.startswith(("filter.", "core.pager")) for k in kept)
    listing = runner._run(["git", "config", "--list"], cwd=str(tmp_path)).stdout
    assert "filter.lfs" not in listing and "core.pager" not in listing
    assert "credential.helper" not in listing and "insteadof" not in listing.lower()
    assert "http.proxy=http://proxy.example:3128" in listing
    assert "http.https://git.example.com/.sslcainfo=/etc/example-ca.pem" in listing.lower()


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
    assert over == (out, 1_000_000, "full") and stopped
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


def test_no_io_uring_warning_when_blocked_and_a_note_when_unknown():
    from engine import report
    for state in ("blocked", None):
        assert "io_uring" not in "\n".join(report.outside_lines(rules.outside_summary(_ran(state))))
    lines = "\n".join(report.outside_lines(rules.outside_summary(_ran("unknown"))))
    assert "could not run" in lines and "⚠️" not in lines


def test_npm_download_refuses_git_and_web_dependencies(tmp_path, monkeypatch):
    from engine import mcp_sources as sources
    seen = []
    monkeypatch.setattr(sources, "_run_fetch", lambda cmd, what, work=None: seen.append(cmd))

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


def test_mcp_package_growth_is_an_error_even_with_the_outside_monitor():
    raw = {**_flood_result("package"), "outside": {"ran": True, "canary": "C", "trace": {"events": []},
                                                    "sink": {"ready": True}}}
    out = mcp._evaluate(raw)
    assert out["verdict"] == rules.VERDICT_ERROR
    assert "disk_flood" not in [f["rule"] for f in out["findings"]]


def test_mcp_package_growth_keeps_worse_evidence_from_before_the_stop():
    canary = "CANARY0123456789ABCD"
    raw = {**_flood_result("package"), "outside": {
        "ran": True, "canary": canary, "trace": {"events": []},
        "sink": {"ready": True, "every_port": True, "dns": [],
                 "tcp": [{"ip": "203.0.113.9", "port": 443, "data": "POST / key=sk-" + canary + "-ENV"}]}}}
    out = mcp._evaluate(raw)
    assert out["verdict"] == rules.VERDICT_DANGEROUS, out


def test_mcp_package_growth_with_only_a_high_finding_stays_an_error():
    raw = {**_flood_result("package"), "outside": {"ran": True, "canary": "C", "trace": {"events": []},
                                                    "sink": {"ready": True}},
           "listing": {"tools": [{"name": "re\u0430d", "description": "x"}]}}
    out = mcp._evaluate(raw)
    assert out["verdict"] == rules.VERDICT_ERROR and out.get("detail")
    assert "lookalike_name" in [f["rule"] for f in out["findings"]]


def test_mcp_package_growth_without_the_monitor_keeps_the_config_checks():
    raw = {**_flood_result("package"), "config_checks": [("mcp_unpinned_launch", "medium", "Not pinned", ["x"])]}
    out = mcp._evaluate(raw)
    assert out["verdict"] == rules.VERDICT_ERROR and out.get("detail")
    assert [f["rule"] for f in out["findings"]] == ["mcp_unpinned_launch"]


@pytest.mark.parametrize("kind", ["out", "streams"])
def test_disk_flood_counts_for_mcp_and_skills_without_the_outside_monitor(kind):
    from engine import skill
    raw = _flood_result(kind)
    with_checks = {**raw, "config_checks": [("mcp_unpinned_launch", "medium", "Not pinned", ["x"])]}
    assert {"disk_flood", "mcp_unpinned_launch"} <= {f["rule"] for f in mcp._evaluate(with_checks)["findings"]}
    for out in (mcp._evaluate(raw), skill.evaluate(raw)):
        assert out["verdict"] == rules.VERDICT_SUSPICIOUS
        assert [f["rule"] for f in out["findings"]] == ["disk_flood"]


@pytest.mark.skipif(not runner._fd_walk_supported() or os.geteuid() == 0,
                    reason="needs folder handles and a non-root user (root can read any folder)")
def test_an_unreadable_subfolder_counts_as_full(tmp_path):
    hidden = tmp_path / "h"
    hidden.mkdir()
    (hidden / "f").write_bytes(b"x" * 1000)
    hidden.chmod(0o300)
    try:
        assert runner.folder_bytes(tmp_path, 10_000_000) > 10_000_000
    finally:
        hidden.chmod(0o700)


def test_a_folder_nested_too_deep_counts_as_full(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "MAX_WATCH_DEPTH", 5)
    p = tmp_path
    for _ in range(8):
        p = p / "d"
        p.mkdir()
    assert runner.folder_bytes(tmp_path, 10_000_000) > 10_000_000
    assert runner.folder_bytes(tmp_path) < 10_000_000      # without a limit it just counts


def test_output_flood_is_stopped_and_kept_out_of_memory(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "DISK_POLL_S", 0.05)
    monkeypatch.setattr(runner, "STREAMS_MAX_BYTES", 2_000_000)
    stopped = []
    spam = "import sys, time\nfor _ in range(2000):\n    sys.stdout.write('y' * 65536); sys.stdout.flush(); time.sleep(0.005)\n"
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

    def stop():
        stopped.append(True)
        proc.kill()
    out = tmp_path / "out"
    out.mkdir()
    result, over = runner._run_watched([sys.executable, "-c", spam], 60, stop, [(out, 10**9)],
                                       streams=tmp_path / "streams")
    assert over and over[0] == tmp_path / "streams" and stopped
    proc.wait(timeout=5)


def test_printed_output_comes_back_as_its_last_part(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    code = "import sys; print('x' * 200000); print('the end', file=sys.stderr)"
    result, over = runner._run_watched([sys.executable, "-c", code], 30, lambda: None, [(out, 10**9)],
                                       streams=tmp_path / "streams")
    assert over is None and result.returncode == 0
    assert len(result.stdout) <= 64 * 1024 and result.stderr.strip() == "the end"


def test_sandbox_run_keeps_output_out_of_dockers_log_store(tmp_path):
    cmd = runner.docker_run_cmd("img", tmp_path, tmp_path, tmp_path)
    assert cmd[cmd.index("--log-driver") + 1] == "none"


def test_wide_folders_never_run_out_of_file_handles(tmp_path):
    resource = pytest.importorskip("resource")
    if not runner._fd_walk_supported():
        pytest.skip("folder handles not used here")
    for i in range(2000):
        (tmp_path / f"pkg{i}").mkdir()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(256, hard), hard))
    try:
        n = runner.folder_bytes(tmp_path, 10**9)
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
    assert n is not None and n < 10**9


def test_out_of_handles_means_try_again_not_full(tmp_path, monkeypatch):
    import errno
    (tmp_path / "a").mkdir()
    real = os.open

    def no_handles(path, flags, *a, **kw):
        if kw.get("dir_fd") is not None:
            raise OSError(errno.EMFILE, "too many open files")
        return real(path, flags, *a, **kw)
    if not runner._fd_walk_supported():
        pytest.skip("folder handles not used here")
    monkeypatch.setattr(runner, "_fd_walk_supported", lambda: True)
    monkeypatch.setattr(runner.os, "open", no_handles)
    assert runner.folder_bytes(tmp_path, 10**9) is None


def test_git_settings_skip_keys_that_cannot_be_passed(tmp_path, monkeypatch, fresh_git_cache):
    if GIT is None:
        pytest.skip("needs git")
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text('[http "https://example.com/a?b=c"]\n\tsslCAInfo = /x.pem\n'
                                     "[http]\n\tproxy = http://proxy.example:3128\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    kept = runner._git_kept_settings()
    assert "http.proxy=http://proxy.example:3128" in kept
    listing = runner._run(["git", "config", "--list"], cwd=str(tmp_path))
    assert listing.returncode == 0 and "http.proxy=http://proxy.example:3128" in listing.stdout
    # On older git (command line) the "=" key is skipped instead of breaking git.
    monkeypatch.setattr(runner, "_git_env_ok", False)
    cmd, _ = runner._git_with_settings(["git", "--version"], {})
    assert not any("b=c" in a for a in cmd) and runner._run(["git", "--version"]).returncode == 0


def test_git_settings_stay_out_of_the_process_list_and_follow_includes(tmp_path, monkeypatch, fresh_git_cache):
    if GIT is None:
        pytest.skip("needs git")
    home = tmp_path / "home"
    home.mkdir()
    (home / "extra.inc").write_text("[http]\n\tproxy = http://user:secret@proxy.example:3128\n", encoding="utf-8")
    (home / ".gitconfig").write_text(f"[include]\n\tpath = {home / 'extra.inc'}\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "credential.helper")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "store")
    monkeypatch.setattr(runner, "_git_env_ok", None)
    assert "http.proxy=http://user:secret@proxy.example:3128" in runner._git_kept_settings()
    cmd, env = runner._git_with_settings(["git", "fetch"], dict(os.environ))
    if runner._git_takes_env_config():
        assert cmd == ["git", "fetch"] and not any("secret" in a for a in cmd)
    listing = runner._run(["git", "config", "--list"], cwd=str(tmp_path)).stdout
    assert "proxy.example" in listing and "credential.helper" not in listing


@pytest.mark.parametrize("why,where,words", [("full", "work", "grew past"), ("uncountable", "work", "could not measure"),
                                            ("full", "streams", "printed more than")])
def test_fetch_stop_messages_say_what_happened(tmp_path, monkeypatch, why, where, words):
    from engine import mcp_sources as sources
    work = tmp_path / "w"
    work.mkdir()

    def fake_watched(cmd, timeout, stop, limits, streams=None, free_watch=None):
        return None, ((work if where == "work" else streams), 1, why)
    monkeypatch.setattr(runner, "_run_watched", fake_watched)
    with pytest.raises(sources.SourceError, match=words):
        sources._run_fetch(["docker", "run", "--name=x"], "pkg", work)


def test_a_folder_removed_mid_count_is_skipped_not_hidden(tmp_path, monkeypatch):
    if not runner._fd_walk_supported():
        pytest.skip("folder handles not used here")
    (tmp_path / "gone").mkdir()
    (tmp_path / "f").write_bytes(b"x" * 10)
    real_open = os.open

    def vanishing(name, flags, *a, dir_fd=None, **k):
        if name == "gone":
            raise FileNotFoundError(2, "gone")
        return real_open(name, flags, *a, dir_fd=dir_fd, **k)
    monkeypatch.setattr(runner.os, "open", vanishing)
    monkeypatch.setattr(runner, "_fd_walk_supported", lambda: True)
    used, hidden = runner.folder_usage(tmp_path, 10**9)
    assert used is not None and not hidden


def test_uncountable_is_an_error_everywhere_and_blames_no_one():
    from engine import skill
    raw = {"fatal": "sandbox stopped: Detonator could not count what was written to x", "disk_flood": "uncountable",
           "outside": {"ran": False}}
    assert rules.disk_flood_finding(raw) is None
    assert mcp._evaluate(raw)["verdict"] == rules.VERDICT_ERROR
    assert skill.evaluate(raw)["verdict"] == rules.VERDICT_ERROR
    assert rules.evaluate(raw)["verdict"] == rules.VERDICT_ERROR


def test_handle_limit_is_put_back_after_the_last_run():
    resource = pytest.importorskip("resource")
    before = resource.getrlimit(resource.RLIMIT_NOFILE)
    runner._raise_handle_limit()
    runner._raise_handle_limit()
    runner._restore_handle_limit()
    mid = resource.getrlimit(resource.RLIMIT_NOFILE)
    runner._restore_handle_limit()
    assert resource.getrlimit(resource.RLIMIT_NOFILE) == before
    assert mid[0] >= before[0]


def test_bare_git_keys_only_kept_when_boolean(tmp_path, monkeypatch, fresh_git_cache):
    if GIT is None:
        pytest.skip("needs git")
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text("[http]\n\tproxy\n\tsslVerify\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    kept = runner._git_kept_settings()
    assert "http.sslverify=true" in kept and not any(k.startswith("http.proxy") for k in kept)


def _fake_free(monkeypatch, values):
    """_free_bytes returns the given values in turn, then the last one forever."""
    seq = list(values)

    def free(path):
        return seq.pop(0) if len(seq) > 1 else seq[0]
    monkeypatch.setattr(runner, "_free_bytes", free)


@pytest.mark.parametrize("after,why", [(10_000_000_000, "deleted"), (6_000_000_000, "freespace")])
def test_free_space_drop_stops_the_run_and_is_tied_to_it_only_if_it_comes_back(tmp_path, monkeypatch, after, why):
    gb = 1_000_000_000
    stopped = []
    # start 10 GB free, then 6 GB free (a 4 GB drop past a 1 GB limit), then `after` once stopped.
    _fake_free(monkeypatch, [10 * gb, 6 * gb, 6 * gb, after])
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    def stop():
        stopped.append(1)
        proc.kill()
    result, over = runner._run_watched([sys.executable, "-c", "import time; time.sleep(10)"], 30, stop,
                                       [(tmp_path, 10**12)], free_watch=(tmp_path, gb))
    proc.wait()
    assert stopped and over is not None and over[2] == why


def test_a_disk_close_to_full_stops_the_run(tmp_path, monkeypatch):
    mb = 1024 * 1024
    _fake_free(monkeypatch, [2048 * mb, 100 * mb])
    result, over = runner._run_watched([sys.executable, "-c", "import time; time.sleep(10)"], 30, lambda: None,
                                       [(tmp_path, 10**12)], free_watch=(tmp_path, 10**12))
    assert over is not None and over[2] in ("freespace", "deleted")


def test_package_folder_leaves_out_private_folders_but_output_folder_does_not(tmp_path, monkeypatch):
    if not runner._fd_walk_supported():
        pytest.skip("folder handles not used here")
    (tmp_path / "private").mkdir()
    real_open = os.open

    def locked(name, flags, *a, dir_fd=None, **k):
        if name == "private":
            raise PermissionError(13, "denied")
        return real_open(name, flags, *a, dir_fd=dir_fd, **k)
    monkeypatch.setattr(runner.os, "open", locked)
    monkeypatch.setattr(runner, "_fd_walk_supported", lambda: True)
    used, hidden = runner.folder_usage(tmp_path, 10**9, strict=False)
    assert used is not None and used < 10**6 and not hidden
    used, hidden = runner.folder_usage(tmp_path, 10**9)
    assert hidden and used > 10**9


@pytest.mark.parametrize("why,words", [("hidden", "could not look into"), ("deleted", "deleted but kept open"),
                                       ("full", "wrote hundreds of MB")])
def test_disk_flood_title_says_what_happened(why, words):
    f = rules.disk_flood_finding({"disk_flood": "out", "disk_flood_why": why, "fatal": "x"})
    assert words in f.title
    if why == "hidden":
        assert "hundreds" not in f.title and "Tried" not in f.title


def test_free_space_without_a_cause_is_an_error_everywhere():
    from engine import skill
    raw = {"fatal": "sandbox stopped: the free space on your disk fell", "disk_flood": "freespace",
           "outside": {"ran": False}}
    assert rules.disk_flood_finding(raw) is None
    for out in (mcp._evaluate(raw), skill.evaluate(raw), rules.evaluate(raw)):
        assert out["verdict"] == rules.VERDICT_ERROR


def test_disk_flood_has_no_atlas_request_flood_tag():
    assert rules.RULES["disk_flood"].atlas == ()
