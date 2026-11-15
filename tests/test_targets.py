"""Finding the commit for people who don't know SHAs: catalog names, newest commit, update check."""

import json
import subprocess
import sys
import types

import pytest

from engine import targets
import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location("_skel", pathlib.Path(__file__).with_name("test_skeleton.py"))
_skel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_skel)
FakeCtx, SHA, _load_plugin = _skel.FakeCtx, _skel.SHA, _skel._load_plugin

OLD, NEW = "1" * 40, "2" * 40


class Entry:
    def __init__(self, name, repo, sha, subdir=""):
        self.name, self.repo, self.sha, self.subdir = name, repo, sha, subdir


@pytest.fixture
def catalog(monkeypatch):
    entries = {"weather": Entry("weather", "https://github.com/acme/hermes-weather", NEW, "plugin"),
               "notgh": Entry("notgh", "https://gitlab.com/acme/x", NEW)}
    mod = types.ModuleType("hermes_cli.plugin_catalog")
    mod.get_live_catalog_entry = lambda name: entries.get(name)
    pkg = types.ModuleType("hermes_cli")
    pkg.plugin_catalog = mod
    monkeypatch.setitem(sys.modules, "hermes_cli", pkg)
    monkeypatch.setitem(sys.modules, "hermes_cli.plugin_catalog", mod)
    return entries


def test_catalog_name_gives_the_pinned_commit_and_folder(catalog):
    plan = targets.parse("weather")
    assert (plan.repo, plan.sha, plan.subdir) == ("acme/hermes-weather", NEW, "plugin")
    assert "hermes plugins install weather" in plan.source


def test_unknown_or_non_github_catalog_name_is_explained(catalog):
    with pytest.raises(ValueError, match="hermes plugins search"):
        targets.parse("nosuch")
    with pytest.raises(ValueError, match="not a GitHub repo"):
        targets.parse("notgh")


def test_no_catalog_available_is_explained(monkeypatch):
    monkeypatch.setitem(sys.modules, "hermes_cli", None)
    with pytest.raises(ValueError, match="catalog"):
        targets.parse("weather")


@pytest.mark.parametrize("text", ["acme/x", "https://github.com/acme/x", "github.com/acme/x.git",
                                  "https://github.com/acme/x/"])
def test_repo_or_link_without_sha_means_newest_commit(text):
    plan = targets.parse(text)
    assert plan.repo == "acme/x" and plan.sha is targets.LATEST and plan.subdir is None


def test_exact_commits_still_work():
    assert targets.parse(f"acme/x {SHA} sub").sha == SHA
    assert targets.parse(f"acme/x {OLD} {NEW}").sha == (OLD, NEW)
    assert targets.parse("acme/x plugins/one").subdir == "plugins/one"


@pytest.mark.parametrize("bad", ["acme/x abc1234", "acme/x ../etc", "acme/x /abs", f"acme/x {OLD} {OLD}",
                                 "https://evil.example/acme/x", "two words", "acme/x a b"])
def test_bad_input_is_refused(bad):
    with pytest.raises(ValueError):
        targets.parse(bad)


def _install(home, name, head=None, record=None, ref=None, packed=None):
    d = home / "plugins" / name
    (d / ".git" / "refs" / "heads").mkdir(parents=True)
    if head:
        (d / ".git" / "HEAD").write_text(head + "\n")
    if ref:
        (d / ".git" / "refs" / "heads" / "main").write_text(ref + "\n")
    if packed:
        (d / ".git" / "packed-refs").write_text(f"# pack-refs\n{packed} refs/heads/main\n")
    (d / ".git" / "config").write_text('[remote "origin"]\n\turl = https://github.com/acme/hermes-weather.git\n')
    if record:
        (d / ".hermes-catalog.json").write_text(json.dumps(record))
    return d


def test_update_compares_installed_with_catalog_pin(tmp_path, monkeypatch, catalog):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    _install(tmp_path, "weather", head=OLD,
             record={"catalog_name": "weather", "repo": "https://github.com/acme/hermes-weather", "sha": OLD})
    plan = targets.parse("update weather")
    assert plan.repo == "acme/hermes-weather" and plan.sha == (OLD, NEW) and plan.subdir == "plugin"
    assert "hermes plugins update" in plan.source


def test_update_when_already_current_says_so(tmp_path, monkeypatch, catalog):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    _install(tmp_path, "weather", head=NEW, record={"catalog_name": "weather",
                                                     "repo": "https://github.com/acme/hermes-weather"})
    with pytest.raises(ValueError, match="nothing newer"):
        targets.parse("update weather")


@pytest.mark.parametrize("how", ["ref", "packed"])
def test_update_outside_catalog_uses_branch_head_and_newest(tmp_path, monkeypatch, how):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    monkeypatch.setitem(sys.modules, "hermes_cli", None)
    _install(tmp_path, "mine", head="ref: refs/heads/main", **{how: OLD})
    plan = targets.parse("update mine")
    assert plan.repo == "acme/hermes-weather" and plan.sha == (OLD, None)


def test_update_refuses_bad_or_missing_names(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    for bad in ("../x", "Nope!", "update"):
        with pytest.raises(ValueError):
            targets.parse(f"update {bad}")
    with pytest.raises(ValueError, match="No installed plugin"):
        targets.parse("update absent")


def test_newest_commit_lookup_parses_ls_remote():
    calls = []

    def run(cmd, timeout):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=f"{NEW}\tHEAD\n", stderr="")

    assert targets.resolve_latest("acme/x", run) == NEW
    assert "ls-remote" in calls[0] and "https://github.com/acme/x.git" in calls[0]
    with pytest.raises(LookupError):
        targets.resolve_latest("acme/x", lambda c, timeout: subprocess.CompletedProcess(c, 128, "", "not found"))


def test_slash_command_looks_up_newest_commit_only_after_approval(monkeypatch, tmp_path):
    plugin = _load_plugin()
    looked = []
    monkeypatch.setattr(plugin.commands.targets, "resolve_latest", lambda repo, run: looked.append(repo) or NEW)
    ran = []
    path = tmp_path / "r.md"
    monkeypatch.setattr(plugin.commands, "run_detonation",
                        lambda repo, sha, subdir, outside=None: ran.append(sha) or (
                            {"verdict": "NO_FINDINGS", "findings": []}, "", path))
    ctx = FakeCtx(choice="cancel")
    plugin.register(ctx)
    assert "Not run" in ctx.commands["detonate"]("acme/x")
    assert looked == [] and ran == []
    assert "newest commit" in ctx.asked[0]
    ctx = FakeCtx(choice="run")
    plugin.register(ctx)
    out = ctx.commands["detonate"]("https://github.com/acme/x")
    assert looked == ["acme/x"] and ran == [NEW]
    assert f"Tested commit: {NEW}" in out


def test_tool_suggests_simple_commands():
    plugin = _load_plugin()
    ctx = FakeCtx()
    plugin.register(ctx)
    tool = ctx.tools["detonate_plugin"][2]
    assert json.loads(tool({"name": "weather"}))["command"] == "/detonate weather"
    assert json.loads(tool({"name": "weather", "update": True}))["command"] == "/detonate update weather"
    assert json.loads(tool({"repo": "acme/x"}))["command"] == "/detonate acme/x"
    assert json.loads(tool({"repo": "acme/x", "sha": SHA}))["command"] == f"/detonate acme/x {SHA}"
    for bad in ({"name": "../x"}, {"repo": "acme/x", "sha": "abc"}, {"repo": "acme/x", "new_sha": NEW},
                {"repo": "acme/x", "subdir": "../etc"}, {}):
        assert "error" in json.loads(tool(bad))


NO_LINKS = pytest.mark.skipif(sys.platform == "win32", reason="making symlinks needs admin rights on Windows")


@NO_LINKS
def test_installed_plugin_cannot_steer_reads_outside_its_records(tmp_path, monkeypatch):
    """The installed plugin wrote its own folder, so its records are untrusted: links, huge files
    and ref paths that climb out are ignored, never followed."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    monkeypatch.setitem(sys.modules, "hermes_cli", None)
    secret = tmp_path / "secret"
    secret.write_text(OLD)
    d = _install(tmp_path, "evil")
    (d / ".git" / "HEAD").symlink_to(secret)
    assert targets.installed_commit(d)[0] is None
    (d / ".git" / "HEAD").unlink()
    (d / ".git" / "HEAD").write_text("ref: refs/../../../secret\n")
    assert targets.installed_commit(d)[0] is None
    (d / ".git" / "HEAD").write_text(OLD + "\n" + "x" * 2_000_000)
    assert targets.installed_commit(d)[0] is None
    with pytest.raises(ValueError, match="Could not tell"):
        targets.parse("update evil")


def test_catalog_folder_that_climbs_out_is_refused(catalog):
    catalog["climb"] = Entry("climb", "https://github.com/acme/x", NEW, "../../etc")
    with pytest.raises(ValueError, match="relative"):
        targets.parse("climb")


@NO_LINKS
def test_installed_plugin_dir_that_is_a_link_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    real = _install(tmp_path, "real", head=OLD)
    (tmp_path / "plugins" / "linked").symlink_to(real)
    with pytest.raises(ValueError, match="No installed plugin"):
        targets.parse("update linked")
