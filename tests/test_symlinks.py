"""A plugin repo must not be able to pull real files from this machine into the sandbox
through a symlink (for example a link to an SSH key or the real Hermes .env)."""

import os
import shutil
import subprocess

import pytest

from engine import runner


def _commit_repo(path, files, links):
    path.mkdir()
    for name, text in files.items():
        (path / name).write_text(text, encoding="utf-8")
    for name, target in links.items():
        os.symlink(target, path / name)
    git = ["git", "-C", str(path), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(git + ["init", "-q"], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", "x"], check=True)
    return subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def _local_fetch(monkeypatch, repo_dir):
    """Run the real git steps of fetch_github, but against a local repository."""
    real = runner._run

    def fake(cmd, *a, **kw):
        cmd = [str(repo_dir) if c.startswith("https://github.com/") else c for c in cmd]
        cmd = ["protocol.file.allow=always" if c == "protocol.file.allow=never" else c for c in cmd]
        return real(cmd, *a, **kw)

    monkeypatch.setattr(runner, "_run", fake)


@pytest.mark.skipif(not shutil.which("git"), reason="git not available")
def test_fetched_symlinks_become_plain_files(tmp_path, monkeypatch):
    secret = tmp_path / "host-secret"
    secret.write_text("REAL-HOST-SECRET", encoding="utf-8")
    repo = tmp_path / "repo"
    sha = _commit_repo(repo, {"plugin.yaml": "name: x\n", "__init__.py": "def register(ctx): pass\n"},
                       {"stolen": str(secret)})
    _local_fetch(monkeypatch, repo)
    target = runner.fetch_github("owner/name", sha, tmp_path / "work")
    stolen = target.path / "stolen"
    assert not stolen.is_symlink()
    assert "REAL-HOST-SECRET" not in stolen.read_text(encoding="utf-8")


@pytest.mark.skipif(not shutil.which("git"), reason="git not available")
def test_subdir_cannot_leave_the_repo(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    sha = _commit_repo(repo, {"plugin.yaml": "name: x\n", "__init__.py": "def register(ctx): pass\n"}, {})
    _local_fetch(monkeypatch, repo)
    with pytest.raises(runner.DetonatorError, match="inside the repository"):
        runner.fetch_github("owner/name", sha, tmp_path / "work", subdir="../../")


def test_sandbox_copy_drops_symlinks(tmp_path):
    secret = tmp_path / "host-secret"
    secret.write_text("REAL-HOST-SECRET", encoding="utf-8")
    src = tmp_path / "plugin"
    src.mkdir()
    (src / "__init__.py").write_text("", encoding="utf-8")
    os.symlink(secret, src / "stolen")
    os.symlink(tmp_path, src / "stolen_dir")
    dst = tmp_path / "copy"
    shutil.copytree(src, dst, ignore=runner._skip_links)
    assert sorted(os.listdir(dst)) == ["__init__.py"]
