"""Reading a Hermes config entry: what it starts (plan_entry), what is wrong with the entry
(config_checks), and npm install scripts. None of these download or run anything."""

import json

import pytest

from engine import mcp_sources as src


# ---- plan_entry: what the entry starts -----------------------------------------------
def test_npx_pinned():
    p = src.plan_entry("m", {"command": "npx", "args": ["-y", "pkg@1.2.3"]})
    assert (p.kind, p.package, p.version, p.pinned) == ("npm", "pkg", "1.2.3", True)


def test_npx_unpinned():
    p = src.plan_entry("m", {"command": "npx", "args": ["-y", "@scope/pkg"]})
    assert (p.kind, p.package, p.pinned) == ("npm", "@scope/pkg", False)


def test_npx_dash_p_package():
    p = src.plan_entry("m", {"command": "npx", "args": ["-p", "pkg@2.0.0", "pkg-bin"]})
    assert (p.kind, p.package, p.version, p.args) == ("npm", "pkg", "2.0.0", ["pkg-bin"])


def test_uvx_pinned_and_from():
    p = src.plan_entry("t", {"command": "uvx", "args": ["mcp-server-time==2026.8.18"]})
    assert (p.kind, p.package, p.version, p.pinned) == ("pypi", "mcp-server-time", "2026.8.18", True)
    p2 = src.plan_entry("t", {"command": "uvx", "args": ["--from", "my-pkg==1.0.0", "my-cmd"]})
    assert (p2.kind, p2.package, p2.version, p2.script) == ("pypi", "my-pkg", "1.0.0", "my-cmd")


def test_remote_url():
    assert src.plan_entry("r", {"url": "https://mcp.example.com/mcp"}).kind == "remote"


def test_local_script(tmp_path):
    s = tmp_path / "server.py"
    s.write_text("print('x')")
    p = src.plan_entry("l", {"command": "python", "args": ["server.py"]}, base=tmp_path)
    assert p.kind == "local" and p.command == "python" and p.script == str(s.resolve())
    assert "\0SCRIPT\0" in p.args


@pytest.mark.parametrize("entry", [
    {"command": "docker", "args": ["run", "x"]},
    {"command": "python", "args": ["-m", "some_module"]},
    {"command": "my-weird-binary"},
    {"command": "npx"},
])
def test_unsupported_entries_raise(entry):
    with pytest.raises(src.SourceError):
        src.plan_entry("x", entry)


# ---- config_checks: what is wrong with the entry -------------------------------------
def checks(name, entry):
    plan = None
    try:
        plan = src.plan_entry(name, entry)
    except src.SourceError:
        pass
    return {c[0] for c in src.config_checks(name, entry, plan)}


def test_unpinned_and_full_trust():
    found = checks("m", {"command": "npx", "args": ["-y", "pkg"]})
    assert "mcp_unpinned_launch" in found
    assert "mcp_full_trust_third_party" in found


def test_pinned_untrusted_is_clean():
    found = checks("m", {"command": "npx", "args": ["-y", "pkg@1.0.0"], "trust": "untrusted"})
    assert "mcp_unpinned_launch" not in found
    assert "mcp_full_trust_third_party" not in found


def test_inline_secret_in_env_and_header_and_arg():
    assert "mcp_inline_secret" in checks(
        "m", {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env": {"API_KEY": "sk-abcd1234abcd1234abcd"}})
    assert "mcp_inline_secret" in checks(
        "r", {"url": "https://x/mcp", "headers": {"Authorization": "Bearer sk-abcd1234abcd1234abcd"}})
    assert "mcp_inline_secret" in checks(
        "m", {"command": "npx", "args": ["-y", "pkg@1.0.0", "--token=glpat-abcdefghij1234567890"]})


def test_http_remote_flagged():
    assert "mcp_inline_secret" in checks("r", {"url": "http://mcp.example.com/mcp"})
    assert "mcp_inline_secret" not in checks("r", {"url": "https://mcp.example.com/mcp"})


def test_loopback_http_is_not_flagged():
    assert "mcp_inline_secret" not in checks("r", {"url": "http://127.0.0.1:8080/mcp"})


# ---- npm install scripts -------------------------------------------------------------
def test_npm_install_scripts(tmp_path):
    pkg = tmp_path / "node_modules" / "evil"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "evil", "scripts": {"postinstall": "node x.js"}}))
    clean = tmp_path / "node_modules" / "nice"
    clean.mkdir(parents=True)
    (clean / "package.json").write_text(json.dumps({"name": "nice", "scripts": {"test": "jest"}}))
    found = {s["package"]: s["scripts"] for s in src.npm_install_scripts(tmp_path)}
    assert "evil" in found and "postinstall" in found["evil"]
    assert "nice" not in found


def test_binding_gyp_counts_as_install(tmp_path):
    pkg = tmp_path / "node_modules" / "native"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "native"}))
    (pkg / "binding.gyp").write_text("{}")
    found = {s["package"] for s in src.npm_install_scripts(tmp_path)}
    assert "native" in found


def test_env_references_are_not_inline_secrets():
    found = checks("m", {"command": "npx", "args": ["-y", "pkg@1.0.0"], "trust": "untrusted",
                         "env": {"API_KEY": "${API_KEY}", "TOKEN": "$TOKEN"}})
    assert "mcp_inline_secret" not in found


def test_inside_hermes_its_own_config_reader_is_used(monkeypatch, tmp_path):
    import sys, types
    fake = types.ModuleType("hermes_cli.config")
    fake.read_raw_config = lambda: {"mcp_servers": {"from-hermes": {"command": "npx", "args": ["pkg"]}}}
    monkeypatch.setitem(sys.modules, "hermes_cli", types.ModuleType("hermes_cli"))
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake)
    assert list(src.read_servers()) == ["from-hermes"]
    # an explicit file (developer use) is read as a file
    f = tmp_path / "config.yaml"
    f.write_text("mcp_servers:\n  from-file:\n    command: npx\n    args: [pkg]\n")
    assert list(src.read_servers(f)) == ["from-file"]
