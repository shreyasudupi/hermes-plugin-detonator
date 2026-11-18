"""The package download container never gets host networking, even with a proxy on localhost."""

import os
import socket
import threading

import pytest

from engine import mcp_sources as s

PROXY_VARS = (*s._PROXY_VARS, *s._NO_PROXY_VARS, "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE")


@pytest.fixture
def env(monkeypatch):
    for k in PROXY_VARS:
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def _env_file(args):
    path = args[args.index("--env-file") + 1]
    with open(path, encoding="utf-8") as fh:
        return path, dict(line.rstrip("\n").split("=", 1) for line in fh)


def _echo_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.sendall(b"pong:" + c.recv(100))
            c.close()
    threading.Thread(target=serve, daemon=True).start()
    return srv


def test_windows_names_ignore_case(env):
    env.setattr(s.os, "name", "nt")
    assert s._env_names(s._PROXY_VARS) == ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")


def test_no_proxy_no_args(env):
    with s._ProxySetup() as args:
        assert args == []


def test_remote_proxy_passed_by_name(env):
    env.setenv("HTTPS_PROXY", "http://user:pw@proxy.example:3128")
    env.setenv("NO_PROXY", "internal.example")
    with s._ProxySetup() as args:
        assert args == ["-e", "HTTPS_PROXY", "-e", "NO_PROXY"]
        assert "pw" not in " ".join(args)


def test_local_proxy_on_docker_desktop(env):
    env.setattr(s, "_docker_desktop", lambda: True)
    env.setenv("HTTPS_PROXY", "http://user:pw@127.0.0.1:8888")
    env.setenv("HTTP_PROXY", "http://localhost:8888/")
    with s._ProxySetup() as args:
        path, vals = _env_file(args)
        assert vals == {"HTTPS_PROXY": "http://user:pw@host.docker.internal:8888",
                        "HTTP_PROXY": "http://host.docker.internal:8888/"}
        assert "--network" not in args and "pw" not in " ".join(args)
        assert args[args.index("--add-host") + 1] == "host.docker.internal:host-gateway"
        if os.name != "nt":
            assert os.stat(path).st_mode & 0o077 == 0
    assert not os.path.exists(path)


def test_local_proxy_on_linux_uses_relay(env):
    upstream = _echo_server()
    port = upstream.getsockname()[1]
    env.setattr(s, "_docker_desktop", lambda: False)
    env.setattr(s, "_bridge", lambda: ("127.0.0.1", "127.0.0.0/8"))
    env.setenv("HTTPS_PROXY", f"http://127.0.0.1:{port}")
    env.setenv("HTTP_PROXY", f"http://localhost:{port}")
    with s._ProxySetup() as args:
        _, vals = _env_file(args)
        assert "--network" not in args and "--add-host" not in args
        relay_url = vals["HTTPS_PROXY"]
        assert vals["HTTP_PROXY"] == relay_url and relay_url.startswith("http://127.0.0.1:")
        relay_port = int(relay_url.rsplit(":", 1)[1])
        assert relay_port != port
        c = socket.create_connection(("127.0.0.1", relay_port), timeout=5)
        c.sendall(b"hi")
        assert c.recv(100) == b"pong:hi"
        c.close()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", relay_port), timeout=2)
    upstream.close()


def test_relay_refuses_peers_outside_the_bridge():
    upstream = _echo_server()
    relay = s._Relay("127.0.0.1", "10.0.0.0/8", upstream.getsockname())
    try:
        c = socket.create_connection(("127.0.0.1", relay.port), timeout=5)
        c.settimeout(5)
        try:
            c.sendall(b"hi")
            assert c.recv(100) == b""      # closed without forwarding
        except ConnectionError:            # reset (Linux) or aborted (Windows): refused either way
            pass
        c.close()
    finally:
        relay.close()
        upstream.close()


def test_two_local_proxies_get_two_relays(env):
    a, b = _echo_server(), _echo_server()
    env.setattr(s, "_docker_desktop", lambda: False)
    env.setattr(s, "_bridge", lambda: ("127.0.0.1", "127.0.0.0/8"))
    env.setenv("HTTPS_PROXY", "http://127.0.0.1:%d" % a.getsockname()[1])
    env.setenv("HTTP_PROXY", "http://127.0.0.1:%d" % b.getsockname()[1])
    with s._ProxySetup() as args:
        _, vals = _env_file(args)
        assert vals["HTTPS_PROXY"] != vals["HTTP_PROXY"]
    a.close()
    b.close()


def test_no_bridge_is_a_clear_error_not_host_network(env):
    env.setattr(s, "_docker_desktop", lambda: False)
    env.setattr(s.runner, "_run", lambda *a, **k: type("P", (), {"stdout": "", "returncode": 0})())
    env.setenv("HTTPS_PROXY", "http://127.0.0.1:8001")
    with pytest.raises(s.SourceError, match="not localhost"):
        with s._ProxySetup():
            pass


def test_fetch_command_never_uses_host_network(env, tmp_path):
    env.setattr(s, "_docker_desktop", lambda: True)
    env.setenv("HTTPS_PROXY", "http://127.0.0.1:8888")
    with s._ProxySetup() as args:
        cmd = s._fetch_cmd("node:x", tmp_path, ["npm", "install"], args)
    assert "host" not in [cmd[i + 1] for i, a in enumerate(cmd) if a == "--network"]
    assert "--network" not in cmd
