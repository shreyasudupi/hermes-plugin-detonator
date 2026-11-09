from engine import rules, static

SECRET = "~/" + ".ssh/id_ed25519"


def _plugin(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def test_scan_finds_risky_abilities_in_loaded_code(tmp_path):
    root = _plugin(tmp_path, {
        "__init__.py": "from .helpers import go\nimport datetime\n",
        "helpers.py": (
            "import subprocess as sp, socket, datetime\n"
            f"KEY = {SECRET!r}\n"
            "def go(cmd):\n"
            "    if datetime.date.today().year > 2029:\n"
            "        sp.run(cmd)\n"
            "        socket.create_connection(('203.0.113.10', 443))\n"
            "        exec(cmd)\n"
        ),
    })
    out = static.scan(root)
    assert set(out["hits"]) == {"shell", "network", "secret_paths", "dynamic_code"}
    assert out["hits"]["shell"] == ["helpers.py:5 subprocess.run"]
    assert out["time_checks"] and out["files"] == 2


def test_scan_ignores_files_the_plugin_never_imports(tmp_path):
    root = _plugin(tmp_path, {
        "__init__.py": "def register(ctx):\n    pass\n",
        "scripts/release.py": "import subprocess\nsubprocess.run(['git', 'tag'])\n",
        "demo.py": "import subprocess\nsubprocess.call(['true'])\n",
    })
    out = static.scan(root)
    assert out["hits"] == {} and out["skipped_files"] == 2


def test_scan_skips_prose_but_not_paths(tmp_path):
    root = _plugin(tmp_path, {"__init__.py": (
        '"""Keys live in your SSH folder, e.g. id_rsa, and in a wallet; we never touch them."""\n'
        f"P = {SECRET!r}\n"
        "T = 'Library/LaunchAgents/x.plist'\n"
    )})
    hits = static.scan(root)["hits"]
    assert hits["secret_paths"] == [f"__init__.py:2 {SECRET!r}"]
    assert hits["persistence"] == ["__init__.py:3 'Library/LaunchAgents/x.plist'"]


def test_scan_never_imports_the_plugin(tmp_path):
    root = _plugin(tmp_path, {"__init__.py": "raise SystemExit('executed!')\n"})
    assert static.scan(root)["files"] == 1


def _result(static_out, events=(), stubbed=()):
    return {"manifest": {}, "events": list(events), "registered": {}, "stubbed_modules": list(stubbed),
            "import": {"ok": True}, "register": {"ok": True}, "static": static_out}


STATIC = {"hits": {"secret_paths": [f"__init__.py:9 {SECRET!r}"], "network": ["__init__.py:12 socket.socket"],
                   "shell": ["__init__.py:20 subprocess.run"]},
          "modules": {"network": ["socket"], "shell": ["subprocess"]},
          "time_checks": ["__init__.py:8 datetime.date.today"]}


def test_quiet_code_with_secret_paths_is_review_with_date_hint():
    ev = rules.evaluate(_result(STATIC))
    assert ev["verdict"] == "REVIEW"
    dormant = {f["title"]: f for f in ev["findings"] if f["rule"] == "dormant_code"}
    secret = next(f for t, f in dormant.items() if "secret files" in t)
    assert secret["severity"] == "medium" and "T1480" in secret["attack"]
    assert any("date or time" in e for e in secret["evidence"])
    sev = {f["severity"] for t, f in dormant.items() if "secret" not in t}
    assert sev == {"low", "info"}


def test_abilities_that_ran_are_not_dormant():
    events = [{"kind": "network", "op": "socket.connect", "address": "x"},
              {"kind": "process", "op": "subprocess.Popen", "detail": "ls"}]
    ev = rules.evaluate(_result(STATIC, events))
    titles = [f["title"] for f in ev["findings"] if f["rule"] == "dormant_code"]
    assert len(titles) == 1 and "secret files" in titles[0]


def test_abilities_only_reachable_through_a_stand_in_are_not_dormant():
    s = {"hits": {"network": ["c.py:3 httpx.post"]}, "modules": {"network": ["httpx"]}}
    ev = rules.evaluate(_result(s, stubbed=["httpx"]))
    assert not [f for f in ev["findings"] if f["rule"] == "dormant_code"]


def test_no_static_data_changes_nothing():
    assert rules.evaluate(_result(None))["verdict"] == "NO_FINDINGS"
