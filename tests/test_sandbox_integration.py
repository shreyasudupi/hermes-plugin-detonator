"""End-to-end: detonate a harmless fixture in the real Docker sandbox.

Skipped when Docker is not available. Malicious fixtures live in the separate
detonator-test-fixtures repo so this repo stays clean for the catalog scanner.
"""

import pathlib

import pytest

from engine import rules, runner

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "clean_plugin"

pytestmark = pytest.mark.skipif(not runner.docker_available(), reason="Docker not available")


def test_clean_plugin_passes_in_sandbox():
    raw = runner.detonate(runner.local_target(str(FIXTURE)))
    assert not raw.get("fatal"), raw.get("fatal")
    assert raw["registered"]["tools"] == ["save_note"]
    out = rules.evaluate(raw)
    assert out["verdict"] == "NO_FINDINGS", out["findings"]


def test_sandbox_flags_are_locked_down(tmp_path):
    cmd = runner.docker_run_cmd("img", tmp_path, tmp_path, tmp_path)
    joined = " ".join(cmd)
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--user 10001:10001"):
        assert flag in joined


def test_hermes_only_imports_get_stand_ins():
    raw = runner.detonate(runner.local_target(str(FIXTURES / "stub_import_plugin")))
    assert raw["registered"]["tools"] == ["ping"]
    assert "gateway.platforms.base" in raw["stubbed_modules"]
    # stdlib probes (subprocess tries msvcrt/_winapi) must never get stand-ins,
    # or Python would act as if it were on Windows and hide process activity.
    assert not {"msvcrt", "_winapi", "nt"} & set(raw["stubbed_modules"])
    # urllib's proxy lookup walks the whole environment: seen, but not blamed on the plugin
    env = [e for e in raw["events"] if e["kind"] == "env_read"]
    assert env and all(e["how"] == "enumerated" and e["by"] == "library" for e in env)
    out = rules.evaluate(raw)
    assert out["verdict"] == "NO_FINDINGS", out["findings"]


def test_package_without_python_code_is_explained(tmp_path):
    (tmp_path / "plugin.json").write_text("{}")
    with pytest.raises(runner.DetonatorError, match="portable Agent Plugins"):
        runner.local_target(str(tmp_path))
    (tmp_path / "plugin.yaml").write_text("name: x\n")
    with pytest.raises(runner.DetonatorError, match="no __init__.py"):
        runner.local_target(str(tmp_path))
