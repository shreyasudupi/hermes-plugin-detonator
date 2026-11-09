"""End-to-end: detonate a harmless fixture in the real Docker sandbox.

Skipped when Docker is not available. Malicious fixtures live in the separate
detonator-test-fixtures repo so this repo stays clean for the catalog scanner.
"""

import pathlib

import pytest

from engine import rules, runner

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "clean_plugin"

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
