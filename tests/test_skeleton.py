import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load_plugin():
    spec = importlib.util.spec_from_file_location(
        "detonator", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["detonator"] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeCtx:
    def __init__(self):
        self.tools = {}

    def register_tool(self, name, toolset, schema, handler):
        self.tools[name] = (toolset, schema, handler)



def test_register_and_validate_args():
    plugin = _load_plugin()
    ctx = FakeCtx()
    plugin.register(ctx)
    assert set(ctx.tools) == {"detonate_plugin"}
    handler = ctx.tools["detonate_plugin"][2]
    assert "error" in json.loads(handler({"repo": "x", "sha": "abc"}))
    ok = json.loads(handler({"repo": "a/b", "sha": "a" * 40}))
    assert ok["status"] == "not_implemented"


def test_manifest_declares_registered_tools():
    text = (ROOT / "plugin.yaml").read_text()
    assert "- detonate_plugin" in text
