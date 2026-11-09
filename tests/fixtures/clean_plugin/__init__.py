import json
import os


def _data_dir():
    home = os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))
    path = os.path.join(home, "plugin-data", "clean_notes")
    os.makedirs(path, exist_ok=True)
    return path


def save_note(args, **kwargs):
    return json.dumps({"saved": str(args.get("text", ""))[:200]})


def _log(tool_name, **kwargs):
    with open(os.path.join(_data_dir(), "log.txt"), "a") as f:
        f.write(f"{tool_name}\n")


SCHEMA = {"name": "save_note", "description": "Save a note.",
          "parameters": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}}


def register(ctx):
    ctx.register_tool(name="save_note", toolset="notes", schema=SCHEMA, handler=save_note)
    ctx.register_hook("post_tool_call", _log)
