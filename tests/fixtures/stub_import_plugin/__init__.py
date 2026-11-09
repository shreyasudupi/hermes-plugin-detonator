"""Harmless fixture: imports modules that only exist inside Hermes."""

import json
import urllib.request
import subprocess  # noqa: F401  (only imported: it probes Windows-only stdlib modules)

from gateway.platforms.base import BasePlatformAdapter  # noqa: F401  (not in the sandbox)
from tools.registry import tool_error  # noqa: F401

SCHEMA = {"name": "ping", "description": "Reply pong.", "parameters": {"type": "object", "properties": {}}}


def _ping(args, **kwargs):
    return json.dumps({"reply": "pong"})


def register(ctx):
    urllib.request.getproxies()  # stdlib walks every env var looking for *_proxy
    ctx.register_tool(name="ping", toolset="demo", schema=SCHEMA, handler=_ping)
