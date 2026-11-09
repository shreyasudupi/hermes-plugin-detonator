"""Tool handlers for the Detonator plugin.

Handlers take (args, **kwargs), return a JSON string, and never raise.
"""

import json
import re

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def detonate_plugin(args: dict, **kwargs) -> str:
    try:
        repo = str(args.get("repo", ""))
        sha = str(args.get("sha", "")).lower()
        if not _REPO_RE.match(repo):
            return json.dumps({"error": "repo must look like owner/name"})
        if not _SHA_RE.match(sha):
            return json.dumps({"error": "sha must be a full 40-character commit SHA"})
        # Sandbox not implemented yet (skeleton for smoke testing).
        return json.dumps(
            {"status": "not_implemented", "repo": repo, "sha": sha, "verdict": None}
        )
    except Exception as exc:  # handlers must never raise
        return json.dumps({"error": f"internal error: {exc}"})
