"""Tool handlers for the Detonator plugin.

Handlers take (args, **kwargs), return a JSON string, and never raise.

The model-facing tool never runs anything itself: a detonation executes
untrusted code (in a sandbox), so it must be approved by the person, which
only the /detonate command and `hermes detonate` can ask for.
"""

import json
import re

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def detonate_plugin(args: dict, **kwargs) -> str:
    try:
        repo = str(args.get("repo", ""))
        sha = str(args.get("sha", "")).lower()
        subdir = str(args.get("subdir") or "").strip()
        if not _REPO_RE.match(repo):
            return json.dumps({"error": "repo must look like owner/name"})
        if not _SHA_RE.match(sha):
            return json.dumps({"error": "sha must be a full 40-character commit SHA"})
        new_sha = str(args.get("new_sha") or "").strip().lower()
        if new_sha and not _SHA_RE.match(new_sha):
            return json.dumps({"error": "new_sha must be a full 40-character commit SHA"})
        command = f"/detonate {repo} {sha}" + (f" {new_sha}" if new_sha else "") + (f" {subdir}" if subdir else "")
        return json.dumps({
            "status": "needs_user_approval",
            "message": "Detonator only runs after the user approves it. Ask the user to run this "
                       "command; Hermes will show them an approval prompt.",
            "command": command,
        })
    except Exception as exc:  # handlers must never raise
        return json.dumps({"error": f"internal error: {exc}"})
